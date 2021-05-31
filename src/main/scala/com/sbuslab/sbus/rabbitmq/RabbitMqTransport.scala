package com.sbuslab.sbus.rabbitmq

import java.util
import java.util.UUID
import java.util.concurrent.{CompletionException, ConcurrentLinkedQueue, ExecutionException, TimeUnit}
import scala.collection.JavaConverters._
import scala.concurrent.{Await, Future}
import scala.concurrent.duration._

import akka.actor.{ActorRef, ActorSystem, Props}
import akka.event.LoggingReceive
import akka.pattern.{ask, AskTimeoutException}
import akka.util.Timeout
import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.databind.{JsonNode, ObjectMapper}
import com.github.sstone.amqp._
import com.rabbitmq.client.{RpcClient ⇒ _, RpcServer ⇒ _, _}
import com.rabbitmq.client.AMQP.BasicProperties
import com.rabbitmq.client.impl.recovery.TopologyRecoveryRetryHandlerBuilder
import com.typesafe.config.Config
import com.typesafe.scalalogging.Logger
import org.slf4j.{LoggerFactory, MDC}

import com.sbuslab.model._
import com.sbuslab.sbus.{Context, Headers, Transport}


class RabbitMqTransport(conf: Config, actorSystem: ActorSystem, mapper: ObjectMapper) extends Transport {

  implicit val ec = actorSystem.dispatcher

  private val log = Logger(LoggerFactory.getLogger("sbus.rabbitmq"))

  private val jsonWriter =
    if (conf.getBoolean("pretty-json")) {
      mapper.writerWithDefaultPrettyPrinter()
    } else {
      mapper.writer()
    }

  implicit val defaultTimeout = Timeout(conf.getDuration("default-timeout").toMillis, TimeUnit.MILLISECONDS)

  private val LogTrimLength         = conf.getInt("log-trim-length")
  private val UnloggedRequests      = conf.getStringList("unlogged-requests").asScala.toSet
  private val DefaultCommandRetries = conf.getInt("default-command-retries")
  private val ChannelParams         = Amqp.ChannelParameters(qos = conf.getInt("prefetch-count"), global = false)

  private val rpcServers = new ConcurrentLinkedQueue[ActorRef]

  private val connection = actorSystem.actorOf(ConnectionOwner.props(
    connFactory = {
      log.debug("Sbus connecting to: " + conf.getString("host"))

      val cf = new ConnectionFactory()
      cf.setUsername(conf.getString("username"))
      cf.setPassword(conf.getString("password"))
      cf.setTopologyRecoveryEnabled(true)

      cf.setTopologyRecoveryRetryHandler(TopologyRecoveryRetryHandlerBuilder.builder()
        .bindingRecoveryRetryCondition((_, _) ⇒ true)
        .consumerRecoveryRetryCondition((_, _) ⇒ true)
        .exchangeRecoveryRetryCondition((_, _) ⇒ true)
        .queueRecoveryRetryCondition((_, _) ⇒ true)
        .retryAttempts(Int.MaxValue)
        .backoffPolicy(_ ⇒ Thread.sleep(100))
        .build())

      cf.setAutomaticRecoveryEnabled(true)
      cf.setNetworkRecoveryInterval(5000)
      cf.setRequestedHeartbeat(10)
      cf.setConnectionTimeout(5000)
      cf
    },
    reconnectionDelay = 3.seconds,
    addressResolver = Some(new ListAddressResolver(
      conf.getString("host").split(',').map(host ⇒ new Address(host, conf.getInt("port"))).toList.asJava
    ))
  ), name = "rabbitmq-connection")

  private val channelConfigs: Map[String, SbusChannel] = {
    val producer = ConnectionOwner.createChildActor(connection, ChannelOwner.props())
    Amqp.waitForConnection(actorSystem, producer).await()

    conf.getConfig("channels").atPath("/").getObject("/").asScala.toMap map { case (name, obj) ⇒
      val cfg = obj.atPath("/").getConfig("/").withFallback(conf.getConfig("channels.default"))

      val exchange      = Amqp.ExchangeParameters(cfg.getString("exchange"), passive = false, exchangeType = cfg.getString("exchange-type"))
      val retryExchange = Amqp.ExchangeParameters(exchange.name + "-retries", passive = false, exchangeType = "fanout")

      Await.ready(for {
        _ ← producer ? Amqp.DeclareExchange(exchange) zip
            producer ? Amqp.DeclareExchange(retryExchange)

        _ ← producer ? Amqp.DeclareQueue(
            Amqp.QueueParameters(retryExchange.name, passive = false, durable = true, exclusive = false, autodelete = false, args = Map("x-dead-letter-exchange" → exchange.name)))

        _ ← producer ? Amqp.QueueBind(retryExchange.name, retryExchange.name, Set("#"))
      } yield {}, 10.seconds)

      name → SbusChannel(
        name            = name,
        producer        = producer,
        exchange        = exchange.name,
        exchangeType    = exchange.exchangeType,
        retryExchange   = retryExchange.name,
        queueNameFormat = cfg.getString("queue-name"),
        durable         = cfg.getBoolean("durable"),
        exclusive       = cfg.getBoolean("exclusive"),
        autodelete      = cfg.getBoolean("autodelete"),
        mandatory       = cfg.getBoolean("mandatory"),
        heartbeat       = cfg.getBoolean("heartbeat"),
        routingKeys     = Option(cfg.getStringList("routing-keys").asScala.toList).filter(_.nonEmpty)
      )
    }
  }

  private val rpcClient = {
    val child = ConnectionOwner.createChildActor(connection, RpcClient.props(Some(ChannelParams)))
    Amqp.waitForConnection(actorSystem, child).await()
    child
  }

  private def getChannel(routingKey: String): SbusChannel =
    if (routingKey.contains(":")) {
      channelConfigs.getOrElse(routingKey.split(':').head, throw new InternalServerError(s"There is no channel configuration for Sbus routingKey = $routingKey!"))
    } else {
      channelConfigs("default")
    }

  scala.sys.addShutdownHook {
    log.info("Stopping Sbus...")

    rpcServers forEach { _ ! Amqp.Shutdown(new ShutdownSignalException(true, false, null, null)) }

    Thread.sleep(conf.getDuration("shutdown-timeout").toMillis)

    actorSystem.terminate()

    log.info("Sbus terminated...")
  }

  /**
   *
   */
  def send(routingKey: String, msg: Any, context: Context, responseClass: Class[_]): Future[Any] = {
    val channel = getChannel(routingKey)
    val realRoutingKey = routingKey.split(':').last // remove channel name prefix, if exists

    val bytes  = jsonWriter.writeValueAsBytes(new Message(realRoutingKey, msg))
    val corrId = Option(context.correlationId).getOrElse(UUID.randomUUID().toString)

    val propsBldr = new BasicProperties().builder()
      .deliveryMode(if (responseClass != null) 1 else 2) // 2 → persistent
      .messageId(context.get(Headers.ClientMessageId).getOrElse(UUID.randomUUID()).toString)
      .expiration(context.timeout match {
        case Some(ms)                   ⇒ ms.max(1).toString
        case _ if responseClass != null ⇒ defaultTimeout.duration.toMillis.toString
        case _                          ⇒ null
      })
      .headers(Map(
        Headers.CorrelationId    → corrId,
        Headers.RoutingKey       → realRoutingKey,
        Headers.RetryAttemptsMax → context.maxRetries.getOrElse(if (responseClass != null) null else DefaultCommandRetries), // commands retryable by default
        Headers.ExpiredAt        → context.timeout.map(_ + System.currentTimeMillis()).getOrElse(null),
        Headers.Timestamp        → System.currentTimeMillis(),
        Headers.Ip               → context.ip,
        Headers.UserAgent        → context.userAgent
      ).filter(_._2 != null).mapValues(_.toString.asInstanceOf[Object]).asJava)

    if (corrId != "sbus:ping") {
      logs("~~~>", realRoutingKey, bytes, corrId)
    }

    val pub = Amqp.Publish(channel.exchange, realRoutingKey, bytes, Some(propsBldr.build()), mandatory = channel.mandatory)

    (if (responseClass != null) {
      meter("request", realRoutingKey) {
        rpcClient.ask(RpcClient.Request(pub))(context.timeout.fold(defaultTimeout)(_.millis)) map {
          case RpcClient.Response(deliveries) ⇒
            logs("resp <~~~", realRoutingKey, deliveries.head.body, corrId)

            val tree = mapper.readTree(deliveries.head.body)

            val status =
              if (tree.hasNonNull("status")) {
                tree.path("status").asInt
              } else if (tree.path("failed").asBoolean(false)) { // backward compatibility with old protocol
                500
              } else { 200 }

            if (status < 400) {
              deserializeToClass(tree.path("body"), responseClass)
            } else {
              val err = mapper.treeToValue(tree.path("body"), classOf[ErrorResponseBody])
              throw ErrorMessage.fromCode(status, err.getMessage, null, err.getError, err.getLinks, err.getEmbedded)
            }

          case other ⇒
            log.error(s"Unexpected response for `$realRoutingKey`: $other")
            throw new InternalServerError(s"Unexpected response for `$realRoutingKey`")
        }
      }
    } else {
      channel.producer ? pub map {
        case _: Amqp.Ok ⇒ // ok
        case error ⇒ throw new InternalServerError("Error on publish message to " + realRoutingKey + ": " + error)
      }
    }) recover {
      case e: AskTimeoutException ⇒
        logs("timeout error", realRoutingKey, bytes, corrId, e)
        throw new ErrorMessage(504, s"Timeout on `$realRoutingKey` with message ${if (msg != null) msg.getClass.getSimpleName else null}", e)

      case e: Throwable ⇒
        logs("error", realRoutingKey, bytes, corrId, e)
        throw e
    }
  }


  /**
   *
   */
  def subscribe[T](routingKey: String, messageClass: Class[_], handler: (T, Context) ⇒ Future[Any]): Unit = {
    require(messageClass != null, "messageClass is required!")

    val channel = getChannel(routingKey)
    val subscriptionName = routingKey.split(':').last

    val processor = new RpcServer.IProcessor {
      def process(delivery: Amqp.Delivery): Future[RpcServer.ProcessResult] =
        meter("handle", subscriptionName) {
          val correlationId = getCorrelationId(delivery)

          (try {
            if (correlationId == "sbus:ping") {
              val pingAt = mapper.readTree(delivery.body).path("body").path("ping").asLong(0)
              Transport.eventsHeartbeat.labels(routingKey).set(System.currentTimeMillis - pingAt)
              return Future.successful(RpcServer.ProcessResult(None))
            }

            logs("<~~~", subscriptionName, delivery.body, correlationId)

            val payload = (Option(mapper.readTree(delivery.body)).map(_.get("body")).orNull match {
              case null ⇒ null
              case body ⇒ deserializeToClass(body, messageClass)
            }).asInstanceOf[T]

            handler(payload, Context.from(delivery))
          } catch {
            case e: Throwable ⇒ Future.failed(e)
          }) map {
            case result if delivery.properties.getReplyTo != null ⇒
              val bytes = jsonWriter.writeValueAsBytes(new Response(200, result))
              logs("resp ~~~>", subscriptionName, bytes, correlationId)
              RpcServer.ProcessResult(Some(bytes))

            case _ ⇒ RpcServer.ProcessResult(None)
          } recover {
            case e: RuntimeException if e.getCause != null && !e.isInstanceOf[ErrorMessage] ⇒ throw e.getCause // unwrap RuntimeException cause errors
          } recoverWith {
            case e @ (_: NullPointerException | _: IllegalArgumentException | _: JsonProcessingException) ⇒
              throw new BadRequestError(e.toString, e)

            case e: IllegalStateException ⇒
              throw new ConflictError(e.toString, e)

            case e: Throwable if !e.isInstanceOf[UnrecoverableFailure] ⇒
              val heads            = Option(delivery.properties.getHeaders).getOrElse(new util.HashMap[String, Object]())
              val attemptsMax      = Option(heads.get(Headers.RetryAttemptsMax)).map(_.toString.toInt)
              val attemptNr        = Option(heads.get(Headers.RetryAttemptNr)).fold(1)(_.toString.toInt)
              val originRoutingKey = Option(heads.get(Headers.RoutingKey)).fold(delivery.envelope.getRoutingKey)(_.toString)

              if (attemptsMax.exists(_ >= attemptNr)) {
                heads.put(Headers.RetryAttemptNr, s"${attemptNr + 1}")

                val backoff = math.pow(2, math.min(attemptNr - 1, 6)).round * 1000  // max 64 seconds

                val updProps = delivery.properties.builder()
                  .headers(heads)
                  .expiration(backoff.toString) // millis, exponential backoff
                  .build()

                // if message will be expired before next attempt — skip it
                if (Option(heads.get(Headers.ExpiredAt)).exists(_.toString.toLong <= System.currentTimeMillis() + backoff)) {
                  logs("timeout", originRoutingKey, s"Message will be expired at ${heads.get(Headers.ExpiredAt)}, don't retry it!".getBytes, correlationId, e)
                  Future.failed(e)
                } else {
                  logs("error", originRoutingKey, s"$e. Retry attempt ${attemptNr} after ${updProps.getExpiration} millis...".getBytes, correlationId, e)

                  channel.producer ? Amqp.Publish(channel.retryExchange, channel.queueNameFormat.format(originRoutingKey), delivery.body, Some(updProps), mandatory = false) map {
                    case _: Amqp.Ok ⇒ RpcServer.ProcessResult(None)
                    case error      ⇒ throw new InternalServerError("Error on publish retry message for " + originRoutingKey + ": " + error)
                  }
                }
              } else {
                Future.failed(e)
              }
          } recover {
            case e @ (_: CompletionException | _: ExecutionException) if e.getCause != null ⇒ onFailure(delivery, e.getCause)
            case e: RuntimeException if e.getCause != null && !e.isInstanceOf[ErrorMessage] ⇒ onFailure(delivery, e.getCause)
            case e: Throwable ⇒ onFailure(delivery, e)
          }
        }

      def onFailure(delivery: Amqp.Delivery, e: Throwable): RpcServer.ProcessResult = {
        logs("error", subscriptionName, e.toString.getBytes, getCorrelationId(delivery), e)

        if (delivery.properties.getReplyTo != null) {
          val response = e match {
            case em: ErrorMessage ⇒ new Response(em.code, new ErrorResponseBody(em.getMessage, em.error, em._links, em._embedded))
            case _                ⇒ new Response(500, new ErrorResponseBody(e.toString, null, null, null))
          }

          val bytes = jsonWriter.writeValueAsBytes(response)
          logs("resp ~~~>", subscriptionName, bytes, getCorrelationId(delivery))
          RpcServer.ProcessResult(Some(bytes))
        } else {
          RpcServer.ProcessResult(None)
        }
      }
    }

    val binding = Amqp.AddBinding(Amqp.Binding(
      exchange = Amqp.ExchangeParameters(channel.exchange, passive = false, exchangeType = channel.exchangeType),
      queue = Amqp.QueueParameters(
        name       = channel.queueNameFormat.format(subscriptionName),
        passive    = false,
        durable    = channel.durable,
        exclusive  = channel.exclusive,
        autodelete = channel.autodelete
      ),
      routingKeys = channel.routingKeys.getOrElse(List(subscriptionName))
        .flatMap(rtKey ⇒ List(rtKey, channel.queueNameFormat.format(rtKey)))  // add routingKey with channel prefix for handlling retried messages
        .filter(_.nonEmpty)
        .toSet
    ))

    def createRpcActor(): Unit = {
      val rpcServer = ConnectionOwner.createChildActor(connection, Props(new RpcServer(
        processor = processor,
        init = List(binding),
        channelParams = Some(ChannelParams)
      ) {
        override def connected(channel: Channel, forwarder: ActorRef): Receive = LoggingReceive({
          case Amqp.ConsumerCancelled(consumerTag) ⇒
            log.warning(s"Sbus consumer for $routingKey cancelled ($consumerTag), trying to shutdown it and connect again...")
            self forward Amqp.Shutdown(new ShutdownSignalException(true, false, null, null))

            actorSystem.stop(self)

            createRpcActor() // recreate

          case Amqp.Shutdown(cause) if !cause.isInitiatedByApplication ⇒
            context.stop(forwarder)

            if (!cause.isHardError) {
              context.parent ! ConnectionOwner.CreateChannel
            }

            statusListeners.foreach(_ ! ChannelOwner.Disconnected)
            context.become(disconnected)

        }: Receive) orElse super.connected(channel, forwarder)

        override def unhandled(message: Any): Unit = message match {
          case Amqp.Shutdown(cause) ⇒
            log.debug(s"Amqp.Shutdown $cause")

          case _ ⇒
            super.unhandled(message)
        }
      }))

      log.debug(s"Sbus subscribed to: $subscriptionName / $channel")

      rpcServers.add(rpcServer)

      Amqp.waitForConnection(actorSystem, rpcServer).await()
    }

    createRpcActor()

    if (channel.heartbeat) {
      actorSystem.scheduler.schedule(1.minute, 1.minute) {
        try send(routingKey, SbusPing(System.currentTimeMillis), context = Context.withCorrelationId("sbus:ping"), null) catch { case _: Throwable ⇒ }
      }
    }
  }

  private def deserializeToClass(node: JsonNode, responseClass: Class[_]): Any = {
    if (responseClass == classOf[java.lang.Void] || responseClass == java.lang.Void.TYPE || responseClass.isInstance(Unit)) {
      // return nothing
    } else {
      try mapper.treeToValue(node, responseClass) catch {
        case e: Throwable ⇒
          throw new BadRequestError(s"Can't deserialize $node to $responseClass: ${e.getMessage}", e)
      }
    }
  }

  private def getCorrelationId(delivery: Amqp.Delivery): String = {
    val heads = delivery.properties.getHeaders

    if (heads != null) {
      val id = heads.get(Headers.CorrelationId)
      if (id == null) null else id.toString
    } else null
  }

  private def logs(prefix: String, routingKey: String, body: Array[Byte], correlationId: String, e: Throwable = null) {
    if (e != null || (log.underlying.isTraceEnabled && !UnloggedRequests.contains(routingKey))) {
      MDC.put("correlation_id", correlationId)

      val msg = s"sbus $prefix $routingKey: ${new String(body.take(LogTrimLength))}"

      e match {
        case null                    ⇒ log.trace(msg)
        case _: NotFoundError        ⇒ log.debug(msg)
        case _: UnrecoverableFailure ⇒ log.warn(msg, e)
        case _                       ⇒ log.error(msg, e)
      }

      MDC.remove("correlation_id")
    }
  }
}


case class QueueConfig(
  name: String,
  durable: Boolean,
  exclusive: Boolean,
  autodelete: Boolean,
  exchange: String,
  exchangeType: String,
  routingKey: String
)

case class SbusChannel(
  name: String,
  producer: ActorRef,
  exchange: String,
  exchangeType: String,
  retryExchange: String,
  queueNameFormat: String,
  durable: Boolean,
  exclusive: Boolean,
  autodelete: Boolean,
  mandatory: Boolean,
  heartbeat: Boolean,
  routingKeys: Option[List[String]]
)

case class SbusPing(
  ping: Long,
)
