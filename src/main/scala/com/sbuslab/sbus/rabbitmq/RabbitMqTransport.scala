package com.sbuslab.sbus.rabbitmq

import java.util
import java.util.UUID
import java.util.concurrent.{CompletionException, ExecutionException, TimeUnit}
import scala.collection.JavaConverters._
import scala.concurrent.Future
import scala.concurrent.duration._
import scala.util.control.NonFatal

import akka.actor.ActorSystem
import akka.pattern.{ask, AskTimeoutException}
import akka.util.Timeout
import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.databind.{JsonNode, ObjectMapper}
import com.github.sstone.amqp._
import com.rabbitmq.client.ConnectionFactory
import com.rabbitmq.client.AMQP.BasicProperties
import com.typesafe.config.Config
import com.typesafe.scalalogging.Logger
import org.slf4j.{LoggerFactory, MDC}

import com.sbuslab.model._
import com.sbuslab.sbus.{Context, Headers, Transport}


class RabbitMqTransport(conf: Config, actorSystem: ActorSystem, mapper: ObjectMapper) extends Transport {

  implicit val ec = actorSystem.dispatcher

  private val log = Logger(LoggerFactory.getLogger("sbus.rabbitmq"))

  implicit val defaultTimeout = Timeout(conf.getDuration("default-timeout").toMillis, TimeUnit.MILLISECONDS)

  private val DefaultCommandRetries = conf.getInt("default-command-retries")
  private val ChannelParams         = Amqp.ChannelParameters(qos = conf.getInt("prefetch-count"), global = false)
  private val CommonExchange        = Amqp.ExchangeParameters(conf.getString("exchange"), passive = false, exchangeType = "direct")
  private val EventExchange         = Amqp.ExchangeParameters(conf.getString("event-exchange"), passive = false, exchangeType = "topic")
  private val RetryExchange         = Amqp.ExchangeParameters(conf.getString("retry-exchange"), passive = false, exchangeType = "fanout")

  private val queueConfigs = conf.getConfig("queues").atPath("/").getObject("/").asScala.toMap mapValues(_.atPath("/").getConfig("/"))

  private def queueConfig(name: String): QueueConfig = {
    val cfg = queueConfigs.get(name).orNull

    QueueConfig(
      name         = if (cfg != null && cfg.hasPath("name")) cfg.getString("name") else name,
      durable      = if (cfg != null && cfg.hasPath("durable")) cfg.getBoolean("durable") else false,
      exclusive    = if (cfg != null && cfg.hasPath("exclusive")) cfg.getBoolean("exclusive") else false,
      autodelete   = if (cfg != null && cfg.hasPath("autodelete")) cfg.getBoolean("autodelete") else false,
      exchange     = if (cfg != null && cfg.hasPath("exchange")) cfg.getString("exchange") else CommonExchange.name,
      exchangeType = if (cfg != null && cfg.hasPath("exchange-type")) cfg.getString("exchange-type") else CommonExchange.exchangeType,
      routingKey   = if (cfg != null && cfg.hasPath("routing-key")) cfg.getString("routing-key") else name
    )
  }

  private val connection = actorSystem.actorOf(ConnectionOwner.props({
    log.debug("Sbus connecting to: " + conf.getString("host"))

    val cf = new ConnectionFactory()
    cf.setHost(conf.getString("host"))
    cf.setPort(conf.getInt("port"))
    cf
  }, 3.seconds), name = "rabbitmq-connection")

  private val producer = {
    val channelOwner = ConnectionOwner.createChildActor(connection, ChannelOwner.props())
    Amqp.waitForConnection(actorSystem, channelOwner).await()

    for {
      _ ← channelOwner ? Amqp.DeclareExchange(CommonExchange)
      _ ← channelOwner ? Amqp.DeclareExchange(RetryExchange)
      _ ← channelOwner ? Amqp.DeclareExchange(EventExchange)

      _ ← channelOwner ? Amqp.DeclareQueue(
        Amqp.QueueParameters("retries", passive = false, durable = true, exclusive = false, autodelete = false, args = Map("x-dead-letter-exchange" → CommonExchange.name)))

      _ ← channelOwner ? Amqp.QueueBind("retries", RetryExchange.name, "#")
    } {}

    channelOwner
  }

  private val rpcClient = {
    val child = ConnectionOwner.createChildActor(connection, RpcClient.props(Some(ChannelParams)))
    Amqp.waitForConnection(actorSystem, child).await()
    child
  }


  /**
   *
   */
  def send(routingKey: String, msg: Any, context: Context, responseClass: Class[_], isEvent: Boolean = false): Future[Any] = {
    val bytes = mapper.writeValueAsBytes(new Message(routingKey, msg))

    val corrId = Option(context.correlationId).getOrElse(UUID.randomUUID().toString)

    val propsBldr = new BasicProperties().builder()
      .deliveryMode(if (responseClass != null) 1 else 2) // 2 → persistent
      .messageId(context.get(Headers.ClientMessageId).getOrElse(UUID.randomUUID()).toString)
      .expiration(context.timeout match {
        case Some(ms) ⇒ ms.toString
        case _ if responseClass != null ⇒ defaultTimeout.duration.toMillis.toString
        case _ ⇒ null
      })
      .headers(Map(
        Headers.CorrelationId → corrId,
        Headers.RetryAttemptsMax → context.maxRetries.getOrElse(if (responseClass != null) 0 else DefaultCommandRetries), // commands retriable by default
        Headers.ExpiredAt → context.timeout.map(_ + System.currentTimeMillis()).getOrElse(null),
        Headers.Timestamp → System.currentTimeMillis()
      ).filter(_._2 != null).mapValues(_.toString.asInstanceOf[Object]).asJava)

    logs("~~~>", routingKey, bytes, corrId)

    val pub = Amqp.Publish(if (isEvent) EventExchange.name else CommonExchange.name, routingKey, bytes, Some(propsBldr.build()))

    (if (responseClass != null) {
      meter("request", routingKey) {
        rpcClient.ask(RpcClient.Request(pub))(context.timeout.fold(defaultTimeout)(_.millis)) map {
          case RpcClient.Response(deliveries) ⇒
            logs("resp <~~~", routingKey, deliveries.head.body, corrId)

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
              throw ErrorMessage.fromCode(status, err.getMessage, null, err.getError, err.getLinks)
            }

          case other ⇒
            throw new InternalServerError(s"Unexpected response for `$routingKey`: $other")
        }
      }
    } else {
      producer ? pub map {
        case _: Amqp.Ok ⇒ // ok
        case error ⇒ throw new InternalServerError("Error on publish message to " + routingKey + ": " + error)
      }
    }) recover {
      case e: AskTimeoutException ⇒
        logs("timeout error", routingKey, bytes, corrId, e)
        throw new ErrorMessage(504, s"Timeout on `$routingKey` with message ${msg.getClass.getSimpleName}", e)

      case e: Throwable ⇒
        logs("error", routingKey, bytes, corrId, e)
        throw e
    }
  }

  /**
   *
   */
  def subscribe[T](routingKey: String, messageClass: Class[_], handler: (T, Context) ⇒ Future[Any]): Unit = {
    require(messageClass != null, "messageClass is required!")

    val processor = new RpcServer.IProcessor {
      def process(delivery: Amqp.Delivery): Future[RpcServer.ProcessResult] =
        meter("handle", routingKey) {
          (try {
            logs("<~~~", routingKey, delivery.body, getCorrelationId(delivery))

            val payload = (Option(mapper.readTree(delivery.body)).map(_.get("body")).orNull match {
              case null ⇒ null
              case body ⇒ deserializeToClass(body, messageClass)
            }).asInstanceOf[T]

            handler(payload, Context.from(delivery))
          } catch {
            case e: Throwable ⇒ Future.failed(e)
          }) map {
            case result if delivery.properties.getReplyTo != null ⇒
              val bytes = mapper.writeValueAsBytes(new Response(200, result))
              logs("resp ~~~>", routingKey, bytes, getCorrelationId(delivery))
              RpcServer.ProcessResult(Some(bytes))

            case _ ⇒ RpcServer.ProcessResult(None)
          } recover {
            case e: RuntimeException if e.getCause != null && !e.isInstanceOf[ErrorMessage] ⇒ throw e.getCause // unwrap RuntimeException cause errors
          } recoverWith {
            case e@(_: NullPointerException | _: IllegalArgumentException | _: JsonProcessingException) ⇒
              throw new BadRequestError(e.toString, e)

            case e: IllegalStateException ⇒
              throw new ConflictError(e.toString, e)

            case e: Throwable if !e.isInstanceOf[UnrecoverableFailure] ⇒
              val heads       = Option(delivery.properties.getHeaders).getOrElse(new util.HashMap[String, Object]())
              val attemptsMax = Option(heads.get(Headers.RetryAttemptsMax)).map(_.toString.toInt)
              val attemptNr   = Option(heads.get(Headers.RetryAttemptNr)).fold(1)(_.toString.toInt)

              if (attemptsMax.exists(_ >= attemptNr)) {
                heads.put(Headers.RetryAttemptNr, s"${attemptNr + 1}")

                val backoff = math.pow(2, math.min(attemptNr - 1, 7)).round * 1000

                val updProps = delivery.properties.builder()
                  .headers(heads)
                  .expiration(backoff.toString) // millis, exponential backoff
                  .build()

                // if message will be expired before next attempt — skip it
                if (Option(heads.get(Headers.ExpiredAt)).exists(_.toString.toLong <= System.currentTimeMillis() + backoff)) {
                  logs("timeout", routingKey, s"Message will be expired at ${heads.get(Headers.ExpiredAt)}, don't retry it!".getBytes, getCorrelationId(delivery), e)
                  Future.failed(e)
                } else {
                  logs("error", routingKey, s"$e. Retry attempt ${attemptNr + 1} after ${updProps.getExpiration} millis...".getBytes, getCorrelationId(delivery), e)

                  producer ? Amqp.Publish(RetryExchange.name, routingKey, delivery.body, Some(updProps), mandatory = false) map {
                    case _: Amqp.Ok ⇒ RpcServer.ProcessResult(None)
                    case error      ⇒ throw new InternalServerError("Error on publish retry message for " + routingKey + ": " + error)
                  }
                }
              } else {
                Future.failed(e)
              }
          } recover {
            case e @ (_: CompletionException | _: ExecutionException) ⇒ onFailure(delivery, e.getCause)
            case e: RuntimeException if e.getCause != null && !e.isInstanceOf[ErrorMessage] ⇒ onFailure(delivery, e.getCause)
            case NonFatal(e: Exception) ⇒ onFailure(delivery, e)
          }
        }

      def onFailure(delivery: Amqp.Delivery, e: Throwable): RpcServer.ProcessResult = {
        logs("error", routingKey, e.toString.getBytes, getCorrelationId(delivery), e)

        if (delivery.properties.getReplyTo != null) {
          val response = e match {
            case em: ErrorMessage ⇒ new Response(em.code, new ErrorResponseBody(em.getMessage, em.error, em._links))
            case _                ⇒ new Response(500, new ErrorResponseBody(e.getMessage, null, null))
          }

          val bytes = mapper.writeValueAsBytes(response)
          logs("resp ~~~>", routingKey, bytes, getCorrelationId(delivery))
          RpcServer.ProcessResult(Some(bytes))
        } else {
          RpcServer.ProcessResult(None)
        }
      }
    }

    val qcfg = queueConfig(routingKey)

    val rpcServer = ConnectionOwner.createChildActor(connection, RpcServer.props(
      queue = Amqp.QueueParameters(
        name       = qcfg.name,
        passive    = false,
        durable    = qcfg.durable,
        exclusive  = qcfg.exclusive,
        autodelete = qcfg.autodelete
      ),
      exchange      = Amqp.ExchangeParameters(qcfg.exchange, passive = false, exchangeType = qcfg.exchangeType),
      routingKey    = qcfg.routingKey,
      proc          = processor,
      channelParams = ChannelParams
    ))

    log.debug(s"Sbus subscribed to: $routingKey / $qcfg")

    Amqp.waitForConnection(actorSystem, rpcServer).await()
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
    if (log.underlying.isTraceEnabled) {
      MDC.put("correlation_id", correlationId)

      val msg = s"sbus $prefix $routingKey: ${new String(body.take(conf.getInt("log-trim-length")))}"

      if (e == null) {
        log.trace(msg)
      } else if (e.isInstanceOf[UnrecoverableFailure]) {
        log.warn(msg, e)
      } else {
        log.error(msg, e)
      }
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
