package com.sbuslab.sbus.kafka

import java.net.InetAddress
import java.util.Properties
import java.util.concurrent.{ConcurrentHashMap, Executors}
import scala.collection.JavaConverters._
import scala.concurrent.{ExecutionContext, Future}

import akka.actor.ActorSystem
import com.fasterxml.jackson.databind.ObjectMapper
import com.rabbitmq.client.{RpcClient ⇒ _, RpcServer ⇒ _}
import com.typesafe.config.Config
import com.typesafe.scalalogging.Logger
import org.apache.kafka.clients.consumer._
import org.apache.kafka.clients.producer._
import org.apache.kafka.common.serialization.{ByteArrayDeserializer, ByteArraySerializer, StringDeserializer, StringSerializer}
import org.slf4j.LoggerFactory

import com.sbuslab.model.Message
import com.sbuslab.sbus.{Context, Headers, Transport}


class KafkaTransport(conf: Config, actorSystem: ActorSystem, mapper: ObjectMapper) extends Transport {

  private val log = Logger(LoggerFactory.getLogger("sbus.kafka"))

  val config = new Properties
  config.put("client.id", InetAddress.getLocalHost.getHostName)
  config.put("bootstrap.servers", "127.0.0.1:9092")
  config.put("acks", "all")
  config.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, classOf[StringSerializer].getName)
  config.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, classOf[ByteArraySerializer].getName)

  config.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, classOf[StringDeserializer].getName)
  config.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, classOf[ByteArrayDeserializer].getName)

  lazy val producer = new KafkaProducer[String, Array[Byte]](config)

  val ServiceName = "user-service"
  val Topic = "sbus.events"

  val consumers = new ConcurrentHashMap[String, KafkaConsumer[String, Array[Byte]]]()
  val consumerRoutingKeys = new ConcurrentHashMap[String, ConsumerRecord[String, Array[Byte]] ⇒ Unit]()

  def send(routingKey: String, msg: Any, context: Context, responseClass: Class[_]): Future[Any] = {
    val bytes  = mapper.writeValueAsBytes(new Message(routingKey, msg))

    val record = new ProducerRecord[String, Array[Byte]](Topic, bytes)
    record.headers().add(Headers.RoutingKey, routingKey.getBytes)

    producer.send(record, new Callback() {
      def onCompletion(metadata: RecordMetadata, e: Exception): Unit =
        if (e != null) {
          log.error("Send failed for record {}", record, e)
        }
    })

    Future.unit
  }

  def subscribe[T](routingKey: String, messageClass: Class[_], handler: (T, Context) ⇒ Future[Any]): Unit = {
    val channel = if (routingKey.contains(":")) routingKey.split(':').head else "default"
    val realRoutingKey = routingKey.split(':').last // remove channel name prefix, if exists

    consumers.computeIfAbsent(channel, { _ ⇒
      val consConf = config.clone().asInstanceOf[Properties]
      consConf.put("group.id", ServiceName)

      val consumer = new KafkaConsumer[String, Array[Byte]](consConf)
      consumer.subscribe(List(Topic).asJava)

      Future({
        while (true) {
          try {
            consumer.poll(java.time.Duration.ofMinutes(1)) forEach { record ⇒
              val routingKey = record.headers().headers(Headers.RoutingKey).iterator().next()

              if (routingKey != null) {
                val handler = consumerRoutingKeys.get(new String(routingKey.value()))
                if (handler != null) {
                  handler(record)
                }
              }
            }

            consumer.commitAsync();
          } catch {
            case e: Throwable ⇒
              println(s"\n | consumer error: $e \n |\n")
          }
        }
      })(ExecutionContext.fromExecutorService(Executors.newSingleThreadExecutor()))

      consumer
    })

    consumerRoutingKeys.computeIfAbsent(realRoutingKey, { _ ⇒
      { record ⇒
        println(s"\n | record: $record \n |\n")
      }
    })
  }
}
