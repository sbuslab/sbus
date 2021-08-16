package com.sbuslab.sbus.kafka

import scala.concurrent.Future

import akka.actor.ActorSystem
import com.fasterxml.jackson.databind.ObjectMapper
import com.rabbitmq.client.{RpcClient ⇒ _, RpcServer ⇒ _}
import com.typesafe.config.Config
import com.typesafe.scalalogging.Logger
import org.slf4j.LoggerFactory

import com.sbuslab.sbus.{Context, Transport}


class KafkaTransport(conf: Config, actorSystem: ActorSystem, mapper: ObjectMapper) extends Transport {

  private val log = Logger(LoggerFactory.getLogger("sbus.kafka"))

  def send(routingKey: String, msg: Any, context: Context, responseClass: Class[_]): Future[Any] =
    Future.successful {
      log.info(s"Kafka ~~> $routingKey : $msg")
    }

  def subscribe[T](routingKey: String, messageClass: Class[_], handler: (T, Context) ⇒ Future[Any]): Unit =
    Future.successful {
      log.info(s"Kafka: subscribe on $routingKey")
    }
}
