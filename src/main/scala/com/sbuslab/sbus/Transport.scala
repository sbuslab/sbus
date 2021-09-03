package com.sbuslab.sbus

import scala.collection.JavaConverters._
import scala.concurrent.{ExecutionContext, Future}

import com.typesafe.config.Config
import io.prometheus.client.{Gauge, Histogram}


object Transport {
  val processingSeconds = Histogram.build()
    .name("sbus_processing_seconds")
    .help("Sbus processing metrics")
    .labelNames("type", "routingKey")
    .register()

  val eventsHeartbeat = Gauge.build()
    .name("sbus_events_heartbeat")
    .help("Sbus events heartbeat")
    .labelNames("routingKey")
    .register()
}


trait Transport {

  def send(routingKey: String, msg: Any, context: Context, responseClass: Class[_]): Future[Any]

  def subscribe[T](routingKey: String, messageClass: Class[_], handler: (T, Context) ⇒ Future[Any]): Unit

  protected def meter[T](typeName: String, routingKey: String)(f: ⇒ Future[T])(implicit ec: ExecutionContext): Future[T] = {
    val timer = Transport.processingSeconds.labels(typeName, routingKey).startTimer()

    f andThen { case _ ⇒
      timer.observeDuration()
    }
  }
}


class TransportDispatcher(conf: Config, transports: java.util.Map[String, Transport]) extends Transport {

  private val transportByChannelMap: Map[String, Transport] =
    conf.atPath("/").getObject("/").asScala.toMap mapValues { t ⇒
      transports.get(t.atPath("/").getString("/"))
    }

  private def getTransport(routingKey: String) =
    transportByChannelMap.getOrElse(routingKey.split(':')(0), transportByChannelMap("default"))

  override def send(routingKey: String, msg: Any, context: Context, responseClass: Class[_]): Future[Any] =
    getTransport(routingKey).send(routingKey, msg, context, responseClass)

  override def subscribe[T](routingKey: String, messageClass: Class[_], handler: (T, Context) ⇒ Future[Any]): Unit =
    getTransport(routingKey).subscribe[T](routingKey, messageClass, handler)
}
