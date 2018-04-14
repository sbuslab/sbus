package com.sbuslab.model

import scala.concurrent.{ExecutionContext, Future}

import io.prometheus.client.Histogram


object Transport {
  private val histogram = Histogram.build()
    .name("sbus_processing_seconds")
    .help("Sbus processing metrics")
    .labelNames("type", "routingKey")
    .register()
}


trait Transport {

  def send(routingKey: String, msg: Any, context: Context, responseClass: Class[_]): Future[Any]

  def subscribe[T](routingKey: String, messageClass: Class[_], handler: (T, Context) ⇒ Future[Any]): Unit

  protected def meter[T](typeName: String, routingKey: String)(f: ⇒ Future[T])(implicit ec: ExecutionContext): Future[T] = {
    val timer = Transport.histogram.labels(typeName, routingKey).startTimer()

    f andThen { case _ ⇒
      timer.observeDuration()
    }
  }
}
