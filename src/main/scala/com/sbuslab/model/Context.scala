package com.sbuslab.model

import java.util.UUID
import scala.collection.JavaConverters._
import scala.concurrent.duration.TimeUnit

import akka.util.Timeout
import com.github.sstone.amqp.Amqp


case class Context(data: Map[String, Any] = Map.empty) {

  def get(key: String): Option[Any] = data.get(key)

  def timeout: Option[Long]   = get(Headers.Timeout).map(_.toString.toLong)
  def maxRetries: Option[Int] = get(Headers.RetryAttemptsMax).map(_.toString.toInt)
  def attemptNr: Int          = get(Headers.RetryAttemptNr).fold(1)(_.toString.toInt)
  def correlationId: String   = get(Headers.CorrelationId).map(_.toString).orNull
  def messageId: String       = get(Headers.MessageId).map(_.toString).orNull
  def routingKey: String      = get(Headers.RoutingKey).map(_.toString).orNull

  def withValue(key: String, value: Any): Context =
    if (value == null) {
      copy(data = data - key)
    } else {
      copy(data = data + (key → value))
    }

  def withCorrelationId(id: String): Context            = withValue(Headers.CorrelationId, id)
  def withTimeout(to: Timeout): Context                 = withTimeout(to.duration.toMillis)
  def withTimeout(value: Long, unit: TimeUnit): Context = withTimeout(Timeout(value, unit))
  def withTimeout(millis: Long): Context                = withValue(Headers.Timeout, millis)
  def withRetries(max: Int): Context                    = withValue(Headers.RetryAttemptsMax, max)
  def withRoutingKey(key: String): Context              = withValue(Headers.RoutingKey, key)
}


object Context {
  private val emptyContext = Context()

  def empty = emptyContext
  def withCorrelationId(id: String) = Context().withCorrelationId(id)

  def withTimeout(to: Timeout): Context = Context().withTimeout(to)
  def withTimeout(value: Long, unit: TimeUnit): Context = Context().withTimeout(value, unit)
  def withTimeout(millis: Long): Context = Context().withTimeout(millis)

  def withRetries(max: Int) = Context().withRetries(max)

  def from(delivery: Amqp.Delivery): Context = {
    val data = Map.newBuilder[String, Any]
    data += Headers.MessageId → Option(delivery.properties.getMessageId).getOrElse(UUID.randomUUID().toString)
    data += Headers.RoutingKey → delivery.envelope.getRoutingKey

    if (delivery.properties.getHeaders != null) {
      data ++= delivery.properties.getHeaders.asScala.filterKeys(Headers.all)
    }

    Context(data.result().filter(_._2 != null))
  }
}
