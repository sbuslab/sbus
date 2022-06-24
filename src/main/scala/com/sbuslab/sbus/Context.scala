package com.sbuslab.sbus

import java.util.UUID
import scala.collection.JavaConverters._
import scala.concurrent.duration.{Duration, TimeUnit}

import akka.util.Timeout
import com.github.sstone.amqp.Amqp

case class Context(data: Map[String, String] = Map.empty) {

  def get(key: String): Option[String] = data.get(key)

  def timeout: Option[Long]   = get(Headers.Timeout).map(_.toLong)
  def maxRetries: Option[Int] = get(Headers.RetryAttemptsMax).map(_.toInt)
  def attemptNr: Int          = get(Headers.RetryAttemptNr).fold(1)(_.toInt)
  def correlationId: String   = get(Headers.CorrelationId).orNull
  def messageId: String       = get(Headers.MessageId).orNull
  def routingKey: String      = get(Headers.RoutingKey).orNull
  def timestamp: Option[Long] = get(Headers.Timestamp).map(_.toLong)
  def ip: String              = get(Headers.Ip).orNull
  def userAgent: String       = get(Headers.UserAgent).orNull

  def withValue(key: String, value: Any): Context =
    withValue(key, if (value != null) value.toString else null)

  def withValue(key: String, value: String): Context =
    if (value == null) {
      copy(data = data - key)
    } else {
      copy(data = data + (key → value))
    }

  def withNewCorrelationId(): Context                   = withCorrelationId(UUID.randomUUID().toString)
  def withCorrelationId(id: String): Context            = withValue(Headers.CorrelationId, id)
  def withTimeout(to: Duration): Context                = withTimeout(to.toMillis)
  def withTimeout(to: Timeout): Context                 = withTimeout(to.duration.toMillis)
  def withTimeout(value: Long, unit: TimeUnit): Context = withTimeout(Timeout(value, unit))
  def withTimeout(millis: Long): Context                = withValue(Headers.Timeout, millis.toString)
  def withRetries(max: Int): Context                    = withValue(Headers.RetryAttemptsMax, max.toString)
  def withRoutingKey(key: String): Context              = withValue(Headers.RoutingKey, key)

  def customData = data -- Context.notLoggedHeaders
}

object Context {

  private val emptyContext = Context()

  private val allowedHeaders = Set(
    Headers.Timeout,
    Headers.RoutingKey,
    Headers.CorrelationId,
    Headers.MessageId,
    Headers.RetryAttemptNr,
    Headers.Timestamp,
    Headers.ExpiredAt,
    Headers.Ip,
    Headers.UserId,
    Headers.Auth,
    Headers.UserAgent,
    Headers.Origin,
    Headers.Signature,
  )

  private val notLoggedHeaders =
    allowedHeaders -- Set(Headers.Ip, Headers.UserId, Headers.Auth, Headers.Timestamp, Headers.Origin, Headers.Signature)

  def empty                         = emptyContext
  def withNewCorrelationId()        = emptyContext.withNewCorrelationId()
  def withCorrelationId(id: String) = Context().withCorrelationId(id)

  def withTimeout(to: Timeout): Context                 = Context().withTimeout(to)
  def withTimeout(value: Long, unit: TimeUnit): Context = Context().withTimeout(value, unit)
  def withTimeout(millis: Long): Context                = Context().withTimeout(millis)

  def withRetries(max: Int) = Context().withRetries(max)

  def from(delivery: Amqp.Delivery): Context = {
    val data = Map.newBuilder[String, String]
    data += Headers.MessageId  → Option(delivery.properties.getMessageId).getOrElse(UUID.randomUUID().toString)
    data += Headers.RoutingKey → delivery.envelope.getRoutingKey

    val headers = delivery.properties.getHeaders

    if (headers != null) {
      data ++= headers.asScala.filterKeys(allowedHeaders).filter(_._2 != null).mapValues(_.toString)

      Option(headers.get(Headers.ExpiredAt)) foreach { expiresAt ⇒
        data += Headers.Timeout → (expiresAt.toString.toLong - System.currentTimeMillis()).max(1).toString
      }
    }

    Context(data.result().filter(_._2 != null))
  }
}
