package com.sbuslab.model

import com.fasterxml.jackson.core.JsonProcessingException


class ErrorMessage(
  val code: Int,
  msg: String,
  cause: Throwable = null,
  val error: String = null,
  val _links: java.util.Map[String, Object] = null
) extends RuntimeException(msg, cause)


object ErrorMessage {
  def fromCode(code: Int, msg: String, cause: Throwable = null, error: String = null, _links: java.util.Map[String, Object] = null): ErrorMessage = code match {
    case 400 ⇒ new BadRequestError(msg, cause, error)
    case 401 ⇒ new UnauthorizedError(msg, cause, error)
    case 403 ⇒ new ForbiddenError(msg, cause, error, _links)
    case 404 ⇒ new NotFoundError(msg, cause, error)
    case 405 ⇒ new MethodNotAllowedError(msg, cause, error)
    case 409 ⇒ new ConflictError(msg, cause, error)
    case 429 ⇒ new TooManyRequestError(msg, cause, error)
    case 456 ⇒ new UnrecoverableError(msg, cause, error)
    case 500 ⇒ new InternalServerError(msg, cause, error)
    case 503 ⇒ new ServiceUnavailableError(msg, cause, error)
    case _   ⇒ new ErrorMessage(code, msg, cause, error, _links)
  }
}

trait UnrecoverableFailure

object UnrecoverableFailures {
  def contains(e: Throwable) = e match {
    case null ⇒ false
    case _: UnrecoverableFailure | _: NullPointerException | _: IllegalArgumentException | _: IllegalStateException | _: JsonProcessingException ⇒ true
    case _ ⇒ false
  }
}


class BadRequestError(msg: String, cause: Throwable = null, error: String = null) extends ErrorMessage(400, msg, cause, error) with UnrecoverableFailure {
  def this(msg: String) = this(msg, null, null)
  def this(msg: String, cause: Throwable) = this(msg, cause, null)
}

class UnauthorizedError(msg: String, cause: Throwable = null, error: String = null, val schema: Option[String] = None) extends ErrorMessage(401, msg, cause, error) with UnrecoverableFailure {
  def this(msg: String) = this(msg, null, null)
  def this(msg: String, cause: Throwable) = this(msg, cause, null)
}

class ForbiddenError(msg: String, cause: Throwable = null, error: String = null, _links: java.util.Map[String, Object] = null) extends ErrorMessage(403, msg, cause, error, _links) with UnrecoverableFailure {
  def this(msg: String) = this(msg, null, null)
  def this(msg: String, cause: Throwable) = this(msg, cause, null)
}

class NotFoundError(msg: String, cause: Throwable = null, error: String = null) extends ErrorMessage(404, msg, cause, error) with UnrecoverableFailure {
  def this(msg: String) = this(msg, null, null)
  def this(msg: String, cause: Throwable) = this(msg, cause, null)
}

class MethodNotAllowedError(msg: String, cause: Throwable = null, error: String = null) extends ErrorMessage(405, msg, cause, error) with UnrecoverableFailure {
  def this(msg: String) = this(msg, null, null)
  def this(msg: String, cause: Throwable) = this(msg, cause, null)
}

class ConflictError(msg: String, cause: Throwable = null, error: String = null) extends ErrorMessage(409, msg, cause, error) with UnrecoverableFailure {
  def this(msg: String) = this(msg, null, null)
  def this(msg: String, cause: Throwable) = this(msg, cause, null)
}

class TooManyRequestError(msg: String, cause: Throwable = null, error: String = null) extends ErrorMessage(429, msg, cause, error) {
  def this(msg: String) = this(msg, null, null)
  def this(msg: String, cause: Throwable) = this(msg, cause, null)
}

class InternalServerError(msg: String, cause: Throwable = null, error: String = null) extends ErrorMessage(500, msg, cause, error) {
  def this(msg: String) = this(msg, null, null)
  def this(msg: String, cause: Throwable) = this(msg, cause, null)
}

class ServiceUnavailableError(msg: String, cause: Throwable = null, error: String = null) extends ErrorMessage(503, msg, cause, error) {
  def this(msg: String) = this(msg, null, null)
  def this(msg: String, cause: Throwable) = this(msg, cause, null)
}

class UnrecoverableError(msg: String, cause: Throwable = null, error: String = null) extends ErrorMessage(456, msg, cause, error) with UnrecoverableFailure {
  def this(msg: String) = this(msg, null, null)
  def this(msg: String, cause: Throwable) = this(msg, cause, null)
}


object Check {
  def req(cond: Boolean, message: String) = require(cond, throw new BadRequestError(message))

  def allow(cond: Boolean, message: String) = require(cond, throw new ForbiddenError(message.toString))

  def allowFor(userId: String, ownerId: String, message: String) =
    require(userId != null && ownerId == userId, throw new ForbiddenError(message))

  def allowFor(userId: String, ownerId1: String, ownerId2: String, message: String) =
    require(userId != null && (ownerId1 == userId || ownerId2 == userId), throw new ForbiddenError(message))

  def allowIfNonEmpty(userId: String, ownerId: String, message: String) =
    require(userId == null || ownerId == userId, throw new ForbiddenError(message))

  def allowIfNonEmpty(userId: String, ownerId1: String, ownerId2: String, message: String) =
    require(userId == null || ownerId1 == userId || ownerId2 == userId, throw new ForbiddenError(message))
}
