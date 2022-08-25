package com.sbuslab.sbus

import scala.concurrent.{ExecutionContext, Future}
import scala.reflect.ClassTag

import com.sbuslab.model.Message
import com.sbuslab.sbus.auth.AuthProvider

class Sbus(transport: Transport, authProvider: AuthProvider)(implicit ec: ExecutionContext) {
  def sign(routingKey: String, message: Message): Context =
    authProvider.signCommand(Context.empty.withRoutingKey(routingKey), message);

  def request[T](routingKey: String, msg: Any = null)(implicit context: Context = Context.empty, tag: ClassTag[T]): Future[T] =
    transport.send(routingKey, msg, context, tag.runtimeClass).mapTo[T]

  def command(routingKey: String, msg: Any = null)(implicit context: Context = Context.empty): Future[Unit] =
    transport.send(routingKey, msg, context, null).map(_ ⇒ {})

  def event(routingKey: String, msg: Any)(implicit context: Context = Context.empty): Future[Unit] =
    transport.send((if (!routingKey.contains(':')) "events:" else "") + routingKey, msg, context, null).map(_ ⇒ {})

  def on[T, R](routingKey: String)(handler: (T, Context) ⇒ Future[R])(implicit tag: ClassTag[T]): Unit =
    transport.subscribe[T](routingKey, tag.runtimeClass, handler)
}
