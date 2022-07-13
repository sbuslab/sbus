package com.sbuslab.sbus.auth

import scala.language.postfixOps
import java.security.MessageDigest
import java.util.Base64
import scala.collection.JavaConverters._
import scala.util.{Failure, Success, Try}
import com.fasterxml.jackson.databind.ObjectMapper
import com.typesafe.config.Config
import com.typesafe.scalalogging.Logger
import net.i2p.crypto.eddsa.{EdDSAEngine, EdDSAPrivateKey, EdDSAPublicKey, Utils}
import net.i2p.crypto.eddsa.spec.{EdDSANamedCurveSpec, EdDSANamedCurveTable, EdDSAPrivateKeySpec, EdDSAPublicKeySpec}
import org.slf4j.LoggerFactory
import com.sbuslab.model.{ForbiddenError, InternalServerError}
import com.sbuslab.sbus.{Context, Headers}

trait AuthProvider {
  def signMessageRequest(context: Context, body: Array[Byte]): Context

  def verifyMessageSignature(context: Context, body: Array[Byte]): Try[Unit]

  def signCommand(context: Context, cmd: Option[Any]): Context

  def verifyCommandSignature(context: Context, body: Option[Array[Byte]]): Try[Unit]

  def authorizeCommand(context: Context): Try[Unit]
}

class AuthProviderImpl(val conf: Config, val mapper: ObjectMapper, val dynamicProvider: DynamicAuthConfigProvider)
    extends AuthProvider {

  val log: Logger = Logger(LoggerFactory.getLogger("sbus.auth"))

  val spec: EdDSANamedCurveSpec = EdDSANamedCurveTable.getByName("Ed25519")

  val serviceName: String = conf.getString("name")

  val localIsRequired: Boolean = conf.getBoolean("required").booleanValue()

  val privKey = new EdDSAPrivateKey(new EdDSAPrivateKeySpec(
    Utils.hexToBytes(
      Option(conf.getString("private-key")).filter(_.nonEmpty)
        .getOrElse(throw new InternalServerError("Missing sbus.auth.private-key configuration!"))
    ),
    spec
  ))

  val localPublicKeys: Map[String, EdDSAPublicKey] = conf.getObject("public-keys").asScala map { case (owner, obj) ⇒
    owner → new EdDSAPublicKey(new EdDSAPublicKeySpec(Utils.hexToBytes(obj.atPath("/").getString("/")), spec))
  } toMap

  val localActions: Map[String, Action] = conf.getConfig("rbac").getObject("actions").asScala.toMap.map { case (action, obj) ⇒
    action → Action(obj.atPath("/").getStringList("/").asScala.toSet)
  }

  val localIdentities: Map[String, Identity] = conf.getConfig("rbac").getObject("identities").asScala.toMap.map { case (owner, obj) ⇒
    owner → Identity(obj.atPath("/").getStringList("/").asScala.toSet)
  }

  private val success = Success {}

  override def signMessageRequest(context: Context, body: Array[Byte]): Context = {
    val edDSAEngine = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm))
    edDSAEngine.initSign(privKey)

    edDSAEngine.update(body)

    addMessageHeadersToEngine(context, edDSAEngine)

    val signature = Base64.getUrlEncoder.encodeToString(edDSAEngine.sign())

    log.debug(s"Signing sbus message: ${context.routingKey}, origin: $serviceName")

    context
      .withValue(Headers.MessageOrigin, serviceName)
      .withValue(Headers.MessageSignature, signature)
  }

  override def verifyMessageSignature(context: Context, body: Array[Byte]): Try[Unit] =
    (for {
      origin    ← context.get(Headers.MessageOrigin)
      signature ← context.get(Headers.MessageSignature)
      pubKey    ← getPublicKeys.get(origin)
    } yield {
      val edDSAEngine = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm))
      edDSAEngine.initVerify(pubKey)

      edDSAEngine.update(body)

      addMessageHeadersToEngine(context, edDSAEngine)

      if (!edDSAEngine.verify(Base64.getUrlDecoder.decode(signature.replace('+', '-').replace('/', '_')))) {
        return failure(
          s"Signature invalid for sbus message: ${context.routingKey}, $origin"
        )
      }

      success
    }) getOrElse {
      failure(
        s"Unauthenticated sbus message: ${context.routingKey}, origin: ${context.get(Headers.MessageOrigin)}"
      )
    }

  override def authorizeCommand(context: Context): Try[Unit] = {
    (for {
      origin     ← context.get(Headers.Origin)
      routingKey ← context.get(Headers.RoutingKey)
    } yield {
      if (origin == serviceName) {
        success
      } else {
        val actions = getActions

        actions.get(routingKey).orElse(actions.get("*")) match {
          case Some(action) ⇒
            val identity = getIdentities.getOrElse(origin, Identity(Set()))

            val authorized =
              identity.isMemberOfAny(action.permissions) || action.permissions.contains(origin) || action.permissions.contains("*")

            if (!authorized) {
              failure(s"Unauthorised sbus cmd: ${context.routingKey}, origin $origin")
            } else {
              success
            }

          case _ ⇒
            failure(
              s"No action defined for sbus cmd: ${context.routingKey}, origin $origin"
            )
        }
      }

    }) getOrElse {
      failure(
        s"Unauthenticated sbus cmd: ${context.routingKey}, origin ${context.origin}"
      )
    }

  }

  override def verifyCommandSignature(context: Context, cmd: Option[Array[Byte]]): Try[Unit] =
    (for {
      origin     ← context.get(Headers.Origin)
      signature  ← context.get(Headers.Signature)
      routingKey ← context.get(Headers.RoutingKey)
      pubKey     ← getPublicKeys.get(origin)
    } yield {
      val edDSAEngine = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm))
      edDSAEngine.initVerify(pubKey)

      cmd foreach edDSAEngine.update
      edDSAEngine.update(routingKey.getBytes)
      edDSAEngine.update(origin.getBytes)

      if (!edDSAEngine.verify(Base64.getUrlDecoder.decode(signature.replace('+', '-').replace('/', '_')))) {
        failure(
          s"Signature invalid for sbus cmd: ${context.routingKey}, origin: $origin"
        )
      } else {
        success
      }
    }) getOrElse {
      failure(
        s"Unauthenticated sbus cmd: ${context.routingKey}, origin: ${context.origin}"
      )
    }

  override def signCommand(context: Context, cmd: Option[Any]): Context = {
    if (context.get(Headers.ProxyPass).exists(_.toBoolean)) {
      context
    } else {
      val edDSAEngine = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm))
      edDSAEngine.initSign(privKey)

      cmd map mapper.writeValueAsBytes foreach edDSAEngine.update
      context.get(Headers.RoutingKey) foreach { routingKey ⇒ edDSAEngine.update(routingKey.getBytes) }
      edDSAEngine.update(serviceName.getBytes)

      val signature = Base64.getUrlEncoder.encodeToString(edDSAEngine.sign())

      log.debug(s"Signing sbus cmd: ${context.routingKey}, origin $serviceName")

      context
        .withValue(Headers.Origin, serviceName)
        .withValue(Headers.Signature, signature)
    }
  }

  private def addMessageHeadersToEngine(context: Context, edDSAEngine: EdDSAEngine): Unit = {
    context.get(Headers.Timestamp) foreach { timestamp ⇒ edDSAEngine.update(timestamp.getBytes) }
    context.get(Headers.RoutingKey) foreach { value ⇒ edDSAEngine.update(value.getBytes) }
    context.get(Headers.CorrelationId) foreach { value ⇒ edDSAEngine.update(value.getBytes) }
  }

  private def getPublicKeys: Map[String, EdDSAPublicKey] =
    localPublicKeys ++ dynamicProvider.getPublicKeys

  private def getActions: Map[String, Action] =
    localActions ++ dynamicProvider.getActions

  private def getIdentities: Map[String, Identity] =
    localIdentities ++ dynamicProvider.getIdentities

  private def isRequired: Boolean =
    localIsRequired || dynamicProvider.isRequired

  private def failure(reason: String): Try[Unit] = {
    log.warn(reason)

    if (isRequired) {
      Failure(new ForbiddenError(reason))
    } else {
      Success {}
    }
  }
}

class NoopAuthProvider extends AuthProvider {
  private val success = Success {}

  override def signMessageRequest(context: Context, body: Array[Byte]): Context = context

  override def verifyMessageSignature(context: Context, body: Array[Byte]): Try[Unit] = success

  override def authorizeCommand(context: Context): Try[Unit] = success

  override def signCommand(context: Context, cmd: Option[Any]): Context = context

  override def verifyCommandSignature(context: Context, cmd: Option[Array[Byte]]): Try[Unit] = success
}
