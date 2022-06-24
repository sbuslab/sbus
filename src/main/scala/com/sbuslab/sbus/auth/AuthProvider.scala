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
import net.i2p.crypto.eddsa.spec.{EdDSANamedCurveTable, EdDSAPrivateKeySpec, EdDSAPublicKeySpec}
import org.slf4j.LoggerFactory

import com.sbuslab.model.{ForbiddenError, InternalServerError}
import com.sbuslab.sbus.{Context, Headers}


trait AuthProvider {
  def sign(context: Context, body: Array[Byte]): Context
  def verify(context: Context, body: Array[Byte]): Try[Unit]
  def authorize(context: Context): Try[Unit]
}

case class AuthProviderImpl(conf: Config, mapper: ObjectMapper, dynamicProvider: DynamicAuthConfigProvider)
    extends AuthProvider {

  val log = Logger(LoggerFactory.getLogger("sbus.auth"))

  val spec = EdDSANamedCurveTable.getByName("Ed25519")

  val serviceName = conf.getString("name")

  val localIsRequired = conf.getBoolean("required").booleanValue()

  val privKey = new EdDSAPrivateKey(new EdDSAPrivateKeySpec(
    Utils.hexToBytes(
      Option(conf.getString("private-key")).filter(_.nonEmpty)
        .getOrElse(throw new InternalServerError("Missing sbus.auth.private-key configuration!"))
    ),
    spec
  ))

  val localPublicKeys = conf.getObject("public-keys").asScala map { case (owner, obj) ⇒
    owner → new EdDSAPublicKey(new EdDSAPublicKeySpec(Utils.hexToBytes(obj.atPath("/").getString("/")), spec))
  } toMap

  val localActions = conf.getConfig("rbac").getObject("actions").asScala.toMap.map { case (action, obj) ⇒
    action → Action(obj.atPath("/").getStringList("/").asScala.toSet)
  }

  val localIdentities = conf.getConfig("rbac").getObject("identities").asScala.toMap.map { case (owner, obj) ⇒
    owner → Identity(obj.atPath("/").getStringList("/").asScala.toSet)
  }

  private val success = Success({})


  override def sign(context: Context, body: Array[Byte]): Context = {
    val signer = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm))
    signer.initSign(privKey)

    signer.update(body)
    context.get(Headers.Timestamp) foreach { timestamp ⇒ signer.update(timestamp.getBytes) }

    context
      .withValue(Headers.Origin, serviceName)
      .withValue(Headers.Signature, Base64.getUrlEncoder.encodeToString(signer.sign()))
  }

  override def verify(context: Context, body: Array[Byte]): Try[Unit] =
    (for {
      caller     ← context.get(Headers.Origin)
      signature  ← context.get(Headers.Signature)
      pubKey     ← getPublicKeys.get(caller)
    } yield {
      val vrf = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm))
      vrf.initVerify(pubKey)
      vrf.update(body)
      context.get(Headers.Timestamp) foreach { timestamp ⇒ vrf.update(timestamp.getBytes) }

      if (!vrf.verify(Base64.getUrlDecoder.decode(signature.replace('+', '-').replace('/', '_')))) {
        return failure(s"Signature invalid for sbus request: ${context.routingKey}, caller $caller, ip ${context.ip}, message ${context.messageId}, signature: $signature, timestamp ${context.get(Headers.Timestamp)}")
      }

      success
    }) getOrElse {
      failure(s"Unauthenticated sbus request: ${context.routingKey}, caller ${context.get(Headers.Origin)}, ip ${context.ip}, messageId ${context.messageId}")
    }

  override def authorize(context: Context): Try[Unit] =
    (for {
      caller     ← context.get(Headers.Origin)
      routingKey ← context.get(Headers.RoutingKey)
    } yield {
      if (caller == serviceName) {
        return success
      }

      val actions = getActions

      actions.get(routingKey).orElse(actions.get("*")) match {
        case Some(action) ⇒
          val identity = getIdentities.getOrElse(caller, Identity(Set()))

          val authorized =
            identity.isMemberOfAny(action.permissions) || action.permissions.contains(caller) || action.permissions.contains("*")

          if (!authorized) {
            failure(s"Unauthorised sbus request: ${context.routingKey}, caller $caller, ip ${context.ip}, message ${context.messageId}")
          } else {
            success
          }

        case _ ⇒
          failure(s"No action defined for sbus request: ${context.routingKey}, caller $caller, ip ${context.ip}, message ${context.messageId}")
      }
    }) getOrElse {
      failure(s"Unauthenticated sbus request: ${context.routingKey}, caller ${context.get(Headers.Origin)}, ip ${context.ip}, messageId ${context.messageId}")
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
      Success({})
    }
  }
}

class NoopAuthProvider extends AuthProvider {
  private val success = Success({})

  override def sign(context: Context, body: Array[Byte]): Context = context
  override def verify(context: Context, body: Array[Byte]): Try[Unit] = success
  override def authorize(context: Context): Try[Unit] = success
}
