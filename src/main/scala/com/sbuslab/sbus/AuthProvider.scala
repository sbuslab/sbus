package com.sbuslab.sbus

import java.security.MessageDigest
import java.util.Base64
import scala.collection.JavaConverters._

import com.fasterxml.jackson.databind.ObjectMapper
import com.typesafe.config.Config
import com.typesafe.scalalogging.Logger
import net.i2p.crypto.eddsa.{EdDSAEngine, EdDSAPrivateKey, EdDSAPublicKey, Utils}
import net.i2p.crypto.eddsa.spec.{EdDSANamedCurveTable, EdDSAPrivateKeySpec, EdDSAPublicKeySpec}
import org.slf4j.LoggerFactory

import com.sbuslab.model.InternalServerError
import com.sbuslab.sbus.auth.{Action, DynamicAuthConfigProvider, DynamicRbacProvider, Identity}

trait AuthProvider {
  def sign(context: Context, body: Array[Byte]): Context
  def verify(context: Context, body: Array[Byte]): Boolean
  def authorize(context: Context): Boolean
}

case class AuthProviderImpl(conf: Config, mapper: ObjectMapper, dynamicProvider: DynamicAuthConfigProvider with DynamicRbacProvider)
    extends AuthProvider {

  val Log = Logger(LoggerFactory.getLogger("sbus.auth"))

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

  override def sign(context: Context, body: Array[Byte]): Context = {
    val signer = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm))
    signer.initSign(privKey)

    signer.update(body)

    context
      .withValue(Headers.Origin, serviceName)
      .withValue(Headers.Signature, Base64.getUrlEncoder.encodeToString(signer.sign()))
  }

  override def verify(context: Context, body: Array[Byte]): Boolean =
    (for {
      caller    ← context.get(Headers.Origin)
      signature ← context.get(Headers.Signature)
      pubKey    ← getPublicKeys.get(caller)
    } yield {
      Log.debug(s"Verifying sbus request: ${context.routingKey}, caller $caller, ip ${context.ip}, message ${context.messageId}")

      val vrf = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm))
      vrf.initVerify(pubKey)

      vrf.update(body)

      if (vrf.verify(Base64.getUrlDecoder.decode(signature.replace('+', '-').replace('/', '_')))) {
        true
      } else {
        Log.warn(
          s"Signature invalid for sbus request: ${context.routingKey}, caller $caller, ip ${context.ip}, message ${context.messageId}"
        )
        !isRequired
      }
    }) getOrElse {
      Log.warn(
        s"Unauthenticated sbus request: ${context.routingKey}, caller ${context.get(Headers.Origin)}, ip ${context.ip}, message ${context.messageId}"
      )
      !isRequired
    }

  override def authorize(context: Context): Boolean =
    (for {
      caller     ← context.get(Headers.Origin)
      routingKey ← context.get(Headers.RoutingKey)
    } yield {
      if (caller == serviceName) {
        true
      } else {
        getIdentities.get(caller) map { identity ⇒
          getActions.get(routingKey).orElse(getActions.get("*"))
            .map(action ⇒
              (identity.isMemberOfAny(action.permissions) || action.permissions.contains(caller) || action.permissions.contains("*")) || !isRequired
            )
            .getOrElse {
              Log.warn(s"No access to sbus request: ${context.routingKey}, caller $caller, ip ${context.ip}, message ${context.messageId}")
              !isRequired
            }
        } getOrElse {
          Log.warn(
            s"No identity configured for sbus request caller: ${context.routingKey}, caller $caller, ip ${context.ip}, message ${context.messageId}"
          )
          !isRequired
        }
      }
    }) getOrElse {
      Log.warn(
        s"Unauthenticated sbus request: ${context.routingKey}, caller ${context.get(Headers.Origin)}, ip ${context.ip}, message ${context.messageId}"
      )
      !isRequired
    }

  private def getPublicKeys: Map[String, EdDSAPublicKey] =
    localPublicKeys ++ dynamicProvider.getPublicKeys

  private def getActions: Map[String, Action] =
    localActions ++ dynamicProvider.getActions

  private def getIdentities: Map[String, Identity] =
    localIdentities ++ dynamicProvider.getIdentities

  private def isRequired: Boolean =
    localIsRequired || dynamicProvider.isRequired
}

class NoopAuthProvider extends AuthProvider {
  override def sign(context: Context, body: Array[Byte]): Context   = context
  override def verify(context: Context, body: Array[Byte]): Boolean = true
  override def authorize(context: Context): Boolean                 = true
}
