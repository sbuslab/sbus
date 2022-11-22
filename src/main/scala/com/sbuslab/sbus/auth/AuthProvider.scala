package com.sbuslab.sbus.auth

import scala.language.postfixOps

import java.security.MessageDigest
import java.util.Base64
import scala.collection.JavaConverters._
import scala.util.{Failure, Success, Try}

import com.fasterxml.jackson.databind.json.JsonMapper
import com.fasterxml.jackson.module.scala.DefaultScalaModule
import com.typesafe.config.{Config, ConfigRenderOptions}
import com.typesafe.scalalogging.Logger
import net.i2p.crypto.eddsa.{EdDSAEngine, EdDSAPrivateKey, EdDSAPublicKey, Utils}
import net.i2p.crypto.eddsa.spec.{EdDSANamedCurveSpec, EdDSANamedCurveTable, EdDSAPrivateKeySpec, EdDSAPublicKeySpec}
import org.slf4j.LoggerFactory

import com.sbuslab.model.{ForbiddenError, InternalServerError}
import com.sbuslab.sbus.{Context, Headers}


trait AuthProvider {

  def signCommand(context: Context, cmd: Array[Byte]): Context

  def verifyCommandSignature(context: Context, body: Array[Byte]): Try[Unit]

  def authorizeCommand(context: Context): Try[Unit]
}


class AuthProviderImpl(val conf: Config, val dynamicProvider: DynamicAuthConfigProvider) extends AuthProvider {

  private val mapper = JsonMapper.builder().addModule(DefaultScalaModule).build()

  private val log: Logger = Logger(LoggerFactory.getLogger("sbus.auth"))

  val spec: EdDSANamedCurveSpec = EdDSANamedCurveTable.getByName("Ed25519")

  val serviceName: String = conf.getString("name")

  private val localIsRequired: Boolean = conf.getBoolean("required").booleanValue()

  private val privKey = new EdDSAPrivateKey(new EdDSAPrivateKeySpec(
    Utils.hexToBytes(
      Option(conf.getString("private-key")).filter(_.nonEmpty)
        .getOrElse(throw new InternalServerError("Missing sbus.auth.private-key configuration!"))
    ),
    spec
  ))

  private val localPublicKeys: Map[String, EdDSAPublicKey] = conf.getObject("public-keys").asScala map { case (owner, obj) ⇒
    owner → new EdDSAPublicKey(new EdDSAPublicKeySpec(Utils.hexToBytes(obj.atPath("/").getString("/")), spec))
  } toMap

  private val localActions: Map[String, Action] = conf.getConfig("rbac").getObject("actions").asScala.toMap.map { case (action, obj) ⇒
    action → mapper.readValue(obj.render(ConfigRenderOptions.concise().setJson(true)), classOf[Action])
  }

  private val localIdentities: Map[String, Identity] = conf.getConfig("rbac").getObject("identities").asScala.toMap.map { case (owner, obj) ⇒
    owner → mapper.readValue(obj.render(ConfigRenderOptions.concise().setJson(true)), classOf[Identity])
  }

  private val success = Success {}

  override def authorizeCommand(context: Context): Try[Unit] = {
    (for {
      origin     ← context.get(Headers.Origin)
      routingKey ← context.get(Headers.RoutingKey)
    } yield {
      if (origin == serviceName) {
        success
      } else {
        getAction(routingKey).orElse(getAction("*")) match {
          case Some(action) ⇒
            val identity = getIdentity(origin).getOrElse(Identity(Set.empty))

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

  override def verifyCommandSignature(context: Context, cmd: Array[Byte]): Try[Unit] =
    (for {
      origin     ← context.get(Headers.Origin)
      signature  ← context.get(Headers.Signature)
      routingKey ← context.get(Headers.RoutingKey)
      pubKey     ← getPublicKey(origin)
    } yield {
      val edDSAEngine = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm))
      edDSAEngine.initVerify(pubKey)

      edDSAEngine.update(cmd)
      edDSAEngine.update(routingKey.getBytes)
      edDSAEngine.update(origin.getBytes)

      if (!edDSAEngine.verify(Base64.getUrlDecoder.decode(signature.replace('+', '-').replace('/', '_')))) {
        failure(
          s"Signature invalid for sbus cmd: ${context.routingKey}, origin: $origin, body: ${new String(cmd)}, signature: $signature"
        )
      } else {
        success
      }
    }) getOrElse {
      failure(
        s"Unauthenticated sbus cmd: ${context.routingKey}, origin: ${context.origin}"
      )
    }

  override def signCommand(context: Context, cmd: Array[Byte]): Context =
    if (context.get(Headers.ProxyPass).contains("true")) {
      context
    } else {
      val edDSAEngine = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm))
      edDSAEngine.initSign(privKey)

      edDSAEngine.update(cmd)
      context.get(Headers.RoutingKey) foreach { routingKey ⇒ edDSAEngine.update(routingKey.getBytes) }
      edDSAEngine.update(serviceName.getBytes)

      val signature = Base64.getUrlEncoder.encodeToString(edDSAEngine.sign())

      context
        .withValue(Headers.Origin, serviceName)
        .withValue(Headers.Signature, signature)
    }

  private def getPublicKey(origin: String): Option[EdDSAPublicKey] =
    dynamicProvider.getPublicKeys.get(origin).orElse(localPublicKeys.get(origin))

  private def getAction(routingKey: String): Option[Action] =
    dynamicProvider.getActions.get(routingKey).orElse(localActions.get(routingKey))

  private def getIdentity(origin: String): Option[Identity] =
    dynamicProvider.getIdentities.get(origin).orElse(localIdentities.get(origin))

  private def isRequired: Boolean =
    dynamicProvider.isRequired.getOrElse(localIsRequired)

  private def failure(reason: String): Try[Unit] = {
    log.trace(reason)

    if (isRequired) {
      Failure(new ForbiddenError(reason))
    } else {
      success
    }
  }
}


class NoopAuthProvider extends AuthProvider {
  private val success = Success {}

  override def authorizeCommand(context: Context): Try[Unit] = success

  override def signCommand(context: Context, cmd: Array[Byte]): Context = context

  override def verifyCommandSignature(context: Context, cmd: Array[Byte]): Try[Unit] = success
}
