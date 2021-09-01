package com.sbuslab.sbus

import java.security.MessageDigest
import java.util.Base64
import scala.collection.JavaConverters._

import com.typesafe.config.Config
import com.typesafe.scalalogging.Logger
import net.i2p.crypto.eddsa.{EdDSAEngine, EdDSAPrivateKey, EdDSAPublicKey, Utils}
import net.i2p.crypto.eddsa.spec.{EdDSANamedCurveTable, EdDSAPrivateKeySpec, EdDSAPublicKeySpec}
import org.slf4j.LoggerFactory


trait AuthProvider {
  def sign(context: Context, body: Array[Byte]): Context
  def verify(context: Context, body: Array[Byte]): Unit
}


class AuthProviderImpl(conf: Config) extends AuthProvider {

  private val originName = conf.getString("name")

  private val log = Logger(LoggerFactory.getLogger("sbus.auth"))

  private val spec = EdDSANamedCurveTable.getByName("Ed25519")

  private val privKey = new EdDSAPrivateKey(new EdDSAPrivateKeySpec(Utils.hexToBytes(conf.getString("private-key")), spec))

  private val publicKeys = conf.getConfig("public-keys").atPath("/").getObject("/").asScala.toMap map { case (owner, obj) ⇒
    owner → new EdDSAPublicKey(new EdDSAPublicKeySpec(Utils.hexToBytes(obj.atPath("/").getString("/")), spec))
  }

  private val access = conf.getConfig("access").atPath("/").getObject("/").asScala.toMap map { case (resource, obj) ⇒
    resource → obj.atPath("/").getStringList("/").asScala.toSet
  }

  private val groups = conf.getConfig("groups").atPath("/").getObject("/").asScala.toList.flatMap({ case (group, obj) ⇒
    obj.atPath("/").getStringList("/").asScala.toList.map((_, group))
  }).groupBy(_._1).mapValues(_.map(_._2).toSet)


  def sign(context: Context, body: Array[Byte]): Context = {
    val signer = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm))
    signer.initSign(privKey)

    signer.update(body)

    context
      .withValue(Headers.Origin, originName)
      .withValue(Headers.Signature, Base64.getUrlEncoder.encodeToString(signer.sign()))
  }

  def verify(context: Context, body: Array[Byte]): Unit =
    (for {
      caller ← context.get(Headers.Origin).map(_.toString)
      signature ← context.get(Headers.Signature)
      pubKey ← publicKeys.get(caller)
    } yield {
      val vrf = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm))
      vrf.initVerify(pubKey)

      vrf.update(body)

      val routingKey = context.routingKey

      if (vrf.verify(Base64.getUrlDecoder.decode(signature.toString))) {
        val callerGroups = groups.getOrElse(caller, Set.empty)

        if (caller == originName
          || access.get("*").exists(rt ⇒ rt.contains("*") || rt.contains(caller) || rt.intersect(callerGroups).nonEmpty)
          || access.get(routingKey).exists(rt ⇒ rt.contains("*") || rt.contains(caller) || rt.intersect(callerGroups).nonEmpty)) {

          log.trace(s"Sbus: $caller get access to $routingKey")
        } else {
          log.warn(s"Sbus: $caller has no access to $routingKey method!")
        }
      } else {
        log.warn(s"Incorrect internal request signature: $caller → $routingKey ($signature)")
      }

    }) getOrElse {
      log.debug(s"Unauthenticated sbus request: ${context.routingKey}, caller: ${context.get(Headers.Origin)}")
    }
}


class NoopAuthProvider extends AuthProvider {
  override def sign(context: Context, body: Array[Byte]): Context = context
  override def verify(context: Context, body: Array[Byte]): Unit = {}
}
