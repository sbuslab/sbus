package com.sbuslab.sbus

import java.net.{HttpURLConnection, URL}
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


trait AuthProvider {
  def sign(context: Context, body: Array[Byte]): Context
  def verify(context: Context, body: Array[Byte]): Unit
}


class AuthProviderImpl(conf: Config, mapper: ObjectMapper) extends AuthProvider {

  private val serviceName = conf.getString("name")

  private val log = Logger(LoggerFactory.getLogger("sbus.auth"))

  private val spec = EdDSANamedCurveTable.getByName("Ed25519")

  private val privKey = new EdDSAPrivateKey(new EdDSAPrivateKeySpec(Utils.hexToBytes(
    Option(conf.getString("private-key")).filter(_.nonEmpty)
      .orElse(Option(conf.getString("default-private-key")).filter(_.nonEmpty))
      .getOrElse(throw new InternalServerError("Missing sbus.auth.private-key configuration!"))
  ), spec))

  private val externalPubKeys = Option(conf.getString("consul-public-keys")).filter(_.nonEmpty) flatMap { consulPath ⇒
    val resp = (new URL(consulPath).openConnection()).asInstanceOf[HttpURLConnection]

    if (resp.getResponseCode == 200) {
      Some(mapper.readTree(resp.getInputStream).elements().asScala.map({ node ⇒
        val pubKey = mapper.readTree(Base64.getDecoder.decode(node.path("Value").asText())).path("publicKey").asText()

        node.path("Key").asText().stripPrefix("services/keys/public/") →
          new EdDSAPublicKey(new EdDSAPublicKeySpec(Utils.hexToBytes(pubKey), spec))
      }).toMap)
    } else {
      None
    }
  } getOrElse Map.empty

  private val publicKeys = externalPubKeys ++ (conf.getConfig("public-keys").atPath("/").getObject("/").asScala.toMap map { case (owner, obj) ⇒
    owner → new EdDSAPublicKey(new EdDSAPublicKeySpec(Utils.hexToBytes(obj.atPath("/").getString("/")), spec))
  })

  private val defaultPublicKey =
    Option(conf.getString("default-private-key")).filter(_.nonEmpty)
      .map(pub ⇒ new EdDSAPublicKey(new EdDSAPublicKeySpec(Utils.hexToBytes(pub), spec)))

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
      .withValue(Headers.Origin, serviceName)
      .withValue(Headers.Signature, Base64.getUrlEncoder.encodeToString(signer.sign()))
  }

  def verify(context: Context, body: Array[Byte]): Unit =
    (for {
      caller    ← context.get(Headers.Origin).map(_.toString)
      signature ← context.get(Headers.Signature)
      pubKey    ← publicKeys.get(caller).orElse(defaultPublicKey)
    } yield {
      val vrf = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm))
      vrf.initVerify(pubKey)

      vrf.update(body)

      val routingKey = context.routingKey

      if (vrf.verify(Base64.getUrlDecoder.decode(signature.toString.replace('+', '-').replace('/', '_')))) {
        val callerGroups = groups.getOrElse(caller, Set.empty)

        if (caller == serviceName
          || access.get("*").exists(rt ⇒ rt.contains("*") || rt.contains(caller) || rt.intersect(callerGroups).nonEmpty)
          || access.get(routingKey).exists(rt ⇒ rt.contains("*") || rt.contains(caller) || rt.intersect(callerGroups).nonEmpty)) {

          // ok
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
