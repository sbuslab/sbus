package com.sbuslab.sbus.auth.providers

import java.net.{HttpURLConnection, URL}
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import scala.collection.JavaConverters._

import com.fasterxml.jackson.databind.ObjectMapper
import com.typesafe.config.{Config, ConfigFactory, ConfigValue}
import net.i2p.crypto.eddsa.{EdDSAPublicKey, Utils}
import net.i2p.crypto.eddsa.spec.{EdDSANamedCurveTable, EdDSAPublicKeySpec}

import com.sbuslab.model.InternalServerError
import com.sbuslab.sbus.auth.{Action, DynamicAuthConfigProvider, Identity}


class ConsulAuthConfigProvider(
  conf: Config,
  mapper: ObjectMapper) extends DynamicAuthConfigProvider {

  case class CachedObject(expiredAt: Long, obj: Any)

  val cache = new ConcurrentHashMap[String, CachedObject]()
  val spec  = EdDSANamedCurveTable.getByName("Ed25519")

  val baseUrl        = conf.getString("base-url")
  val publicKeysPath = conf.getString("public-keys-path")
  val identitiesPath = conf.getString("identities-path")
  val configPath     = conf.getString("config-path")
  val cacheDuration  = conf.getDuration("cache-duration")

  override def getPublicKeys: Map[String, EdDSAPublicKey] = {
    def load: Map[String, EdDSAPublicKey] =
      Option(publicKeysPath)
        .filter(_.nonEmpty)
        .flatMap { publicKeysPath ⇒
          val resp =
            try new URL(s"$baseUrl$publicKeysPath?recurse=true").openConnection().asInstanceOf[HttpURLConnection]
            catch {
              case e: Throwable ⇒
                throw new InternalServerError(s"Sbus auth: couldn't fetch public keys from $publicKeysPath endpoint: ${e.getMessage}", e)
            }

          if (resp.getResponseCode == 200) {
            Some(mapper.readTree(resp.getInputStream).elements().asScala.map { node ⇒
              val pubKey = mapper.readTree(Base64.getDecoder.decode(node.path("Value").asText())).path("publicKey").asText()

              node.path("Key").asText().stripPrefix(s"$publicKeysPath").stripPrefix("/") → new EdDSAPublicKey(new EdDSAPublicKeySpec(
                Utils.hexToBytes(pubKey),
                spec
              ))
            }.toMap)
          } else {
            None
          }

        } getOrElse Map.empty

    cache.compute(
      "public-keys",
      (_, exist) ⇒ {
        if (exist == null || exist.expiredAt < System.currentTimeMillis()) {
          CachedObject(System.currentTimeMillis() + cacheDuration.toMillis, load)
        } else {
          exist
        }
      }
    ).obj.asInstanceOf[Map[String, EdDSAPublicKey]]
  }

  override def getActions: Map[String, Action] = getMap("actions")
    .map { case (key, value) ⇒ key → Action(value.atPath("/").getStringList("/").asScala.toSet) }

  override def getIdentities: Map[String, Identity] = {
    def load: Map[String, Identity] =
      Option(identitiesPath)
        .filter(_.nonEmpty)
        .flatMap { identitiesPath ⇒
          val resp =
            try new URL(s"$baseUrl$identitiesPath?recurse=true").openConnection().asInstanceOf[HttpURLConnection]
            catch {
              case e: Throwable ⇒
                throw new InternalServerError(s"Sbus auth: couldn't fetch identities from $identitiesPath endpoint: ${e.getMessage}", e)
            }

          if (resp.getResponseCode == 200) {
            Some(mapper.readTree(resp.getInputStream).elements().asScala.map { node ⇒
              val permissions =
                mapper.readValue(Base64.getDecoder.decode(node.path("Value").asText()), classOf[java.util.Set[String]]).asScala.toSet

              node.path("Key").asText().stripPrefix(s"$identitiesPath").stripPrefix("/") → Identity(permissions)
            }.toMap)
          } else {
            None
          }

        } getOrElse Map.empty

    cache.compute(
      "identities",
      (_, exist) ⇒ {
        if (exist == null || exist.expiredAt < System.currentTimeMillis()) {
          CachedObject(System.currentTimeMillis() + cacheDuration.toMillis, load)
        } else {
          exist
        }
      }
    ).obj.asInstanceOf[Map[String, Identity]]
  }

  override def isRequired: Boolean = opt[Boolean]("required", _.getBoolean).getOrElse(false)

  private def getConfig: Config = {
    cache.compute(
      "config",
      (_, exist) ⇒ {
        if (exist == null || exist.expiredAt < System.currentTimeMillis()) {
          CachedObject(
            System.currentTimeMillis() + cacheDuration.toMillis,
            ConfigFactory.parseURL(new URL(s"$baseUrl$configPath?raw=true"))
          )
        } else {
          exist
        }
      }
    ).obj.asInstanceOf[Config]
  }

  private def opt[T](path: String, getter: Config ⇒ String ⇒ T): Option[T] = {
    val config = getConfig
    if (config.hasPath(path)) {
      Option(getter(config)(path))
    } else {
      None
    }
  }

  private def getMap(path: String): Map[String, ConfigValue] = {
    val config = getConfig
    if (config.hasPath(path)) {
      config.getObject(path).entrySet().asScala.map(entry ⇒ entry.getKey → entry.getValue).toMap
    } else {
      Map.empty
    }
  }
}
