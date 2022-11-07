package com.sbuslab.sbus.auth.providers

import java.net.{HttpURLConnection, URL}
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import scala.collection.JavaConverters._
import scala.reflect.ClassTag

import com.fasterxml.jackson.databind.json.JsonMapper
import com.fasterxml.jackson.module.scala.DefaultScalaModule
import com.typesafe.config.{Config, ConfigFactory, ConfigParseOptions, ConfigRenderOptions}
import com.typesafe.scalalogging.Logger
import net.i2p.crypto.eddsa.{EdDSAPublicKey, Utils}
import net.i2p.crypto.eddsa.spec.{EdDSANamedCurveTable, EdDSAPublicKeySpec}
import org.slf4j.LoggerFactory

import com.sbuslab.model.InternalServerError
import com.sbuslab.sbus.auth.{Action, DynamicAuthConfigProvider, Identity}


class ConsulAuthConfigProvider(conf: Config) extends DynamicAuthConfigProvider {

  val log: Logger = Logger(LoggerFactory.getLogger("sbus.auth"))

  case class CachedObject(expiredAt: Long, obj: Any)

  val mapper = JsonMapper.builder().addModule(DefaultScalaModule).build()

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
          val resp = new URL(s"$baseUrl$publicKeysPath?recurse=true").openConnection().asInstanceOf[HttpURLConnection]

          if (resp.getResponseCode == 200) {
            Option(mapper.readTree(resp.getInputStream).elements().asScala.map { node ⇒
              val pubKey = mapper.readTree(Base64.getDecoder.decode(node.path("Value").asText())).path("publicKey").asText()

              node.path("Key").asText().stripPrefix(s"$publicKeysPath").stripPrefix("/") → new EdDSAPublicKey(new EdDSAPublicKeySpec(
                Utils.hexToBytes(pubKey),
                spec
              ))
            }.toMap)
          } else {
            throw new InternalServerError(
              s"Sbus auth: couldn't fetch public keys from $publicKeysPath endpoint with status code ${resp.getResponseCode}"
            )
          }

        } getOrElse Map.empty

    cache.compute(
      "public-keys",
      (_, exist) ⇒ {
        if (exist == null || exist.expiredAt < System.currentTimeMillis()) {
          try CachedObject(System.currentTimeMillis() + cacheDuration.toMillis, load)
          catch {
            case e: Throwable ⇒
              if (exist == null) {
                log.error("Couldn't update cached object from consul, defaulting values", e)
                CachedObject(0, Map.empty[String, EdDSAPublicKey])
              } else {
                log.error("Couldn't update cached object from consul, using expired values", e)
                exist
              }
          }
        } else {
          exist
        }
      }
    ).obj.asInstanceOf[Map[String, EdDSAPublicKey]]
  }

  override def getActions: Map[String, Action] = getMap[Action]("actions")

  override def getIdentities: Map[String, Identity] = {
    def load: Map[String, Identity] =
      Option(identitiesPath)
        .filter(_.nonEmpty)
        .flatMap { identitiesPath ⇒
          val resp =
            new URL(s"$baseUrl$identitiesPath?recurse=true").openConnection().asInstanceOf[HttpURLConnection]

          if (resp.getResponseCode == 200) {
            Option(mapper.readTree(resp.getInputStream).elements().asScala.map { node ⇒
              val identity =
                mapper.readValue(Base64.getDecoder.decode(node.path("Value").asText()), classOf[Identity])

              node.path("Key").asText().stripPrefix(s"$identitiesPath").stripPrefix("/") → identity
            }.toMap)
          } else {
            throw new InternalServerError(
              s"Sbus auth: couldn't fetch identities from $identitiesPath endpoint with status code ${resp.getResponseCode}"
            )
          }

        } getOrElse Map.empty

    cache.compute(
      "identities",
      (_, exist) ⇒ {
        if (exist == null || exist.expiredAt < System.currentTimeMillis()) {
          try CachedObject(System.currentTimeMillis() + cacheDuration.toMillis, load)
          catch {
            case e: Throwable ⇒
              if (exist == null) {
                log.error("Couldn't update cached object from consul, defaulting values", e)
                CachedObject(0, Map.empty[String, Identity])
              } else {
                log.error("Couldn't update cached object from consul, using expired values", e)
                exist
              }
          }
        } else {
          exist
        }
      }
    ).obj.asInstanceOf[Map[String, Identity]]
  }

  override def isRequired: Option[Boolean] = opt[Boolean]("required", _.getBoolean)

  private def getConfig: Config = {
    cache.compute(
      "config",
      (_, exist) ⇒ {
        if (exist == null || exist.expiredAt < System.currentTimeMillis()) {
          try CachedObject(
              System.currentTimeMillis() + cacheDuration.toMillis,
              ConfigFactory.parseURL(new URL(s"$baseUrl$configPath?raw=true"), ConfigParseOptions.defaults().setAllowMissing(false))
            )
          catch {
            case e: Throwable ⇒
              if (exist == null) {
                log.error("Couldn't update cached object from consul, defaulting values with validation off", e)
                CachedObject(0, ConfigFactory.parseMap(Map("required" → false).asJava))
              } else {
                log.error("Couldn't update cached object from consul, using expired values", e)
                exist
              }
          }
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

  private def getMap[T](path: String)(implicit classTag: ClassTag[T]): Map[String, T] = {
    val config = getConfig
    if (config.hasPath(path)) {
      config.getObject(path).asScala.toMap.map {
        case (key, obj) ⇒
          key → mapper.readValue(obj.render(ConfigRenderOptions.concise().setJson(true)), classTag.runtimeClass).asInstanceOf[T]
      }
    } else {
      Map.empty
    }
  }
}
