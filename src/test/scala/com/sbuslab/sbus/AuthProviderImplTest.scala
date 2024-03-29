package com.sbuslab.sbus

import scala.language.postfixOps

import java.security.MessageDigest
import java.util.Base64
import scala.collection.JavaConverters._
import scala.util.{Failure, Success}

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.scala.DefaultScalaModule
import com.typesafe.config.{ConfigFactory, ConfigValueFactory}
import net.i2p.crypto.eddsa._
import org.junit.runner.RunWith
import org.mockito.Mockito.when
import org.scalatest.{AsyncWordSpec, Matchers}
import org.scalatest.junit.JUnitRunner
import org.scalatest.mockito.MockitoSugar

import com.sbuslab.model.Message
import com.sbuslab.sbus.auth.{Action, AuthProviderImpl, Identity}
import com.sbuslab.sbus.auth.providers.ConsulAuthConfigProvider

@RunWith(classOf[JUnitRunner])
class AuthProviderImplTest extends AsyncWordSpec with Matchers with MockitoSugar {

  def defaultConfig =
    s"""{
       | enabled = true
       |
       | name = "services/java-service"
       |
       | rbac {
       |   identities = {
       |     "users/joe.bloggs": {
       |       "groups": ["devs"]
       |     }
       |     "users/sarah.dene": {
       |       "groups": ["support"]
       |     }
       |     "services/other-service": {
       |       "groups": ["services"]
       |     }
       |   }
       |   actions = {
       |     "*": { "permissions": ["*"] }
       |     "users.create-user": { "permissions": ["devs", "services", "users/sarah.dene"] }
       |     "users.delete-user": { "permissions": ["devs"] }
       |     "users.update-user": { "permissions": ["*"] }
       |   }
       | }}""".stripMargin

  case class TestSuite(config: String = defaultConfig, required: Boolean = true) {
    val objectMapper        = new ObjectMapper().registerModule(DefaultScalaModule)
    val mockDynamicProvider = mock[ConsulAuthConfigProvider]

    val keyPair  = new KeyPairGenerator().generateKeyPair
    val keyPair2 = new KeyPairGenerator().generateKeyPair

    val underTest = new AuthProviderImpl(
      ConfigFactory
        .parseString(config)
        .withValue("required", ConfigValueFactory.fromAnyRef(required))
        .withValue(
          "private-key",
          ConfigValueFactory.fromAnyRef(Utils.bytesToHex(keyPair.getPrivate.asInstanceOf[EdDSAPrivateKey].getSeed))
        )
        .withValue(
          "public-keys",
          ConfigValueFactory.fromMap(Map[String, String](
            ("services/java-service", Utils.bytesToHex(keyPair.getPublic.asInstanceOf[EdDSAPublicKey].getAbyte)),
            ("services/other-service", Utils.bytesToHex(keyPair2.getPublic.asInstanceOf[EdDSAPublicKey].getAbyte)),
            ("services/javascript-service", "bb908e16a0d9024a8d25ca720aaf2a4e35126462a329b52fbe01837545d00432"),
            ("services/cli-service", "59842ab5f5d5b515126eb86a799d9fa4547b1b42209ca7ff96a189d4bd2f3130")
          ).asJava)
        )
        .resolve(),
      mockDynamicProvider
    )

    def signMessageRequest(
      context: Context,
      body: Array[Byte],
      serviceName: String,
      privKey: EdDSAPrivateKey,
      timestamp: Array[Byte]): Context = {
      val signer = new EdDSAEngine(MessageDigest.getInstance(underTest.spec.getHashAlgorithm))
      signer.initSign(privKey)

      signer.update(body)
      signer.update(timestamp)

      context
        .withValue(Headers.Origin, serviceName)
        .withValue(Headers.Signature, Base64.getUrlEncoder.encodeToString(signer.sign()))
    }

    def signCommand(
      context: Context,
      body: Array[Byte],
      serviceName: String,
      privKey: EdDSAPrivateKey,
      routingKey: Array[Byte]): Context = {
      val signer = new EdDSAEngine(MessageDigest.getInstance(underTest.spec.getHashAlgorithm))
      signer.initSign(privKey)

      signer.update(body)
      signer.update(routingKey)
      signer.update(serviceName.getBytes)

      context
        .withValue(Headers.Origin, serviceName)
        .withValue(Headers.Signature, Base64.getUrlEncoder.encodeToString(signer.sign()))
    }

    def verifyMessageSignature(
      signature: Array[Byte],
      body: Array[Byte],
      pubKey: EdDSAPublicKey,
      timestamp: Array[Byte],
      routingKey: Array[Byte],
      correlationId: Array[Byte]): Boolean = {

      val vrf = new EdDSAEngine(MessageDigest.getInstance(underTest.spec.getHashAlgorithm))
      vrf.initVerify(pubKey)

      vrf.update(body)
      vrf.update(timestamp)
      vrf.update(routingKey)
      vrf.update(correlationId)

      vrf.verify(signature)
    }

    def verifyCommand(
      signature: Array[Byte],
      body: Array[Byte],
      pubKey: EdDSAPublicKey,
      routingKey: Array[Byte],
      serviceName: Array[Byte]): Boolean = {
      val vrf = new EdDSAEngine(MessageDigest.getInstance(underTest.spec.getHashAlgorithm))
      vrf.initVerify(pubKey)

      vrf.update(body)
      vrf.update(routingKey)
      vrf.update(serviceName)

      vrf.verify(signature)
    }

  }

  "ConsulProvider" should {
    "sign commands" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getPublicKeys).thenReturn(Map[String, EdDSAPublicKey]())

      val routingKey = "system.event"
      val context    = Context.empty
        .withRoutingKey(routingKey)
      val message    = test.objectMapper.writeValueAsBytes(new Message(routingKey, null))

      val result = test.underTest.signCommand(context, message)

      result.get(Headers.Origin).get should equal(test.underTest.serviceName)
      result.get(Headers.Signature) should not be null

      val verified = test.verifyCommand(
        result.get(Headers.Signature).map(sig ⇒ Base64.getUrlDecoder.decode(sig.replace('+', '-').replace('/', '_'))).get,
        message,
        test.keyPair.getPublic.asInstanceOf[EdDSAPublicKey],
        routingKey.getBytes,
        test.underTest.serviceName.getBytes
      )

      verified shouldBe true
    }

    "not resign commands if proxy pass" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getPublicKeys).thenReturn(Map[String, EdDSAPublicKey]())

      val routingKey = "system.event"
      val context    = Context.empty
        .withRoutingKey(routingKey)
        .withValue(Headers.ProxyPass, true)
        .withValue(Headers.Signature, "fakesig")
        .withValue(Headers.Origin, "fakeorigin")

      val message = test.objectMapper.writeValueAsBytes(new Message(routingKey, null))

      val result = test.underTest.signCommand(context, message)

      result.get(Headers.Origin).get should equal("fakeorigin")
      result.get(Headers.Signature).get should equal("fakesig")
    }

    "sign and verify commands" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getPublicKeys).thenReturn(Map[String, EdDSAPublicKey]())

      val routingKey = "system.event"
      val context    = Context.empty
        .withRoutingKey(routingKey)

      val data         = Map("gas" → 6325)
      val message      = new Message(routingKey, data)
      val deliveryBody = test.objectMapper.writeValueAsBytes(message)

      val result = test.underTest.signCommand(context, deliveryBody)

      result.get(Headers.Origin).get should equal(test.underTest.serviceName)
      result.get(Headers.Signature) should not be null

      val verified = test.underTest.verifyCommandSignature(result, deliveryBody)

      verified shouldBe a[Success[_]]
    }

    "not verify commands with the wrong key pair with required true" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getPublicKeys).thenReturn(Map[String, EdDSAPublicKey]())
      when(test.mockDynamicProvider.isRequired).thenReturn(Option.empty)

      val routingKey = "system.event"
      val context    = Context.empty
        .withRoutingKey(routingKey)
      val message    = new Message(routingKey, null)
      val bytes      = test.objectMapper.writeValueAsBytes(message)

      val signed =
        test.signCommand(
          context,
          bytes,
          "services/java-service",
          test.keyPair2.getPrivate.asInstanceOf[EdDSAPrivateKey],
          routingKey.getBytes
        )

      val verified = test.underTest.verifyCommandSignature(signed, bytes)

      verified shouldBe a[Failure[_]]
    }

    "not verify commands with the wrong key pair with required false" in {
      val test = TestSuite(required = false)

      when(test.mockDynamicProvider.getPublicKeys).thenReturn(Map[String, EdDSAPublicKey]())
      when(test.mockDynamicProvider.isRequired).thenReturn(Some(false))

      val routingKey = "system.event"
      val context    = Context.empty
        .withRoutingKey(routingKey)
      val message    = new Message(routingKey, null)
      val bytes      = test.objectMapper.writeValueAsBytes(message)

      val signed =
        test.signCommand(
          context,
          bytes,
          "services/java-service",
          test.keyPair2.getPrivate.asInstanceOf[EdDSAPrivateKey],
          routingKey.getBytes
        )

      val verified = test.underTest.verifyCommandSignature(signed, bytes)

      verified shouldBe a[Success[_]]
    }

    "authorize command when origin is self" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getActions).thenReturn(Map[String, Action]())
      when(test.mockDynamicProvider.getIdentities).thenReturn(Map[String, Identity]())

      val context = Context.empty
        .withValue(Headers.Origin, "services/java-service")
        .withValue(Headers.RoutingKey, "users.delete-user")

      val authorized = test.underTest.authorizeCommand(context)

      authorized shouldBe a[Success[_]]
    }

    "authorize command when origin is authorized by being a memberOf  by specific action" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getActions).thenReturn(Map[String, Action]())
      when(test.mockDynamicProvider.getIdentities).thenReturn(Map[String, Identity]())

      val context = Context.empty
        .withValue(Headers.Origin, "users/joe.bloggs")
        .withValue(Headers.RoutingKey, "users.delete-user")

      val authorized = test.underTest.authorizeCommand(context)

      authorized shouldBe a[Success[_]]
    }

    "authorize command when origin is authorized directly by specific action" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getActions).thenReturn(Map[String, Action]())
      when(test.mockDynamicProvider.getIdentities).thenReturn(Map[String, Identity]())

      val context = Context.empty
        .withValue(Headers.Origin, "users/sarah.dene")
        .withValue(Headers.RoutingKey, "users.create-user")

      val authorized = test.underTest.authorizeCommand(context)

      authorized shouldBe a[Success[_]]
    }

    "authorize command when origin is authorized by action by wildcard" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getActions).thenReturn(Map[String, Action]())
      when(test.mockDynamicProvider.getIdentities).thenReturn(Map[String, Identity]())

      val context = Context.empty
        .withValue(Headers.Origin, "users/sarah.dene")
        .withValue(Headers.RoutingKey, "users.update-user")

      val authorized = test.underTest.authorizeCommand(context)

      authorized shouldBe a[Success[_]]
    }

    "authorize command when unknown origin is authorized by action by wildcard" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getActions).thenReturn(Map[String, Action]())
      when(test.mockDynamicProvider.getIdentities).thenReturn(Map[String, Identity]())

      val context = Context.empty
        .withValue(Headers.Origin, "users/foo.bar")
        .withValue(Headers.RoutingKey, "users.update-user")

      val authorized = test.underTest.authorizeCommand(context)

      authorized shouldBe a[Success[_]]
    }

    "authorize command when origin is authorized by wildcard for action and permission" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getActions).thenReturn(Map[String, Action]())
      when(test.mockDynamicProvider.getIdentities).thenReturn(Map[String, Identity]())

      val context = Context.empty
        .withValue(Headers.Origin, "users/sarah.dene")
        .withValue(Headers.RoutingKey, "users.find-user")

      val authorized = test.underTest.authorizeCommand(context)

      authorized shouldBe a[Success[_]]
    }

    "deny command when origin is not authorized by specific action" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getActions).thenReturn(Map[String, Action]())
      when(test.mockDynamicProvider.getIdentities).thenReturn(Map[String, Identity]())
      when(test.mockDynamicProvider.isRequired).thenReturn(Option.empty)

      val context = Context.empty
        .withValue(Headers.Origin, "users/sarah.dene")
        .withValue(Headers.RoutingKey, "users.delete-user")

      val authorized = test.underTest.authorizeCommand(context)

      authorized shouldBe a[Failure[_]]
    }

    "authorize command when origin is authorized by dynamic provider with a new action" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getActions).thenReturn(Map[String, Action](("users.delete-user", Action(Set("users/sarah.dene")))))
      when(test.mockDynamicProvider.getIdentities).thenReturn(Map[String, Identity]())

      val context = Context.empty
        .withValue(Headers.Origin, "users/sarah.dene")
        .withValue(Headers.RoutingKey, "users.delete-user")

      val authorized = test.underTest.authorizeCommand(context)

      authorized shouldBe a[Success[_]]
    }

    "authorize command when origin is authorized by dynamic provider with a new identity" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getActions).thenReturn(Map[String, Action]())
      when(test.mockDynamicProvider.getIdentities).thenReturn(Map[String, Identity](("users/sarah.dene", Identity(Set("devs")))))

      val context = Context.empty
        .withValue(Headers.Origin, "users/sarah.dene")
        .withValue(Headers.RoutingKey, "users.delete-user")

      val authorized = test.underTest.authorizeCommand(context)

      authorized shouldBe a[Success[_]]
    }

    "authorize command when origin is not authorized by specific action when required is off" in {
      val test = TestSuite(required = false)

      when(test.mockDynamicProvider.getActions).thenReturn(Map[String, Action]())
      when(test.mockDynamicProvider.getIdentities).thenReturn(Map[String, Identity]())
      when(test.mockDynamicProvider.isRequired).thenReturn(Some(false))

      val context = Context.empty
        .withValue(Headers.Origin, "users/sarah.dene")
        .withValue(Headers.RoutingKey, "users.delete-user")

      val authorized = test.underTest.authorizeCommand(context)

      authorized shouldBe a[Success[_]]
    }

    "deny command when origin is not authorized by specific action when required is dynamically on" in {
      val test = TestSuite(required = false)

      when(test.mockDynamicProvider.getActions).thenReturn(Map[String, Action]())
      when(test.mockDynamicProvider.getIdentities).thenReturn(Map[String, Identity]())
      when(test.mockDynamicProvider.isRequired).thenReturn(Some(true))

      val context = Context.empty
        .withValue(Headers.Origin, "users/sarah.dene")
        .withValue(Headers.RoutingKey, "users.delete-user")

      val authorized = test.underTest.authorizeCommand(context)

      authorized shouldBe a[Failure[_]]
    }

    "verifies javascript generated command" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getPublicKeys).thenReturn(Map[String, EdDSAPublicKey]())

      val body    = s"""{"routingKey":"system.event","body":null}""".getBytes
      val context = Context.empty
        .withValue(Headers.Origin, "services/javascript-service")
        .withValue(Headers.Signature, "1fwFNGp6_3cuKNV99hmU6bH1ofR2Y0fMLXCWo66EIC65hI2H6AcAA6wa1qMhT48Jh3lChzKFbBAR46cnU4cFCA")
        .withValue(Headers.RoutingKey, "system.event")

      val verified = test.underTest.verifyCommandSignature(context, body)

      verified shouldBe a[Success[_]]
    }
  }
}
