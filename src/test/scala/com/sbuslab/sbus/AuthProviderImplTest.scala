package com.sbuslab.sbus

import scala.language.postfixOps

import java.security.MessageDigest
import java.util.{Base64, UUID}
import scala.collection.JavaConverters._
import scala.util
import scala.util.{Failure, Success, Try}

import com.fasterxml.jackson.databind.ObjectMapper
import com.typesafe.config.{ConfigFactory, ConfigValueFactory}
import net.i2p.crypto.eddsa.{EdDSAEngine, EdDSAPrivateKey, EdDSAPublicKey, KeyPairGenerator, Utils}
import org.hibernate.validator.internal.util.stereotypes.Immutable
import org.junit.runner.RunWith
import org.mockito.Mockito.when
import org.scalatest.{AsyncWordSpec, Matchers}
import org.scalatest.junit.JUnitRunner
import org.scalatest.mockito.MockitoSugar

import com.sbuslab.sbus.auth.{Action, AuthProviderImpl, Identity}
import com.sbuslab.sbus.auth.providers.ConsulAuthConfigProvider

@RunWith(classOf[JUnitRunner])
class AuthProviderImplTest extends AsyncWordSpec with Matchers with MockitoSugar {

  def defaultConfig =
    s"""{
       | enabled = true
       |
       | name = "services/my-service"
       |
       | rbac {
       |   identities = {
       |     "users/joe.bloggs": [
       |       "devs"
       |     ]
       |     "users/sarah.dene": [
       |       "support"
       |     ]
       |     "services/other-service": [
       |       "services"
       |     ]
       |   }
       |   actions = {
       |     "*": ["*"]
       |     "users.create-user": ["devs", "services", "users/sarah.dene"]
       |     "users.delete-user": ["devs"]
       |     "users.update-user": ["*"]
       |   }
       | }}""".stripMargin

  case class TestSuite(config: String = defaultConfig, required: Boolean = true) {
    val mockDynamicProvider = mock[ConsulAuthConfigProvider]

    val keyPair = new KeyPairGenerator().generateKeyPair
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
            ("services/my-service", Utils.bytesToHex(keyPair.getPublic.asInstanceOf[EdDSAPublicKey].getAbyte)),
            ("services/other-service", Utils.bytesToHex(keyPair2.getPublic.asInstanceOf[EdDSAPublicKey].getAbyte)),
            ("services/javascript-service", "970c32b647a1055065e2b5d50398a4dc9c3c71c077ba27dad8fb739a3f3ded45"),
            ("services/cli-service", "59842ab5f5d5b515126eb86a799d9fa4547b1b42209ca7ff96a189d4bd2f3130")
          ).asJava)
        )
        .resolve(),
      new ObjectMapper(),
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
        .withValue(Headers.MessageOrigin, serviceName)
        .withValue(Headers.MessageSignature, Base64.getUrlEncoder.encodeToString(signer.sign()))
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
      val context = Context.empty
        .withRoutingKey(routingKey)

      val result = test.underTest.signCommand(context, Option.empty)

      result.get(Headers.Origin).get should equal(test.underTest.serviceName)
      result.get(Headers.Signature) should not be null

      val verified = test.verifyCommand(
        result.get(Headers.Signature).map(sig ⇒ Base64.getUrlDecoder.decode(sig.replace('+', '-').replace('/', '_'))).get,
        Array.empty,
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
      val context = Context.empty
        .withRoutingKey(routingKey)
        .withValue(Headers.ProxyPass, true)
        .withValue(Headers.Signature, "fakesig")
        .withValue(Headers.Origin, "fakeorigin")

      val result = test.underTest.signCommand(context, Option.empty)

      result.get(Headers.Origin).get should equal("fakeorigin")
      result.get(Headers.Signature).get should equal("fakesig")
    }

    "sign and verify commands" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getPublicKeys).thenReturn(Map[String, EdDSAPublicKey]())

      val context = Context.empty
        .withRoutingKey("system.event")

      val result = test.underTest.signCommand(context, Option.empty)

      result.get(Headers.Origin).get should equal(test.underTest.serviceName)
      result.get(Headers.Signature) should not be null

      val verified = test.underTest.verifyCommandSignature(result, Option.empty)

      verified shouldBe a[Success[_]]
    }

    "not verify commands with the wrong key pair with required true" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getPublicKeys).thenReturn(Map[String, EdDSAPublicKey]())

      val routingKey = "system.event"
      val context = Context.empty
        .withRoutingKey(routingKey)

      val signed =
        test.signCommand(
          context,
          Array.empty,
          "services/my-service",
          test.keyPair2.getPrivate.asInstanceOf[EdDSAPrivateKey],
          routingKey.getBytes
        )

      val verified = test.underTest.verifyCommandSignature(signed, Option.empty)

      verified shouldBe a[Failure[_]]
    }

    "not verify commands with the wrong key pair with required false" in {
      val test = TestSuite(required = false)

      when(test.mockDynamicProvider.getPublicKeys).thenReturn(Map[String, EdDSAPublicKey]())
      when(test.mockDynamicProvider.isRequired).thenReturn(false)

      val body = "{}".getBytes
      val routingKey = "system.event"
      val context = Context.empty
        .withRoutingKey(routingKey)

      val signed =
        test.signCommand(
          context,
          Array.empty,
          "services/my-service",
          test.keyPair2.getPrivate.asInstanceOf[EdDSAPrivateKey],
          routingKey.getBytes
        )

      val verified = test.underTest.verifyCommandSignature(signed, Option.empty)

      verified shouldBe a[Success[_]]
    }

    "sign messages" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getPublicKeys).thenReturn(Map[String, EdDSAPublicKey]())

      val routingKey = "route.main"
      val correlationId = UUID.randomUUID.toString
      val body = "{}".getBytes
      val timestamp = System.currentTimeMillis().toString
      val context = Context.empty
        .withValue(Headers.Timestamp, timestamp)
        .withValue(Headers.RoutingKey, routingKey)
        .withValue(Headers.CorrelationId, correlationId)

      val result = test.underTest.signMessageRequest(context, body)

      result.get(Headers.MessageOrigin).get should equal(test.underTest.serviceName)
      result.get(Headers.MessageSignature) should not be null

      val verified = test.verifyMessageSignature(
        result.get(Headers.MessageSignature).map(sig ⇒ Base64.getUrlDecoder.decode(sig.replace('+', '-').replace('/', '_'))).get,
        body,
        test.keyPair.getPublic.asInstanceOf[EdDSAPublicKey],
        timestamp.getBytes,
        routingKey.getBytes,
        correlationId.getBytes,
      )

      verified shouldBe true
    }

    "sign and verify messages" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getPublicKeys).thenReturn(Map[String, EdDSAPublicKey]())

      val body = "{}".getBytes
      val timestamp = System.currentTimeMillis().toString
      val context = Context.empty
        .withValue(Headers.Timestamp, timestamp)

      val result = test.underTest.signMessageRequest(context, body)

      result.get(Headers.MessageOrigin).get should equal(test.underTest.serviceName)
      result.get(Headers.MessageSignature) should not be null

      val verified = test.underTest.verifyMessageSignature(result, body)

      verified shouldBe a[Success[_]]
    }

    "verify messages with the right key pair" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getPublicKeys).thenReturn(Map[String, EdDSAPublicKey]())

      val body = "{}".getBytes
      val timestamp = System.currentTimeMillis().toString
      val context = Context.empty
        .withValue(Headers.Timestamp, timestamp)

      val signed =
        test.signMessageRequest(
          context,
          body,
          "services/other-service",
          test.keyPair2.getPrivate.asInstanceOf[EdDSAPrivateKey],
          timestamp.getBytes
        )

      val verified = test.underTest.verifyMessageSignature(signed, body)

      verified shouldBe a[Success[_]]
    }

    "not verify messages with the wrong key pair with required true" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getPublicKeys).thenReturn(Map[String, EdDSAPublicKey]())

      val body = "{}".getBytes
      val timestamp = System.currentTimeMillis().toString

      val context = Context.empty
        .withValue(Headers.Timestamp, timestamp)

      val signed =
        test.signMessageRequest(
          context,
          body,
          "services/my-service",
          test.keyPair2.getPrivate.asInstanceOf[EdDSAPrivateKey],
          timestamp.getBytes
        )

      val verified = test.underTest.verifyMessageSignature(signed, body)

      verified shouldBe a[Failure[_]]
    }

    "verify messages with the wrong key pair with required false" in {
      val test = TestSuite(required = false)

      when(test.mockDynamicProvider.getPublicKeys).thenReturn(Map[String, EdDSAPublicKey]())
      when(test.mockDynamicProvider.isRequired).thenReturn(false)

      val body = "{}".getBytes
      val timestamp = System.currentTimeMillis().toString

      val context = Context.empty
        .withValue(Headers.Timestamp, timestamp)

      val signed =
        test.signMessageRequest(
          context,
          body,
          "services/my-service",
          test.keyPair2.getPrivate.asInstanceOf[EdDSAPrivateKey],
          timestamp.getBytes
        )

      val verified = test.underTest.verifyMessageSignature(signed, body)

      verified shouldBe a[Success[_]]
    }

    "not verify messages with no key pair with required true" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getPublicKeys).thenReturn(Map[String, EdDSAPublicKey]())

      val body = "{}".getBytes
      val timestamp = System.currentTimeMillis().toString

      val context = Context.empty
        .withValue(Headers.Timestamp, timestamp)

      val signed =
        test.signMessageRequest(
          context,
          body,
          "services/random-service",
          test.keyPair2.getPrivate.asInstanceOf[EdDSAPrivateKey],
          timestamp.getBytes
        )

      val verified = test.underTest.verifyMessageSignature(signed, body)

      verified shouldBe a[Failure[_]]
    }

    "verify messages with no key pair with required false" in {
      val test = TestSuite(required = false)

      when(test.mockDynamicProvider.getPublicKeys).thenReturn(Map[String, EdDSAPublicKey]())
      when(test.mockDynamicProvider.isRequired).thenReturn(false)

      val body = "{}".getBytes
      val timestamp = System.currentTimeMillis().toString

      val context = Context.empty
        .withValue(Headers.Timestamp, timestamp)

      val signed =
        test.signMessageRequest(
          context,
          body,
          "services/random-service",
          test.keyPair2.getPrivate.asInstanceOf[EdDSAPrivateKey],
          timestamp.getBytes
        )

      val verified = test.underTest.verifyMessageSignature(signed, body)

      verified shouldBe a[Success[_]]
    }

    "not verify messages with no origin with required true" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getPublicKeys).thenReturn(Map[String, EdDSAPublicKey]())

      val body = "{}".getBytes
      val timestamp = System.currentTimeMillis().toString

      val context = Context.empty
        .withValue(Headers.Timestamp, timestamp)

      val signed = test.signMessageRequest(context, body, null, test.keyPair2.getPrivate.asInstanceOf[EdDSAPrivateKey], timestamp.getBytes)

      val verified = test.underTest.verifyMessageSignature(signed, body)

      verified shouldBe a[Failure[_]]
    }

    "verify messages with no origin with required false" in {
      val test = TestSuite(required = false)

      when(test.mockDynamicProvider.getPublicKeys).thenReturn(Map[String, EdDSAPublicKey]())
      when(test.mockDynamicProvider.isRequired).thenReturn(false)

      val body = "{}".getBytes
      val timestamp = System.currentTimeMillis().toString

      val context = Context.empty
        .withValue(Headers.Timestamp, timestamp)

      val signed = test.signMessageRequest(context, body, null, test.keyPair2.getPrivate.asInstanceOf[EdDSAPrivateKey], timestamp.getBytes)

      val verified = test.underTest.verifyMessageSignature(signed, body)

      verified shouldBe a[Success[_]]
    }

    "not verify messages with no signature with required true" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getPublicKeys).thenReturn(Map[String, EdDSAPublicKey]())

      val body = "{}".getBytes
      val context = Context.empty
        .withValue(Headers.MessageOrigin, "services/other-service")

      val verified = test.underTest.verifyMessageSignature(context, body)

      verified shouldBe a[Failure[_]]
    }

    "verify messages with no signature with required false" in {
      val test = TestSuite(required = false)

      when(test.mockDynamicProvider.getPublicKeys).thenReturn(Map[String, EdDSAPublicKey]())
      when(test.mockDynamicProvider.isRequired).thenReturn(false)

      val body = "{}".getBytes
      val context = Context.empty
        .withValue(Headers.MessageOrigin, "services/other-service")

      val verified = test.underTest.verifyMessageSignature(context, body)

      verified shouldBe a[Success[_]]
    }

    "verify messages with no signature with required false by dynamic is true" in {
      val test = TestSuite(required = false)

      when(test.mockDynamicProvider.getPublicKeys).thenReturn(Map[String, EdDSAPublicKey]())
      when(test.mockDynamicProvider.isRequired).thenReturn(true)

      val body = "{}".getBytes
      val context = Context.empty
        .withValue(Headers.MessageOrigin, "services/other-service")

      val verified = test.underTest.verifyMessageSignature(context, body)

      verified shouldBe a[Failure[_]]
    }

    "authorize messages when origin is self" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getActions).thenReturn(Map[String, Action]())
      when(test.mockDynamicProvider.getIdentities).thenReturn(Map[String, Identity]())

      val context = Context.empty
        .withValue(Headers.Origin, "services/my-service")
        .withValue(Headers.RoutingKey, "users.delete-user")

      val authorized = test.underTest.authorizeCommand(context)

      authorized shouldBe a[Success[_]]
    }

    "authorize messages when origin is authorized by being a memberOf  by specific action" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getActions).thenReturn(Map[String, Action]())
      when(test.mockDynamicProvider.getIdentities).thenReturn(Map[String, Identity]())

      val context = Context.empty
        .withValue(Headers.Origin, "users/joe.bloggs")
        .withValue(Headers.RoutingKey, "users.delete-user")

      val authorized = test.underTest.authorizeCommand(context)

      authorized shouldBe a[Success[_]]
    }

    "authorize messages when origin is authorized directly by specific action" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getActions).thenReturn(Map[String, Action]())
      when(test.mockDynamicProvider.getIdentities).thenReturn(Map[String, Identity]())

      val context = Context.empty
        .withValue(Headers.Origin, "users/sarah.dene")
        .withValue(Headers.RoutingKey, "users.create-user")

      val authorized = test.underTest.authorizeCommand(context)

      authorized shouldBe a[Success[_]]
    }

    "authorize messages when origin is authorized by action by wildcard" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getActions).thenReturn(Map[String, Action]())
      when(test.mockDynamicProvider.getIdentities).thenReturn(Map[String, Identity]())

      val context = Context.empty
        .withValue(Headers.Origin, "users/sarah.dene")
        .withValue(Headers.RoutingKey, "users.update-user")

      val authorized = test.underTest.authorizeCommand(context)

      authorized shouldBe a[Success[_]]
    }

    "authorize messages when unknown origin is authorized by action by wildcard" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getActions).thenReturn(Map[String, Action]())
      when(test.mockDynamicProvider.getIdentities).thenReturn(Map[String, Identity]())

      val context = Context.empty
        .withValue(Headers.Origin, "users/foo.bar")
        .withValue(Headers.RoutingKey, "users.update-user")

      val authorized = test.underTest.authorizeCommand(context)

      authorized shouldBe a[Success[_]]
    }

    "authorize messages when origin is authorized by wildcard for action and permission" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getActions).thenReturn(Map[String, Action]())
      when(test.mockDynamicProvider.getIdentities).thenReturn(Map[String, Identity]())

      val context = Context.empty
        .withValue(Headers.Origin, "users/sarah.dene")
        .withValue(Headers.RoutingKey, "users.find-user")

      val authorized = test.underTest.authorizeCommand(context)

      authorized shouldBe a[Success[_]]
    }

    "deny messages when origin is not authorized by specific action" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getActions).thenReturn(Map[String, Action]())
      when(test.mockDynamicProvider.getIdentities).thenReturn(Map[String, Identity]())

      val context = Context.empty
        .withValue(Headers.Origin, "users/sarah.dene")
        .withValue(Headers.RoutingKey, "users.delete-user")

      val authorized = test.underTest.authorizeCommand(context)

      authorized shouldBe a[Failure[_]]
    }

    "authorize messages when origin is authorized by dynamic provider with a new action" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getActions).thenReturn(Map[String, Action](("users.delete-user", Action(Set("users/sarah.dene")))))
      when(test.mockDynamicProvider.getIdentities).thenReturn(Map[String, Identity]())

      val context = Context.empty
        .withValue(Headers.Origin, "users/sarah.dene")
        .withValue(Headers.RoutingKey, "users.delete-user")

      val authorized = test.underTest.authorizeCommand(context)

      authorized shouldBe a[Success[_]]
    }

    "authorize messages when origin is authorized by dynamic provider with a new identity" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getActions).thenReturn(Map[String, Action]())
      when(test.mockDynamicProvider.getIdentities).thenReturn(Map[String, Identity](("users/sarah.dene", Identity(Set("devs")))))

      val context = Context.empty
        .withValue(Headers.Origin, "users/sarah.dene")
        .withValue(Headers.RoutingKey, "users.delete-user")

      val authorized = test.underTest.authorizeCommand(context)

      authorized shouldBe a[Success[_]]
    }

    "authorize messages when origin is not authorized by specific action when required is off" in {
      val test = TestSuite(required = false)

      when(test.mockDynamicProvider.getActions).thenReturn(Map[String, Action]())
      when(test.mockDynamicProvider.getIdentities).thenReturn(Map[String, Identity]())
      when(test.mockDynamicProvider.isRequired).thenReturn(false)

      val context = Context.empty
        .withValue(Headers.Origin, "users/sarah.dene")
        .withValue(Headers.RoutingKey, "users.delete-user")

      val authorized = test.underTest.authorizeCommand(context)

      authorized shouldBe a[Success[_]]
    }

    "deny messages when origin is not authorized by specific action when required is dynamically on" in {
      val test = TestSuite(required = false)

      when(test.mockDynamicProvider.getActions).thenReturn(Map[String, Action]())
      when(test.mockDynamicProvider.getIdentities).thenReturn(Map[String, Identity]())
      when(test.mockDynamicProvider.isRequired).thenReturn(true)

      val context = Context.empty
        .withValue(Headers.Origin, "users/sarah.dene")
        .withValue(Headers.RoutingKey, "users.delete-user")

      val authorized = test.underTest.authorizeCommand(context)

      authorized shouldBe a[Failure[_]]
    }

    "verifies javascript generated signatures" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getPublicKeys).thenReturn(Map[String, EdDSAPublicKey]())

      val body = "{}".getBytes
      val timestamp = "1655829081471"
      val context = Context.empty
        .withValue(Headers.MessageOrigin, "services/javascript-service")
        .withValue(Headers.MessageSignature, "tC2YsPMhL0WnHkwDdGDjuOdku3ACIBXfZwyUXhLCiIDt50HqzB4cyOkZtlwvF2ZD0IMYnAWszzv5--O1C5LLCQ")
        .withValue(Headers.Timestamp, timestamp)

      val verified = test.underTest.verifyMessageSignature(context, body)

      verified shouldBe a[Success[_]]
    }

    "verifies cli generated signatures" in {
      val test = TestSuite()

      when(test.mockDynamicProvider.getPublicKeys).thenReturn(Map[String, EdDSAPublicKey]())

      val body = "{\"body\":{}}".getBytes
      val timestamp = "1655826239963"
      val origin = "services/cli-service"
      val context = Context.empty
        .withValue(Headers.MessageOrigin, origin)
        .withValue(Headers.MessageSignature, "N5Q31CHmWtZ4YDhXxJlTU_-s_yb0yIBEn3R5hB69syta6XC8n__kSrXabQ7Jdf3YMpQlzQAWZwDnuDdrKmM8AQ==")
        .withValue(Headers.Timestamp, timestamp)

      val verified = test.underTest.verifyMessageSignature(context, body)

      verified shouldBe a[Success[_]]
    }
  }
}
