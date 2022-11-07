package com.sbuslab.sbus.auth.providers

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.WireMock
import com.github.tomakehurst.wiremock.client.WireMock._
import com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig
import com.github.tomakehurst.wiremock.http.Fault
import com.typesafe.config.ConfigFactory
import net.i2p.crypto.eddsa.{EdDSAPublicKey, KeyPairGenerator}
import org.apache.commons.codec.binary.{Base64, Hex}
import org.junit.runner.RunWith
import org.scalatest.{AsyncWordSpec, BeforeAndAfterAll, BeforeAndAfterEach, Matchers}
import org.scalatest.junit.JUnitRunner

import com.sbuslab.sbus.auth.{Action, Identity}

@RunWith(classOf[JUnitRunner])
class ConsulAuthConfigProviderTest extends AsyncWordSpec with Matchers with BeforeAndAfterEach with BeforeAndAfterAll {

  val Host   = "localhost"
  val Port   = 4893
  val server = new WireMockServer(wireMockConfig().port(Port))

  override def beforeAll(): Unit = {
    server.start()
    WireMock.configureFor(Host, Port)
  }

  override def afterEach(): Unit =
    server.resetAll()

  override def afterAll(): Unit =
    server.stop()

  def defaultConfig =
    s"""{
          | base-url = "http://$Host:$Port/"
          | public-keys-path = "services/keys/public"
          | config-path = "services/auth/config/test-service"
          | identities-path = "rbac/identities"
          | cache-duration = "1 second"
          | cache-failure-required = false
          |}""".stripMargin

  case class TestSuite(config: String = defaultConfig) {

    val underTest = new ConsulAuthConfigProvider(
      ConfigFactory
        .parseString(config)
        .resolve()
    )

    server.resetAll()
  }

  "ConsulProvider" should {

    "successfully fetch actions" in {
      val test = TestSuite()

      stubFor(get(urlPathEqualTo(s"/${test.underTest.configPath}")).willReturn(
        okJson(
          "{\"actions\": {\"*\": {\"permissions\": [\"devs\"]}, \"webhooks.create-subscription\": {\"permissions\": [\"users/joe.bloggs\"]}}}"
        )
      ))

      val actions = test.underTest.getActions

      actions should contain key "*"
      actions should contain key "webhooks.create-subscription"
      actions should contain value Action(Set("devs"))
      actions should contain value Action(Set("users/joe.bloggs"))
    }

    "successfully fetch cached actions" in {
      val test = TestSuite()

      stubFor(get(urlPathEqualTo(s"/${test.underTest.configPath}")).willReturn(
        okJson(
          "{\"actions\": {\"*\": {\"permissions\": [\"devs\"]}, \"webhooks.create-subscription\": {\"permissions\": [\"users/joe.bloggs\"]}}}"
        )
      ))

      val actions = test.underTest.getActions

      actions should contain key "*"
      actions should contain key "webhooks.create-subscription"
      actions should contain value Action(Set("devs"))
      actions should contain value Action(Set("users/joe.bloggs"))

      stubFor(get(urlPathEqualTo(s"/${test.underTest.configPath}")).willReturn(
        okJson("{\"actions\": {\"*\": {\"permissions\": [\"devs\"]}}}")
      ))

      val actionsAfter = test.underTest.getActions

      verify(WireMock.exactly(1), getRequestedFor(urlPathEqualTo(s"/${test.underTest.configPath}")))

      actionsAfter should contain key "*"
      actionsAfter should contain key "webhooks.create-subscription"
      actionsAfter should contain value Action(Set("devs"))
      actionsAfter should contain value Action(Set("users/joe.bloggs"))
    }

    "successfully refresh cached actions" in {
      val test = TestSuite()

      stubFor(get(urlPathEqualTo(s"/${test.underTest.configPath}")).willReturn(
        okJson(
          "{\"actions\": {\"*\": {\"permissions\": [\"devs\"]}, \"webhooks.create-subscription\": {\"permissions\": [\"users/joe.bloggs\"]}}}"
        )
      ))

      val actions = test.underTest.getActions

      actions should contain key "*"
      actions should contain key "webhooks.create-subscription"
      actions should contain value Action(Set("devs"))
      actions should contain value Action(Set("users/joe.bloggs"))

      Thread.sleep(1000)

      stubFor(get(urlPathEqualTo(s"/${test.underTest.configPath}")).willReturn(
        okJson("{\"actions\": {\"*\": {\"permissions\": [\"devs\"]}}}")
      ))

      val actionsAfter = test.underTest.getActions

      verify(WireMock.exactly(2), getRequestedFor(urlPathEqualTo(s"/${test.underTest.configPath}")))

      actionsAfter should contain key "*"
      actionsAfter should not(contain key "webhooks.create-subscription")
      actionsAfter should contain value Action(Set("devs"))
      actionsAfter should not(contain value Action(Set("users/joe.bloggs")))
    }

    "successfully default actions" in {
      val test = TestSuite()

      stubFor(get(urlPathEqualTo(s"/${test.underTest.configPath}")).willReturn(
        okJson("{}")
      ))

      val actions = test.underTest.getActions

      actions should be(empty)
    }

    "successfully default actions when error in consul" in {
      val test = TestSuite()

      stubFor(get(urlPathEqualTo(s"/${test.underTest.configPath}")).willReturn(
        serverError()
      ))

      val actions = test.underTest.getActions

      actions should be(empty)

      stubFor(get(urlPathEqualTo(s"/${test.underTest.configPath}")).willReturn(
        okJson(
          "{\"actions\": {\"*\": {\"permissions\": [\"devs\"]}, \"webhooks.create-subscription\": {\"permissions\": [\"users/joe.bloggs\"]}}}"
        )
      ))

      val actionsAfter = test.underTest.getActions

      actionsAfter should contain key "*"
      actionsAfter should contain key "webhooks.create-subscription"
      actionsAfter should contain value Action(Set("devs"))
      actionsAfter should contain value Action(Set("users/joe.bloggs"))
    }

    "successfully default actions when no network route" in {
      val test = TestSuite()

      val actions = test.underTest.getActions

      actions should be(empty)
    }

    "successfully fetch identities" in {
      val test = TestSuite()

      stubFor(get(urlPathEqualTo(s"/${test.underTest.identitiesPath}")).willReturn(
        okJson(
          "[{\"LockIndex\":0,\"Key\":\"rbac/identities/users/joe.bloggs\",\"Flags\":0,\"Value\":\"eyAiZ3JvdXBzIjogWyJkZXZzIl0gfQ\",\"CreateIndex\":142363424,\"ModifyIndex\":142363424}]"
        )
      ))

      val identities = test.underTest.getIdentities

      identities should contain key "users/joe.bloggs"
      identities should contain value Identity(Set("devs"))
    }

    "successfully fetch cached identities" in {
      val test = TestSuite()

      stubFor(get(urlPathEqualTo(s"/${test.underTest.identitiesPath}")).willReturn(
        okJson(
          "[{\"LockIndex\":0,\"Key\":\"rbac/identities/users/joe.bloggs\",\"Flags\":0,\"Value\":\"eyAiZ3JvdXBzIjogWyJkZXZzIl0gfQ\",\"CreateIndex\":142363424,\"ModifyIndex\":142363424}]"
        )
      ))

      val identities = test.underTest.getIdentities

      identities should contain key "users/joe.bloggs"
      identities should contain value Identity(Set("devs"))

      stubFor(get(urlPathEqualTo(s"/${test.underTest.identitiesPath}")).willReturn(
        okJson(
          "[]"
        )
      ))

      val identitiesAfter = test.underTest.getIdentities

      verify(WireMock.exactly(1), getRequestedFor(urlPathEqualTo(s"/${test.underTest.identitiesPath}")))

      identitiesAfter should contain key "users/joe.bloggs"
      identitiesAfter should contain value Identity(Set("devs"))
    }

    "successfully refresh cached identities" in {
      val test = TestSuite()

      stubFor(get(urlPathEqualTo(s"/${test.underTest.identitiesPath}")).willReturn(
        okJson(
          "[{\"LockIndex\":0,\"Key\":\"rbac/identities/users/joe.bloggs\",\"Flags\":0,\"Value\":\"eyAiZ3JvdXBzIjogWyJkZXZzIl0gfQ\",\"CreateIndex\":142363424,\"ModifyIndex\":142363424}]"
        )
      ))

      val identities = test.underTest.getIdentities

      identities should contain key "users/joe.bloggs"
      identities should contain value Identity(Set("devs"))

      Thread.sleep(1000)

      stubFor(get(urlPathEqualTo(s"/${test.underTest.identitiesPath}")).willReturn(
        okJson(
          "[]"
        )
      ))

      val identitiesAfter = test.underTest.getIdentities

      verify(WireMock.exactly(2), getRequestedFor(urlPathEqualTo(s"/${test.underTest.identitiesPath}")))

      identitiesAfter should not(contain key "users/joe.bloggs")
      identitiesAfter should not(contain value Identity(Set("devs")))
    }

    "successfully default identities when error in consul" in {
      val test = TestSuite()

      stubFor(get(urlPathEqualTo(s"/${test.underTest.identitiesPath}")).willReturn(
        serverError()
      ))

      val actions = test.underTest.getIdentities

      actions should be(empty)
    }

    "successfully default identities when error in consul and recovers" in {
      val test = TestSuite()

      stubFor(get(urlPathEqualTo(s"/${test.underTest.identitiesPath}")).willReturn(
        serverError()
      ))

      val actions = test.underTest.getIdentities

      actions should be(empty)

      stubFor(get(urlPathEqualTo(s"/${test.underTest.identitiesPath}")).willReturn(
        okJson(
          "[{\"LockIndex\":0,\"Key\":\"rbac/identities/users/joe.bloggs\",\"Flags\":0,\"Value\":\"eyAiZ3JvdXBzIjogWyJkZXZzIl0gfQ\",\"CreateIndex\":142363424,\"ModifyIndex\":142363424}]"
        )
      ))

      val identitiesAfter = test.underTest.getIdentities

      identitiesAfter should contain key "users/joe.bloggs"
      identitiesAfter should contain value Identity(Set("devs"))
    }

    "successfully fetch required config" in {
      val test = TestSuite()

      stubFor(get(urlPathEqualTo(s"/${test.underTest.configPath}")).willReturn(
        okJson("{\"required\": false}")
      ))

      val required = test.underTest.isRequired

      required should equal(Some(false))
    }

    "successfully default required config when error in consul and recovers" in {
      val test = TestSuite()

      stubFor(get(urlPathEqualTo(s"/${test.underTest.configPath}")).willReturn(
        aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)
      ))

      val required = test.underTest.isRequired

      required should equal(Some(false))

      stubFor(get(urlPathEqualTo(s"/${test.underTest.configPath}")).willReturn(
        okJson("{\"required\": true}")
      ))

      val afterRequired = test.underTest.isRequired

      afterRequired should equal(Some(true))
    }

    "successfully fetch cached required config" in {
      val test = TestSuite()

      stubFor(get(urlPathEqualTo(s"/${test.underTest.configPath}")).willReturn(
        okJson("{\"required\": false}")
      ))

      val required = test.underTest.isRequired

      required should equal(Some(false))

      stubFor(get(urlPathEqualTo(s"/${test.underTest.configPath}")).willReturn(
        okJson("{\"required\": true}")
      ))

      val requiredAfter = test.underTest.isRequired

      verify(WireMock.exactly(1), getRequestedFor(urlPathEqualTo(s"/${test.underTest.configPath}")))

      requiredAfter should equal(Some(false))
    }

    "successfully refresh cached required config" in {
      val test = TestSuite()

      stubFor(get(urlPathEqualTo(s"/${test.underTest.configPath}")).willReturn(
        okJson("{\"required\": false}")
      ))

      val required = test.underTest.isRequired

      required should equal(Some(false))

      Thread.sleep(1000)

      stubFor(get(urlPathEqualTo(s"/${test.underTest.configPath}")).willReturn(
        okJson("{\"required\": true}")
      ))

      val requiredAfter = test.underTest.isRequired

      verify(WireMock.exactly(2), getRequestedFor(urlPathEqualTo(s"/${test.underTest.configPath}")))

      requiredAfter should equal(Some(true))
    }

    "successfully default required config" in {
      val test = TestSuite()

      stubFor(get(urlPathEqualTo(s"/${test.underTest.configPath}")).willReturn(
        okJson("{}")
      ))

      val required = test.underTest.isRequired

      required should equal(None)
    }

    "successfully fetch public keys" in {
      val test = TestSuite()

      val keyPairGenerator = new KeyPairGenerator()

      val pair             = keyPairGenerator.generateKeyPair
      val publicKeyBytes   = pair.getPublic.asInstanceOf[EdDSAPublicKey].getAbyte
      val publicKeyEncoded = Base64.encodeBase64String(s"""{ "publicKey": "${Hex.encodeHexString(publicKeyBytes)}" }""".getBytes)

      val responseBody =
        s"""[{"LockIndex":0,"Key":"services/keys/public/users/joe.bloggs","Flags":0,"Value":"$publicKeyEncoded","CreateIndex":31349461,"ModifyIndex":31349461}]"""

      stubFor(get(urlPathEqualTo(s"/${test.underTest.publicKeysPath}")).willReturn(
        okJson(
          responseBody
        )
      ))

      val publicKeys = test.underTest.getPublicKeys

      publicKeys should contain key "users/joe.bloggs"
      publicKeys should contain value pair.getPublic.asInstanceOf[EdDSAPublicKey]
    }

    "successfully fetch cached public keys" in {
      val test = TestSuite()

      val keyPairGenerator = new KeyPairGenerator()

      val pair             = keyPairGenerator.generateKeyPair
      val publicKeyBytes   = pair.getPublic.asInstanceOf[EdDSAPublicKey].getAbyte
      val publicKeyEncoded = Base64.encodeBase64String(s"""{ "publicKey": "${Hex.encodeHexString(publicKeyBytes)}" }""".getBytes)

      val responseBody =
        s"""[{"LockIndex":0,"Key":"services/keys/public/users/joe.bloggs","Flags":0,"Value":"$publicKeyEncoded","CreateIndex":31349461,"ModifyIndex":31349461}]"""

      stubFor(get(urlPathEqualTo(s"/${test.underTest.publicKeysPath}")).willReturn(
        okJson(
          responseBody
        )
      ))

      val publicKeys = test.underTest.getPublicKeys

      publicKeys should contain key "users/joe.bloggs"
      publicKeys should contain value pair.getPublic.asInstanceOf[EdDSAPublicKey]

      stubFor(get(urlPathEqualTo(s"/${test.underTest.publicKeysPath}")).willReturn(
        okJson(
          "[]"
        )
      ))

      val publicKeysAfter = test.underTest.getPublicKeys

      verify(WireMock.exactly(1), getRequestedFor(urlPathEqualTo(s"/${test.underTest.publicKeysPath}")))

      publicKeysAfter should contain key "users/joe.bloggs"
      publicKeysAfter should contain value pair.getPublic.asInstanceOf[EdDSAPublicKey]
    }

    "successfully refresh cached public keys" in {
      val test = TestSuite()

      val keyPairGenerator = new KeyPairGenerator()

      val pair             = keyPairGenerator.generateKeyPair
      val publicKeyBytes   = pair.getPublic.asInstanceOf[EdDSAPublicKey].getAbyte
      val publicKeyEncoded = Base64.encodeBase64String(s"""{ "publicKey": "${Hex.encodeHexString(publicKeyBytes)}" }""".getBytes)

      val responseBody =
        s"""[{"LockIndex":0,"Key":"services/keys/public/users/joe.bloggs","Flags":0,"Value":"$publicKeyEncoded","CreateIndex":31349461,"ModifyIndex":31349461}]"""

      stubFor(get(urlPathEqualTo(s"/${test.underTest.publicKeysPath}")).willReturn(
        okJson(
          responseBody
        )
      ))

      val publicKeys = test.underTest.getPublicKeys

      publicKeys should contain key "users/joe.bloggs"
      publicKeys should contain value pair.getPublic.asInstanceOf[EdDSAPublicKey]

      Thread.sleep(1000)

      stubFor(get(urlPathEqualTo(s"/${test.underTest.publicKeysPath}")).willReturn(
        okJson(
          "[]"
        )
      ))

      val publicKeysAfter = test.underTest.getPublicKeys

      verify(WireMock.exactly(2), getRequestedFor(urlPathEqualTo(s"/${test.underTest.publicKeysPath}")))

      publicKeysAfter should not(contain key "users/joe.bloggs")
    }

  }

}
