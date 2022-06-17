package com.sbuslab.sbus.auth.providers

import net.i2p.crypto.eddsa.EdDSAPublicKey

import com.sbuslab.sbus.auth.{Action, DynamicProvider, Identity}

case class NoopDynamicProvider() extends DynamicProvider {
  override def getPublicKeys: Map[String, EdDSAPublicKey] = Map.empty

  override def getActions: Map[String, Action] = Map.empty

  override def getIdentities: Map[String, Identity] = Map.empty

  override def isRequired = false
}
