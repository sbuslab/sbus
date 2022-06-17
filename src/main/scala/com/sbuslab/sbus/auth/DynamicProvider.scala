package com.sbuslab.sbus.auth

import net.i2p.crypto.eddsa.EdDSAPublicKey

trait DynamicProvider {
  def getPublicKeys: Map[String, EdDSAPublicKey]
  def getActions: Map[String, Action]
  def getIdentities: Map[String, Identity]
  def isRequired: Boolean
}
