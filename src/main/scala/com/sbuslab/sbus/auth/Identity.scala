package com.sbuslab.sbus.auth

case class Identity(groups: Set[String]) {
  def isMember(group: String): Boolean =
    groups.contains(group)

  def isMemberOfAny(others: Set[String]): Boolean =
    groups.intersect(others).nonEmpty
}
