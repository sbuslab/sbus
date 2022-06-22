package com.sbuslab.sbus.auth

case class Identity(memberOf: Set[String]) {
  def isMember(group: String): Boolean =
    memberOf.contains(group)

  def isMemberOfAny(groups: Set[String]): Boolean =
    memberOf.intersect(groups).nonEmpty
}
