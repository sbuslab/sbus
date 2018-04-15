sbus
=============

[![Build Status](https://travis-ci.org/sbuslab/sbus.svg?branch=master)](https://travis-ci.org/sbuslab/sbus)

Service Bus for java/scala services with RabbitMQ transport

```scala
sbus.on[GetOrders, List[Order]]("get-orders") { (req, context) ⇒
  Future.successful(List(Order(), Order()))
}

sbus.request[List[Order]]("get-orders", GetOrders(id = 123)) map { orders ⇒
  println(orders)
}
```
