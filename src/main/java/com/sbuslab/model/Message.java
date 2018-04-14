package com.sbuslab.model;

import java.util.Objects;


public class Message {
    private final String routingKey;
    private final Object body;

    @java.beans.ConstructorProperties({"routingKey", "body"})
    public Message(String routingKey, Object body) {
        this.routingKey = routingKey;
        this.body = body;
    }

    public String getRoutingKey() {
        return this.routingKey;
    }

    public Object getBody() {
        return this.body;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Message message = (Message) o;
        return Objects.equals(routingKey, message.routingKey) &&
                Objects.equals(body, message.body);
    }

    @Override
    public int hashCode() {
        return Objects.hash(routingKey, body);
    }

    public String toString() {
        return "Message(routingKey=" + this.getRoutingKey() +
                ", body=" + this.getBody() +
                ")";
    }
}
