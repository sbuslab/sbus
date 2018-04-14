package com.sbuslab.model;

import java.util.Objects;


public class Response {
    private final int status;
    private final Object body;

    @java.beans.ConstructorProperties({"status", "body"})
    public Response(int status, Object body) {
        this.status = status;
        this.body = body;
    }

    public int getStatus() {
        return this.status;
    }

    public Object getBody() {
        return this.body;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Response response = (Response) o;
        return status == response.status &&
                Objects.equals(body, response.body);
    }

    @Override
    public int hashCode() {

        return Objects.hash(status, body);
    }

    public String toString() {
        return "Response(status=" + this.getStatus() + ", body=" + this.getBody() + ")";
    }
}
