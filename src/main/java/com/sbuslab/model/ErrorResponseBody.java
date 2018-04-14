package com.sbuslab.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;
import java.util.Objects;


public class ErrorResponseBody {

    private final String message;

    private final String error;

    @JsonProperty("_links")
    private final Map<String, Object> links;

    @java.beans.ConstructorProperties({"message", "error", "links"})
    public ErrorResponseBody(String message, String error, Map<String, Object> links) {
        this.message = message;
        this.error = error;
        this.links = links;
    }

    public String getMessage() {
        return this.message;
    }

    public String getError() {
        return this.error;
    }

    public Map<String, Object> getLinks() {
        return this.links;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ErrorResponseBody that = (ErrorResponseBody) o;
        return Objects.equals(message, that.message) &&
                Objects.equals(error, that.error) &&
                Objects.equals(links, that.links);
    }

    @Override
    public int hashCode() {
        return Objects.hash(message, error, links);
    }

    public String toString() {
        return "ErrorResponseBody(message=" + this.getMessage() +
                ", error=" + this.getError() +
                ", links=" + this.getLinks() + ")";
    }
}
