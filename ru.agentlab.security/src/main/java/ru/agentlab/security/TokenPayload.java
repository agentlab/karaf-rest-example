package ru.agentlab.security;

import java.util.List;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class TokenPayload {

    private final String sub;

    private Optional<List<String>> groups;

    private Optional<String> email;

    public TokenPayload(@JsonProperty("sub") String sub) {
        this.sub = sub;
    }

    public Optional<List<String>> getGroups() {
        return groups;
    }

    public void setGroups(Optional<List<String>> groups) {
        this.groups = groups;
    }

    public Optional<String> getEmail() {
        return email;
    }

    public void setEmail(Optional<String> email) {
        this.email = email;
    }

    public String getSub() {
        return sub;
    }

}