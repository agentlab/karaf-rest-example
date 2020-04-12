package ru.agentlab.oauth.commons;

public class AuthServerUnavailable extends RuntimeException {

    public AuthServerUnavailable(String message) {
        super(message);
    }

    public AuthServerUnavailable(String message, Throwable cause) {
        super(message, cause);
    }
}
