package ru.agentlab.oauth.commons;

public interface IAuthServerProvider {

    String getServeBaserUrl();

    String getServerJwksUrl();

    String getTokenUrl();
}
