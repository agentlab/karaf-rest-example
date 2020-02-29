package ru.agentlab.oauth.commons;

import java.net.URI;

public interface IAuthServerProvider {

    URI getServeBaserUrl();

    URI getServerJwksUrl();

    URI getTokenUrl();

    URI getTokenIntrospectUrl();

    URI getDeviceAuthorizationEndpoint();
}
