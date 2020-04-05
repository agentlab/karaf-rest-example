package ru.agentlab.oauth.commons;

import java.net.URI;

public interface IAuthServerProvider {

    URI getServeBaserUrl();

    URI getServerJwksUrl();

    URI getTokenUrl();

    URI getTokenIntrospectionUrl();

    URI getDeviceAuthorizationEndpoint();
    
    URI getTokenRevocationUrl();
    
    URI getUserInfoUrl();
}
