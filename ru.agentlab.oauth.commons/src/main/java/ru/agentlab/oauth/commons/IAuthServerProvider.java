package ru.agentlab.oauth.commons;

import java.net.URI;

public interface IAuthServerProvider {

    URI getJWKSetURI() throws AuthServerUnavailable;

    URI getTokenEndpointURI() throws AuthServerUnavailable;

    URI getIntrospectionEndpointURI() throws AuthServerUnavailable;

    URI getDeviceAuthorizationEndpointURI() throws AuthServerUnavailable;

    URI getRevocationEndpointURI() throws AuthServerUnavailable;

    URI getUserInfoEndpointURI() throws AuthServerUnavailable;
}
