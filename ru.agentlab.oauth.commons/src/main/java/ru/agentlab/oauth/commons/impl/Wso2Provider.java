package ru.agentlab.oauth.commons.impl;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.net.URI;

import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.AbstractRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderConfigurationRequest;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderEndpointMetadata;

import ru.agentlab.oauth.commons.AuthServerUnavailable;
import ru.agentlab.oauth.commons.IAuthServerProvider;

@Component
public class Wso2Provider implements IAuthServerProvider {
    private static final Logger LOGGER = LoggerFactory.getLogger(Wso2Provider.class);
    private static final String WSO2_PROTOCOL = getEnv("WSO2_PROTOCOL", String.class, "https");
    private static final String WSO2_HOST = getEnv("WSO2_HOST", String.class, "localhost");
    private static final int WSO2_PORT = getEnv("WSO2_PORT", Integer.class, 9443);
    private static final String WSO2_URL = WSO2_PROTOCOL + "://" + WSO2_HOST + ':' + WSO2_PORT;

    private static final String OIDC_DISCOVERY = WSO2_URL + "/oauth2/token";

    private volatile AuthorizationServerMetadata authorizationMetadata;
    private volatile OIDCProviderEndpointMetadata oidcMetadata;

    private Object lock = new Object();

    @Override
    public URI getJWKSetURI() {
        return getAuthorizationMetadata().getJWKSetURI();
    }

    @Override
    public URI getTokenEndpointURI() {
        return getAuthorizationMetadata().getTokenEndpointURI();
    }

    @Override
    public URI getIntrospectionEndpointURI() {
        return getAuthorizationMetadata().getIntrospectionEndpointURI();
    }

    @Override
    public URI getDeviceAuthorizationEndpointURI() {
        return getAuthorizationMetadata().getDeviceAuthorizationEndpointURI();
    }

    @Override
    public URI getRevocationEndpointURI() {
        return getAuthorizationMetadata().getRevocationEndpointURI();
    }

    @Override
    public URI getUserInfoEndpointURI() {
        return getOidcMetadata().getUserInfoEndpointURI();
    }

    private AuthorizationServerMetadata getAuthorizationMetadata() {

        if (authorizationMetadata == null) {

            Issuer issuer = new Issuer(OIDC_DISCOVERY);
            AbstractRequest oidcProviderConfigurationRequest = new OIDCProviderConfigurationRequest(issuer);

            synchronized (lock) {
                if (authorizationMetadata != null)
                    return authorizationMetadata;
                try {
                    HTTPResponse response = oidcProviderConfigurationRequest.toHTTPRequest().send();
                    if (response.indicatesSuccess()) {
                        authorizationMetadata = AuthorizationServerMetadata.parse(response.getContentAsJSONObject());
                    } else {
                        throw new AuthServerUnavailable(response.getContent());
                    }
                } catch (ParseException | IOException e) {
                    throw new AuthServerUnavailable(e.getMessage(), e);
                }
            }
        }

        return authorizationMetadata;
    }

    private OIDCProviderEndpointMetadata getOidcMetadata() {

        if (oidcMetadata == null) {

            Issuer issuer = new Issuer(OIDC_DISCOVERY);
            AbstractRequest oidcProviderConfigurationRequest = new OIDCProviderConfigurationRequest(issuer);

            synchronized (lock) {
                if (oidcMetadata != null)
                    return oidcMetadata;
                try {
                    HTTPResponse response = oidcProviderConfigurationRequest.toHTTPRequest().send();
                    if (response.indicatesSuccess()) {
                        oidcMetadata = OIDCProviderEndpointMetadata.parse(response.getContentAsJSONObject());
                    } else {
                        throw new AuthServerUnavailable(response.getContent());
                    }
                } catch (ParseException | IOException e) {
                    throw new AuthServerUnavailable(e.getMessage(), e);
                }
            }
        }

        return oidcMetadata;
    }

    private static <T> T getEnv(String key, Class<T> clazz, T def) {
        String envValue = System.getenv(key);
        if (envValue != null) {
            try {
                if (Integer.class.equals(clazz) || String.class.equals(clazz)) {
                    return clazz.getDeclaredConstructor(String.class).newInstance(envValue);
                }
            } catch (InstantiationException | IllegalAccessException | IllegalArgumentException
                    | InvocationTargetException | NoSuchMethodException | SecurityException e) {
                LOGGER.error(e.getMessage(), e);
            }
        }
        return def;
    }
}
