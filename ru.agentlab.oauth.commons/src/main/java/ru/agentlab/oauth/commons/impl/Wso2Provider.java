package ru.agentlab.oauth.commons.impl;

import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.net.URISyntaxException;

import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ru.agentlab.oauth.commons.IAuthServerProvider;

@Component
public class Wso2Provider implements IAuthServerProvider {
    private static final Logger LOGGER = LoggerFactory.getLogger(Wso2Provider.class);
    private static final String WSO2_PROTOCOL = getEnv("WSO2_PROTOCOL", String.class, "https");
    private static final String WSO2_HOST = getEnv("WSO2_HOST", String.class, "localhost");
    private static final int WSO2_PORT = getEnv("WSO2_PORT", Integer.class, 9443);
    private static final String WSO2_URL = WSO2_PROTOCOL + "://" + WSO2_HOST + ':' + WSO2_PORT;

    private static final String JWKS_ENDPOINT = WSO2_URL + "/oauth2/jwks";

    private static final String TOKEN_ENDPOINT = WSO2_URL + "/oauth2/token";

    private static final String TOKEN_INTROSPECT_ENDPOINT = WSO2_URL + "/oauth2/introspect";

    @Override
    public URI getServeBaserUrl() {
        return getUri(WSO2_URL);
    }

    @Override
    public URI getServerJwksUrl() {
        return getUri(JWKS_ENDPOINT);
    }

    @Override
    public URI getTokenUrl() {
        return getUri(TOKEN_ENDPOINT);
    }

    @Override
    public URI getTokenIntrospectUrl() {
        return getUri(TOKEN_INTROSPECT_ENDPOINT);
    }

    private URI getUri(String uri) {
        try {
            return new URI(uri);
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }

        return null;
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
