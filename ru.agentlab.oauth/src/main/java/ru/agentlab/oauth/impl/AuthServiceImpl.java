package ru.agentlab.oauth.impl;

import java.io.IOException;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Strings;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.RefreshToken;

import ru.agentlab.oauth.IAuthService;
import ru.agentlab.oauth.commons.IAuthServerProvider;
import ru.agentlab.oauth.commons.IHttpClientProvider;

@Path("/oauth2")
@Component(property = { "osgi.jaxrs.resource=true" })
public class AuthServiceImpl implements IAuthService {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthServiceImpl.class);

    private final ClientAuthentication clientAuth;

    private URI tokenEndpoint;

    @Reference
    private IAuthServerProvider authServerProvider;
    @Reference
    private IHttpClientProvider httpClientProvider;

    public AuthServiceImpl() {
        ClientID clientId = new ClientID(getEnv("CLIENT_ID", "2dvw9sE_ll81aKQs938H_5yASOca"));
        Secret clientSecret = new Secret(getEnv("CLIENT_SECRET", "UHnMWe4rjMiEv7CNEqMdT03UK8Ua"));

        clientAuth = new ClientSecretBasic(clientId, clientSecret);

        disableSSLVerification();
    }

    @Activate
    public void activate() {
        try {
            tokenEndpoint = new URI(authServerProvider.getTokenUrl());
        } catch (URISyntaxException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    @Override
    @POST
    @Path("/token:loginPassword")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response authenticateByLoginAndPassword(@FormParam("username") String username,
            @FormParam("password") String password) {

        if (Strings.isNullOrEmpty(username) || Strings.isNullOrEmpty(password)) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        AuthorizationGrant passwordGrant = new ResourceOwnerPasswordCredentialsGrant(username, new Secret(password));

        return performAuthorizationGrantOperation(passwordGrant);
    }

    @Override
    @POST
    @Path("/token:refresh")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response refreshToken(@FormParam("refresh_token") String refreshToken) {

        if (Strings.isNullOrEmpty(refreshToken)) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        return performAuthorizationGrantOperation(new RefreshTokenGrant(new RefreshToken(refreshToken)));
    }

    private static String getEnv(String key, String defValue) {
        String value = System.getenv(key);
        return value != null ? value : defValue;
    }

    private Response performAuthorizationGrantOperation(AuthorizationGrant grant) {

        TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth, grant);

        TokenResponse response = null;
        try {
            response = TokenResponse.parse(request.toHTTPRequest().send());
        } catch (IOException | ParseException e) {
            LOGGER.error(e.getMessage(), e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }

        if (!response.indicatesSuccess()) {
            TokenErrorResponse errorResponse = response.toErrorResponse();

            LOGGER.info(errorResponse.toErrorResponse().toJSONObject().toString());

            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        AccessTokenResponse successResponse = response.toSuccessResponse();

        return Response.ok().entity(successResponse.getTokens().toString()).build();
    }

    private void disableSSLVerification() {

        TrustManager[] trustAllCerts = new TrustManager[] { new X509ExtendedTrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {

            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {

            }

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {

            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {

            }

            @Override
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            @Override
            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }

        } };

        SSLContext sc = null;
        try {
            sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
        } catch (KeyManagementException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        HTTPRequest.setDefaultSSLSocketFactory(sc.getSocketFactory());
    }
}
