package ru.agentlab.oauth.impl;

import java.io.IOException;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Optional;

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
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Token;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;

import ru.agentlab.oauth.IAuthService;
import ru.agentlab.oauth.commons.IAuthServerProvider;
import ru.agentlab.oauth.commons.IHttpClientProvider;

@Path("/oauth2")
@Component(property = { "osgi.jaxrs.resource=true" })
public class AuthServiceImpl implements IAuthService {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthServiceImpl.class);

    private final ClientAuthentication clientAuth;

    private final Scope standartScopes;

    @Reference
    private IAuthServerProvider authServerProvider;
    @Reference
    private IHttpClientProvider httpClientProvider;

    public AuthServiceImpl() {
        ClientID clientId = new ClientID(getEnv("CLIENT_ID", "SdQOGBYwEC0rVNYGBWBByxrEQuca"));
        Secret clientSecret = new Secret(getEnv("CLIENT_SECRET", "tBXDHx2riibj_U3dXOIvhZKRPPIa"));

        standartScopes = new Scope(OIDCScopeValue.values());

        clientAuth = new ClientSecretBasic(clientId, clientSecret);

        disableSSLVerification();
    }

    @Override
    @POST
    @Path("/token:loginPassword")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response authenticateByLoginAndPassword(@FormParam("username") String username,
            @FormParam("password") String password, @FormParam("scope") String[] scopes) {

        if (isBadRequest(username, password)) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        Scope requestScopes = isEmptyScopes(scopes) ? standartScopes : new Scope(scopes);

        AuthorizationGrant passwordGrant = new ResourceOwnerPasswordCredentialsGrant(username, new Secret(password));

        return performAuthorizationGrantOperation(passwordGrant, requestScopes);
    }

    @Override
    @POST
    @Path("/token:refresh")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response refreshToken(@FormParam("refresh_token") String refreshToken) {

        if (isBadRequest(refreshToken)) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        return performAuthorizationGrantOperation(new RefreshTokenGrant(new RefreshToken(refreshToken)), null);
    }

    @Override
    @POST
    @Path("/token:introspect")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response introspectToken(@FormParam("token") String token,
            @FormParam("token_type_hint") String token_type_hint) {

        Optional<Token> optionalToken = getToken(token, token_type_hint);

        if (!optionalToken.isPresent()) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        TokenIntrospectionRequest introspectionRequest = new TokenIntrospectionRequest(
                authServerProvider.getTokenIntrospectUrl(), optionalToken.get());

        HTTPResponse httpResponse = null;

        try {
            httpResponse = introspectionRequest.toHTTPRequest().send();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }

        return Response.status(httpResponse.getStatusCode()).entity(httpResponse.getContent()).build();
    }

    private static String getEnv(String key, String defValue) {
        String value = System.getenv(key);
        return value != null ? value : defValue;
    }

    private boolean isEmptyScopes(String[] scopes) {
        if (scopes == null || scopes.length == 0) {
            return true;
        }
        return false;
    }

    private Optional<Token> getToken(String token, String token_type_hint) {

        if (isBadRequest(token, token_type_hint))
            return Optional.empty();

        if ("access_token".equals(token_type_hint)) {
            return Optional.of(new BearerAccessToken(token));

        } else if ("refresh_token".equals(token_type_hint)) {
            return Optional.of(new RefreshToken(token));
        }

        return Optional.empty();

    }

    private Response performAuthorizationGrantOperation(AuthorizationGrant grant, Scope scopes) {

        TokenRequest request = new TokenRequest(authServerProvider.getTokenUrl(), clientAuth, grant, scopes);

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

    private boolean isBadRequest(String... params) {
        for (String param : params) {
            if (Strings.isNullOrEmpty(param)) {
                return true;
            }
        }
        return false;
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
