package ru.agentlab.oauth.impl;

import java.io.IOException;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Strings;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
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

        standartScopes = new Scope(OIDCScopeValue.OPENID);

        clientAuth = new ClientSecretBasic(clientId, clientSecret);

        disableSSLVerification();
    }

    @Override
    @POST
    @Path("/token")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response grantOperation(Form form) {
        MultivaluedMap<String, String> formParams = form.asMap();

        List<String> grantTypes = formParams.get("grant_type");

        if (grantTypes == null || grantTypes.isEmpty() || grantTypes.size() > 2) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        GrantType grantType = null;

        try {
            grantType = GrantType.parse(grantTypes.get(0));
        } catch (ParseException e) {
            LOGGER.error(e.getMessage(), e);
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        if (grantType.equals(GrantType.PASSWORD)) {
            return clientCredentialsGrantFlow(form);
        } else if (grantType.equals(GrantType.REFRESH_TOKEN)) {
            return refreshTokenGrantFlow(form);
        }

        return Response.status(Response.Status.BAD_REQUEST).build();
    }

    private Response clientCredentialsGrantFlow(Form form) {
        String username = form.asMap().getFirst("username");
        String password = form.asMap().getFirst("password");

        if (isBadRequest(username, password)) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        AuthorizationGrant passwordGrant = new ResourceOwnerPasswordCredentialsGrant(username, new Secret(password));

        return performAuthorizationGrantOperation(passwordGrant, getRequestedScopes(form));

    }

    private Response refreshTokenGrantFlow(Form form) {
        String refreshToken = form.asMap().getFirst("refresh_token");

        if (isBadRequest(refreshToken)) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        return performAuthorizationGrantOperation(new RefreshTokenGrant(new RefreshToken(refreshToken)), null);
    }

    private Scope getRequestedScopes(Form form) {

        List<String> scope = form.asMap().get("scope");
        Scope scopes = new Scope();

        if (scope != null) {
            scope.forEach(sc -> scopes.add(sc));
        } else {
            scopes.addAll(standartScopes);
        }

        return scopes;
    }

    private static String getEnv(String key, String defValue) {
        String value = System.getenv(key);
        return value != null ? value : defValue;
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
            ErrorObject error = response.toErrorResponse().getErrorObject();

            return Response.status(error.getHTTPStatusCode()).entity(error.toJSONObject().toString()).build();
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
