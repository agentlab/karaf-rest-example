package ru.agentlab.oauth.impl;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

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

import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.message.BasicNameValuePair;
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
import com.nimbusds.oauth2.sdk.device.DeviceCode;
import com.nimbusds.oauth2.sdk.device.DeviceCodeGrant;
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

    ClientID clientId = new ClientID(getEnv("CLIENT_ID", "iZ04i_h11Xt0cIwK_SSfYjgup3Ea"));

    private final ClientAuthentication clientAuth;

    private final Scope standartScopes;

    @Reference
    private IAuthServerProvider authServerProvider;
    @Reference
    private IHttpClientProvider httpClientProvider;

    public AuthServiceImpl() {
        Secret clientSecret = new Secret(getEnv("CLIENT_SECRET", "BQcD7CcPH6AfOvZ83TqVhMl3ezYa"));

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

        if (GrantType.PASSWORD.equals(grantType)) {
            return clientCredentialsGrantFlow(form);
        } else if (GrantType.REFRESH_TOKEN.equals(grantType)) {
            return refreshTokenGrantFlow(form);
        } else if (GrantType.DEVICE_CODE.equals(grantType)) {
            return deviceGrantFlow(form);
        } else if (GrantType.AUTHORIZATION_CODE.equals(grantType)) {
            return deviceGrantFlow(form);
        }

        return Response.status(Response.Status.BAD_REQUEST).build();
    }

    @Override
    @POST
    @Path("/device_authorize")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response getDeviceGrantInfo(Form form) {

        Optional<String> info = getDeviceCodeInfo(form);

        if (info.isPresent()) {
            return Response.ok().entity(info.get()).build();
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

    private Response deviceGrantFlow(Form form) {
        String deviceCode = form.asMap().getFirst(GrantType.DEVICE_CODE.getValue());

        if (isBadRequest(deviceCode)) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        AuthorizationGrant deviceGrant = new DeviceCodeGrant(new DeviceCode(deviceCode));

        return performAuthorizationGrantOperation(deviceGrant, getRequestedScopes(form));
    }

    private Response authorizationCodeGrantFlow(Form form) {
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

    private Optional<String> getDeviceCodeInfo(Form form) {
        HttpPost httpPost = new HttpPost(authServerProvider.getDeviceAuthorizationEndpoint());

        List<NameValuePair> params = new ArrayList<NameValuePair>();
        params.add(new BasicNameValuePair("scope", getRequestedScopes(form).toString()));
        params.add(new BasicNameValuePair("client_id", clientId.getValue()));
        try {
            httpPost.setEntity(new UrlEncodedFormEntity(params));
        } catch (UnsupportedEncodingException e) {
            LOGGER.error(e.getMessage(), e);
        }

        try (CloseableHttpResponse response = httpClientProvider.getClient().execute(httpPost)) {
            if (response.getStatusLine().getStatusCode() == Response.Status.OK.getStatusCode()) {
                String responseString = new BasicResponseHandler().handleResponse(response);
                return Optional.ofNullable(responseString);
            }

        } catch (IOException e) {
            LOGGER.error(e.getMessage(), e);
        }

        return Optional.empty();
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
