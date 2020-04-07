package ru.agentlab.oauth.impl;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;
import java.util.Optional;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.CookieParam;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.NewCookie;
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

import static com.google.common.base.Strings.isNullOrEmpty;

import com.google.common.base.Strings;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.TokenRevocationRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.device.DeviceCode;
import com.nimbusds.oauth2.sdk.device.DeviceCodeGrant;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Token;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;

import ru.agentlab.oauth.IAuthService;
import ru.agentlab.oauth.commons.IAuthServerProvider;
import ru.agentlab.oauth.commons.IHttpClientProvider;

@Path("/oauth2")
@Component(property = { "osgi.jaxrs.resource=true" })
public class AuthServiceImpl implements IAuthService {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthServiceImpl.class);

    private final ClientSecretPost clientAuthPost;
    private final ClientAuthentication clientAuthBasic;

    @Reference
    private IAuthServerProvider authServerProvider;
    @Reference
    private IHttpClientProvider httpClientProvider;

    @Context
    private HttpServletRequest requestContext;

    public AuthServiceImpl() {
        ClientID clientId = new ClientID(getEnv("CLIENT_ID", "Ynio_EuYVk8j2gn_6nUbIVQbj_Aa"));
        Secret clientSecret = new Secret(getEnv("CLIENT_SECRET", "fTJGvvfJjUkWvn8R_NY8zXSyYQ0a"));

        clientAuthPost = new ClientSecretPost(clientId, clientSecret);
        clientAuthBasic = new ClientSecretBasic(clientId, clientSecret);

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
            return authorizationCodeGrantFlow(form);
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

    @Override
    @POST
    @Path("/revoke")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response revokeToken(Form form, @CookieParam(OAuthConstants.ACCESS_TOKEN) String accessTokenCookie,
            @CookieParam(OAuthConstants.REFRESH_TOKEN) String refreshTokenCookie) {

        MultivaluedMap<String, String> formParams = form.asMap();

        String tokenType = formParams.getFirst(OAuthConstants.TOKEN_TYPE_HINT);

        if (Strings.isNullOrEmpty(tokenType)) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        String tokenFromForm = formParams.getFirst(OAuthConstants.TOKEN);

        Token token;
        NewCookie resetCookie;

        if (OAuthConstants.ACCESS_TOKEN.equals(tokenType)) {
            String accessToken = isNullOrEmpty(accessTokenCookie) ? tokenFromForm : accessTokenCookie;
            if (isNullOrEmpty(accessToken)) {
                return Response.status(Response.Status.BAD_REQUEST).build();
            } else {
                token = new BearerAccessToken(accessToken);
                resetCookie = createTokenCookie(OAuthConstants.ACCESS_TOKEN, "", 0);
            }
        } else if (OAuthConstants.REFRESH_TOKEN.equals(tokenType)) {
            String refreshToken = isNullOrEmpty(refreshTokenCookie) ? tokenFromForm : refreshTokenCookie;
            if (isNullOrEmpty(refreshToken)) {
                return Response.status(Response.Status.BAD_REQUEST).build();
            } else {
                token = new RefreshToken(refreshToken);
                resetCookie = createTokenCookie(OAuthConstants.REFRESH_TOKEN, "", 0);
            }
        } else {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        TokenRevocationRequest revokeRequest = new TokenRevocationRequest(authServerProvider.getTokenRevocationUrl(),
                clientAuthPost, token);
        HTTPResponse response = null;
        try {
            response = revokeRequest.toHTTPRequest().send();
            if (response.indicatesSuccess()) {
                return Response.ok().cookie(resetCookie).build();
            }

            return Response.status(response.getStatusCode()).entity(response.getContent()).build();
        } catch (IOException e) {
            LOGGER.error(e.getMessage(), e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }
    }

    @Override
    @GET
    @Path("/userinfo")
    @Produces(MediaType.APPLICATION_JSON)
    public Response userInfo(@HeaderParam(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @CookieParam(OAuthConstants.ACCESS_TOKEN) String accessTokenCookie) {

        BearerAccessToken bearerAccessToken = null;

        if (!isNullOrEmpty(accessTokenCookie)) {
            bearerAccessToken = new BearerAccessToken(accessTokenCookie);
        }

        if (bearerAccessToken == null) {
            try {
                bearerAccessToken = BearerAccessToken.parse(authorizationHeader);
            } catch (ParseException e) {
                LOGGER.error(e.getMessage(), e);
            }
        }

        if (bearerAccessToken == null) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        try {
            HTTPResponse httpResponse = new UserInfoRequest(authServerProvider.getUserInfoUrl(), bearerAccessToken)
                    .toHTTPRequest().send();
            UserInfoResponse userInfoResponse = UserInfoResponse.parse(httpResponse);

            if (!userInfoResponse.indicatesSuccess()) {
                ErrorObject errorObject = userInfoResponse.toErrorResponse().getErrorObject();
                return Response.status(errorObject.getHTTPStatusCode()).entity(errorObject.getDescription()).build();
            }

            return Response.ok().entity(userInfoResponse.toSuccessResponse().getUserInfo().toJSONString()).build();

        } catch (IOException | ParseException e) {
            LOGGER.error(e.getMessage(), e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }
    }

    @Override
    @POST
    @Path("/introspect")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response introspectToken(Form form, @CookieParam(OAuthConstants.ACCESS_TOKEN) String accessTokenCookie,
            @CookieParam(OAuthConstants.REFRESH_TOKEN) String refreshTokenCookie) {
        MultivaluedMap<String, String> formParams = form.asMap();

        List<String> tokenType = formParams.get(OAuthConstants.TOKEN_TYPE_HINT);

        if (tokenType == null || tokenType.isEmpty() || tokenType.size() > 2) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        String tokenFromForm = formParams.getFirst(OAuthConstants.TOKEN);

        Token token;

        if (OAuthConstants.ACCESS_TOKEN.equals(tokenType.get(0))) {
            String accessToken = isNullOrEmpty(accessTokenCookie) ? tokenFromForm : accessTokenCookie;
            if (isNullOrEmpty(accessToken)) {
                return Response.status(Response.Status.BAD_REQUEST).build();
            } else {
                token = new BearerAccessToken(accessToken);
            }
        } else if (OAuthConstants.REFRESH_TOKEN.equals(tokenType.get(0))) {
            String refreshToken = isNullOrEmpty(refreshTokenCookie) ? tokenFromForm : refreshTokenCookie;
            if (isNullOrEmpty(refreshToken)) {
                return Response.status(Response.Status.BAD_REQUEST).build();
            } else {
                token = new RefreshToken(refreshToken);
            }
        } else {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        TokenIntrospectionRequest introspectionRequest = new TokenIntrospectionRequest(
                authServerProvider.getTokenIntrospectionUrl(), clientAuthBasic, token);
        try {
            TokenIntrospectionResponse response = TokenIntrospectionResponse
                    .parse(introspectionRequest.toHTTPRequest().send());

            if (!response.indicatesSuccess()) {
                ErrorObject errorObject = response.toErrorResponse().getErrorObject();
                return Response.status(errorObject.getHTTPStatusCode()).entity(errorObject.getDescription()).build();
            }

            return Response.ok().entity(response.toSuccessResponse().toJSONObject().toJSONString()).build();
        } catch (IOException | ParseException e) {
            LOGGER.error(e.getMessage(), e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }

    }

    private Optional<String> getCookieByName(String name) {
        List<Cookie> cookies = Arrays.asList(Optional.ofNullable(requestContext.getCookies()).orElse(new Cookie[0]));
        return cookies.stream().filter(cookie -> name.equals(cookie.getName())).findAny()
                .map(cookie -> cookie.getValue());
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
        String refreshToken = getCookieByName(OAuthConstants.REFRESH_TOKEN)
                .orElse(form.asMap().getFirst(OAuthConstants.REFRESH_TOKEN));

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
        String code = form.asMap().getFirst("code");
        String redirectUriRaw = form.asMap().getFirst("redirect_uri");
        String codeChallenge = form.asMap().getFirst("code_challenge");

        if (isBadRequest(code, redirectUriRaw)) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        URI redirectUri;

        try {
            redirectUri = new URI(redirectUriRaw);
        } catch (URISyntaxException e) {
            LOGGER.error(e.getMessage(), e);
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        CodeVerifier codeVerifier = codeChallenge != null ? new CodeVerifier(codeChallenge) : null;

        return performAuthorizationGrantOperation(
                new AuthorizationCodeGrant(new AuthorizationCode(code), redirectUri, codeVerifier), null);
    }

    private Scope getRequestedScopes(Form form) {

        List<String> scope = form.asMap().get("scope");
        Scope scopes = new Scope();

        if (scope != null) {
            scope.forEach(sc -> scopes.add(sc));
        }

        return scopes;
    }

    private Optional<String> getDeviceCodeInfo(Form form) {
        HttpPost httpPost = new HttpPost(authServerProvider.getDeviceAuthorizationEndpoint());

        List<NameValuePair> params = new ArrayList<NameValuePair>();
        params.add(new BasicNameValuePair("scope", getRequestedScopes(form).toString()));
        params.add(new BasicNameValuePair("client_id", clientAuthPost.getClientID().getValue()));
        params.add(new BasicNameValuePair("client_secret", clientAuthPost.getClientSecret().getValue()));

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

        TokenRequest request = new TokenRequest(authServerProvider.getTokenUrl(), clientAuthPost, grant, scopes);

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

        String accessToken = successResponse.getTokens().getBearerAccessToken().getValue();
        String refreshToken = successResponse.getTokens().getRefreshToken().getValue();

        // TODO: expire time
        NewCookie accessTokenCookie = createTokenCookie(OAuthConstants.ACCESS_TOKEN, accessToken, 3600);
        NewCookie refreshTokenCookie = createTokenCookie(OAuthConstants.REFRESH_TOKEN, refreshToken, 86400);

        return Response.ok().cookie(accessTokenCookie, refreshTokenCookie)
                .entity(successResponse.getTokens().toString()).build();
    }

    private NewCookie createTokenCookie(String tokenTypeHint, String token, int maxAge) {
        Calendar expireTime = Calendar.getInstance();
        expireTime.add(Calendar.SECOND, maxAge);
        return new NewCookie(tokenTypeHint, token, "/", null, NewCookie.DEFAULT_VERSION, null, maxAge,
                expireTime.getTime(), false, true);
    }

    private boolean isBadRequest(String... params) {
        for (String param : params) {
            if (isNullOrEmpty(param)) {
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
