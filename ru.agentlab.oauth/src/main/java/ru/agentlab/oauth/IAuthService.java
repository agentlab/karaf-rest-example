package ru.agentlab.oauth;

import javax.ws.rs.core.Response;

public interface IAuthService {

    public Response authenticateByLoginAndPassword(String username, String password, String[] scopes);

    public Response refreshToken(String refreshToken);

    public Response introspectToken(String token, String token_type_hint);
}
