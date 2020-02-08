package ru.agentlab.oauth;

import javax.ws.rs.core.Response;

public interface IAuthService {

    public Response authenticateByLoginAndPassword(String username, String password);
}
