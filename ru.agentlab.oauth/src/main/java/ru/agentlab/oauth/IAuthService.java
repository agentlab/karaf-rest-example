package ru.agentlab.oauth;

import javax.ws.rs.core.Form;
import javax.ws.rs.core.Response;

public interface IAuthService {

    Response grantOperation(Form form);
}
