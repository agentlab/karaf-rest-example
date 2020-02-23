package ru.agentlab.security;

import org.apache.shiro.authc.AuthenticationException;

public interface ISecurityService {

    /**
     * Performs jaas's login
     *
     * @param accessToken JWT access token, can not be {@code null}
     */
    void setSubject(String accessToken) throws AuthenticationException;
}
