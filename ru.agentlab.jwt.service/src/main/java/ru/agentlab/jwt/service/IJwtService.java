package ru.agentlab.jwt.service;

import java.util.Map;

/**
 * Service for working with JWT token
 */
public interface IJwtService {

    boolean isValid(String jwt) throws JwtException;

    String getTokenPayload(String jwt) throws JwtException;

    Map<String, Object> getClaimsMap(String jwt) throws JwtException;
}
