package ru.agentlab.oauth.impl;

import java.io.IOException;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ru.agentlab.jwt.service.IJwtService;
import ru.agentlab.jwt.service.JwtException;

@Component(property = { "osgi.jaxrs.extension=true" })
@Provider
public class HttpFilter implements ContainerRequestFilter, ExceptionMapper<JwtException> {

    private static final Logger LOGGER = LoggerFactory.getLogger(HttpFilter.class);

    @Reference
    private IJwtService jwtService;

    @Context
    private UriInfo uriInfo;

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {

        if (!uriInfo.getPath().contains("oauth/login")) {
            if (!jwtService.isValid(requestContext.getHeaderString(HttpHeaders.AUTHORIZATION))) {
                requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
            }
        }
    }

    @Override
    public Response toResponse(JwtException exception) {
        LOGGER.info(exception.getMessage(), exception);
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

}