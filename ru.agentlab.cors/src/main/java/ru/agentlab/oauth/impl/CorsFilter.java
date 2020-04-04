package ru.agentlab.oauth.impl;

import java.io.IOException;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.Provider;

import org.osgi.service.component.annotations.Component;

@Component(property = { "osgi.jaxrs.extension=true" })
@Provider
public class CorsFilter implements ContainerResponseFilter {
    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext)
            throws IOException {

        MultivaluedMap<String, Object> headers = responseContext.getHeaders();
        headers.add("Access-Control-Allow-Credentials", true);
        headers.add("Access-Control-Allow-Origin", "*");
        headers.addAll("Access-Control-Allow-Methods", HttpMethod.GET, HttpMethod.POST, HttpMethod.PUT,
                HttpMethod.DELETE, HttpMethod.OPTIONS, HttpMethod.HEAD);
        headers.addAll("Access-Control-Allow-Headers", "origin, content-type, accept, authorization, user-agent");

    }
}
