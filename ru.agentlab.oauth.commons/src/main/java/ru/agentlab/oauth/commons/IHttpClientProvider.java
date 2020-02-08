package ru.agentlab.oauth.commons;

import org.apache.http.impl.client.CloseableHttpClient;

public interface IHttpClientProvider {
    CloseableHttpClient getClient();
}
