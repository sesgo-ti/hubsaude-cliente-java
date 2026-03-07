package br.gov.go.saude.hubsaude.client;

import java.time.Duration;
import java.util.Objects;

/**
 * Configuração de tolerância a falhas e resiliência para SmartTokenClient.
 */
public class FaultToleranceConfig {
    private final Duration connectTimeout;
    private final Duration requestTimeout;
    private final int assertionTtlSeconds;
    private final int maxRetries;

    public FaultToleranceConfig(Duration connectTimeout, Duration requestTimeout, int assertionTtlSeconds, int maxRetries) {
        this.connectTimeout = Objects.requireNonNull(connectTimeout, "connectTimeout");
        this.requestTimeout = Objects.requireNonNull(requestTimeout, "requestTimeout");
        // Usa valor padrão se zero ou negativo
        this.assertionTtlSeconds = assertionTtlSeconds > 0
                ? assertionTtlSeconds
                : SmartTokenClient.DEFAULT_ASSERTION_TTL_SECONDS;
        this.maxRetries = maxRetries > 0
                ? maxRetries
                : SmartTokenClient.DEFAULT_MAX_RETRIES;
    }

    public Duration getConnectTimeout() {
        return connectTimeout;
    }

    public Duration getRequestTimeout() {
        return requestTimeout;
    }

    public int getAssertionTtlSeconds() {
        return assertionTtlSeconds;
    }

    public int getMaxRetries() {
        return maxRetries;
    }
}


