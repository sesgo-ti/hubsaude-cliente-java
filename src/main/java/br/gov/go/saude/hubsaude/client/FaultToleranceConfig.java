/*
 * Copyright (c) 2026 SES-GO / UFG
 * Todos os direitos reservados.
 */

package br.gov.go.saude.hubsaude.client;

import java.time.Duration;
import java.util.Objects;

/**
 * Configuração imutável de tolerância a falhas para {@link SmartTokenClient}.
 *
 * <p>
 * Agrupa parâmetros relacionados à resiliência em uma única classe coesa,
 * seguindo o princípio de alta coesão. Valores inválidos (zero ou negativos)
 * para {@code assertionTtlSeconds} e {@code maxRetries} são automaticamente
 * substituídos pelos valores padrão.
 * </p>
 *
 * <h2>Parâmetros</h2>
 * <ul>
 *   <li><strong>connectTimeout:</strong> tempo máximo para estabelecer conexão TCP</li>
 *   <li><strong>requestTimeout:</strong> tempo máximo para completar a requisição HTTP</li>
 *   <li><strong>assertionTtlSeconds:</strong> TTL do JWT client_assertion</li>
 *   <li><strong>maxRetries:</strong> tentativas em caso de falha transitória</li>
 * </ul>
 *
 * <h2>Exemplo de Uso</h2>
 * <pre>{@code
 * var config = new FaultToleranceConfig(
 *     Duration.ofSeconds(10),   // connectTimeout
 *     Duration.ofSeconds(30),   // requestTimeout
 *     120,                      // assertionTtlSeconds
 *     3                         // maxRetries
 * );
 * }</pre>
 *
 * @see SmartTokenClient
 * @see SmartTokenClientBuilder
 * @since 0.0.0
 */
public final class FaultToleranceConfig {
    private final Duration connectTimeout;
    private final Duration requestTimeout;
    private final int assertionTtlSeconds;
    private final int maxRetries;

    /**
     * Cria configuração de tolerância a falhas.
     *
     * <p>
     * Valores zero ou negativos para {@code assertionTtlSeconds} e {@code maxRetries}
     * são substituídos pelos padrões definidos em {@link SmartTokenClient}.
     * </p>
     *
     * @param connectTimeout      timeout de conexão TCP (não pode ser null)
     * @param requestTimeout      timeout de requisição HTTP (não pode ser null)
     * @param assertionTtlSeconds TTL do JWT em segundos (≤0 usa padrão de 60s)
     * @param maxRetries          número de tentativas (≤0 usa padrão de 3)
     * @throws NullPointerException se connectTimeout ou requestTimeout forem null
     */
    public FaultToleranceConfig(
            final Duration connectTimeout,
            final Duration requestTimeout,
            final int assertionTtlSeconds,
            final int maxRetries) {
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

    /**
     * Retorna o timeout de conexão TCP.
     *
     * @return duração do timeout de conexão
     */
    public Duration getConnectTimeout() {
        return connectTimeout;
    }

    /**
     * Retorna o timeout de requisição HTTP.
     *
     * @return duração do timeout de requisição
     */
    public Duration getRequestTimeout() {
        return requestTimeout;
    }

    /**
     * Retorna o TTL do client_assertion JWT em segundos.
     *
     * @return TTL em segundos (sempre positivo)
     */
    public int getAssertionTtlSeconds() {
        return assertionTtlSeconds;
    }

    /**
     * Retorna o número máximo de tentativas em caso de falha transitória.
     *
     * @return número de retries (sempre positivo)
     */
    public int getMaxRetries() {
        return maxRetries;
    }
}


