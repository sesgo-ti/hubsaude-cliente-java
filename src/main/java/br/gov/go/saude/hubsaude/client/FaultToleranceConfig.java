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
 * @param connectTimeout      timeout de conexão TCP (não pode ser null)
 * @param requestTimeout      timeout de requisição HTTP (não pode ser null)
 * @param assertionTtlSeconds TTL do JWT em segundos (≤0 usa padrão)
 * @param maxRetries          número de tentativas (≤0 usa padrão)
 *
 * @see SmartTokenClient
 * @see SmartTokenClientBuilder
 * @since 0.0.0
 */
public record FaultToleranceConfig(Duration connectTimeout, Duration requestTimeout,
                                   int assertionTtlSeconds, int maxRetries) {
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
}

