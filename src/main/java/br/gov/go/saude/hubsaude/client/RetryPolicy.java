/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás — Secretaria de Estado da Saúde (SES-GO).
 * Copyright 2025-2026 Universidade Federal de Goiás (UFG) —
 *     Instituto de Informática / Fábrica de Software.
 *
 * Licenciado sob a Apache License, Version 2.0 (a "Licença");
 * você só pode usar este arquivo em conformidade com a Licença.
 * Você pode obter uma cópia da Licença em
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * A menos que exigido por lei aplicável ou acordado por escrito,
 * o software distribuído sob a Licença é distribuído "NO ESTADO
 * EM QUE SE ENCONTRA", SEM GARANTIAS OU CONDIÇÕES DE QUALQUER
 * TIPO, expressas ou implícitas. Consulte a Licença para o
 * idioma específico que rege permissões e limitações sob a
 * Licença.
 */

package br.gov.go.saude.hubsaude.client;

import java.net.http.HttpResponse;

/**
 * Política de retry para o token endpoint: classificação de status HTTP
 * transitórios e cálculo do delay entre tentativas.
 *
 * <p>
 * Regras aplicadas por {@link SmartTokenClient}:
 * </p>
 * <ul>
 * <li>São retriáveis HTTP 429 (rate limit) e 500/502/503/504;</li>
 * <li>quando o servidor envia {@code Retry-After} (segundos) em 429/503,
 * o valor é honrado com teto de {@link #RETRY_AFTER_MAX_MS};</li>
 * <li>na ausência de {@code Retry-After}, aplica-se backoff exponencial
 * (1s, 2s, 4s...).</li>
 * </ul>
 */
final class RetryPolicy {

    /** Delay base para retry exponencial em milissegundos. */
    private static final long RETRY_BASE_DELAY_MS = 1000L;

    /** Milissegundos por segundo (conversão de Retry-After). */
    private static final long MILLIS_PER_SECOND = 1000L;

    /** Teto para o valor do cabeçalho Retry-After, em milissegundos. */
    private static final long RETRY_AFTER_MAX_MS = 60_000L;

    /** Código HTTP: Rate Limit Exceeded. */
    private static final int HTTP_TOO_MANY_REQUESTS = 429;

    /** Código HTTP: Internal Server Error. */
    private static final int HTTP_INTERNAL_ERROR = 500;

    /** Código HTTP: Bad Gateway. */
    private static final int HTTP_BAD_GATEWAY = 502;

    /** Código HTTP: Service Unavailable. */
    private static final int HTTP_SERVICE_UNAVAILABLE = 503;

    /** Código HTTP: Gateway Timeout. */
    private static final int HTTP_GATEWAY_TIMEOUT = 504;

    private RetryPolicy() {
        // Classe utilitária: não instanciável.
    }

    /**
     * Indica se o status HTTP representa falha transitória passível de retry.
     *
     * <p>São retriáveis: 429 (rate limit) e 500/502/503/504.</p>
     *
     * @param statusCode código de status HTTP
     * @return {@code true} se o status for retriável
     */
    static boolean isRetriableStatus(final int statusCode) {
        return statusCode == HTTP_TOO_MANY_REQUESTS
                || statusCode == HTTP_INTERNAL_ERROR
                || statusCode == HTTP_BAD_GATEWAY
                || statusCode == HTTP_SERVICE_UNAVAILABLE
                || statusCode == HTTP_GATEWAY_TIMEOUT;
    }

    /**
     * Extrai o cabeçalho {@code Retry-After} (em segundos) para HTTP 429/503.
     *
     * <p>Somente o formato delta em segundos é suportado; o formato
     * HTTP-date é ignorado.</p>
     *
     * @param response   resposta HTTP
     * @param statusCode código de status da resposta
     * @return delay sugerido em milissegundos, ou {@code -1} se ausente/inválido
     */
    static long parseRetryAfterMillis(
            final HttpResponse<String> response, final int statusCode) {
        if (statusCode != HTTP_TOO_MANY_REQUESTS && statusCode != HTTP_SERVICE_UNAVAILABLE) {
            return -1L;
        }
        return response.headers().firstValue("Retry-After")
                .map(value -> {
                    try {
                        final long seconds = Long.parseLong(value.trim());
                        return seconds >= 0 ? seconds * MILLIS_PER_SECOND : -1L;
                    } catch (NumberFormatException e) {
                        return -1L;
                    }
                })
                .orElse(-1L);
    }

    /**
     * Calcula o delay entre tentativas de retry.
     *
     * <p>
     * Quando o servidor informa {@code Retry-After} (HTTP 429/503), o valor
     * é honrado com teto de {@link #RETRY_AFTER_MAX_MS}. Caso contrário,
     * aplica-se backoff exponencial (1s, 2s, 4s...).
     * </p>
     *
     * @param attempt      número da tentativa que falhou (1-based)
     * @param retryAfterMs valor de Retry-After em ms, ou negativo se ausente
     * @return delay em milissegundos
     */
    static long computeRetryDelayMs(final int attempt, final long retryAfterMs) {
        if (retryAfterMs >= 0) {
            return Math.min(retryAfterMs, RETRY_AFTER_MAX_MS);
        }
        return RETRY_BASE_DELAY_MS * (1L << (attempt - 1));
    }
}
