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

/**
 * Política de retry do cliente: cálculo do delay entre tentativas.
 *
 * <p>
 * Regras aplicadas por {@link SmartTokenClient} (RF-07 da especificação):
 * </p>
 * <ul>
 * <li>apenas falhas transitórias de rede são retriáveis — timeout de
 * conexão, timeout de requisição HTTP e recusa/queda de conexão TCP;</li>
 * <li>respostas HTTP recebidas (qualquer status, inclusive 429 e 5xx)
 * <strong>não</strong> sofrem retry automático: resultam em erro imediato
 * e a decisão de aguardar e reenviar é do chamador;</li>
 * <li>o delay antes da tentativa {@code n+1} é {@code 1s × 2^(n−1)}
 * (1s, 2s, 4s...), sem <em>jitter</em>.</li>
 * </ul>
 */
final class RetryPolicy {

    /** Delay base para retry exponencial em milissegundos. */
    private static final long RETRY_BASE_DELAY_MS = 1000L;

    private RetryPolicy() {
        // Classe utilitária: não instanciável.
    }

    /**
     * Calcula o delay de backoff exponencial entre tentativas:
     * {@code 1s × 2^(attempt−1)}, sem jitter.
     *
     * @param attempt número da tentativa que falhou (1-based)
     * @return delay em milissegundos
     */
    static long computeRetryDelayMs(final int attempt) {
        return RETRY_BASE_DELAY_MS * (1L << (attempt - 1));
    }
}
