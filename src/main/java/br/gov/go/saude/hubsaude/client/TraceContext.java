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

import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.regex.Pattern;

/**
 * Contexto de trace <a href="https://www.w3.org/TR/trace-context/">W3C
 * Trace Context</a> gerado localmente para uma requisição HTTP do cliente.
 *
 * <p>
 * O HubSaúde deriva o identificador de correlação de cada requisição
 * exclusivamente do header {@code traceparent} (contexto de trace W3C);
 * headers como {@code X-Correlation-Id} enviados pelo cliente são
 * ignorados pelo gateway. Este tipo gera o par trace-id/span-id por
 * requisição — sem dependência do SDK OpenTelemetry — permitindo que o
 * integrador correlacione seus logs locais com o {@code correlation-id}
 * registrado pela plataforma.
 * </p>
 *
 * <p>
 * Formato emitido (W3C Trace Context §3.2):
 * {@code 00-<trace-id>-<parent-id>-<trace-flags>}, onde:
 * </p>
 * <ul>
 * <li><strong>version</strong>: {@code 00};</li>
 * <li><strong>trace-id</strong>: 16 bytes aleatórios criptograficamente
 * (32 caracteres hexadecimais minúsculos), nunca todo-zeros;</li>
 * <li><strong>parent-id</strong> (span-id): 8 bytes aleatórios
 * criptograficamente (16 caracteres hexadecimais minúsculos), nunca
 * todo-zeros;</li>
 * <li><strong>trace-flags</strong>: {@code 00} — flag {@code sampled}
 * desligada, pois esta biblioteca não grava spans (semântica da
 * §3.2.2.5.1: o chamador não registrou o span correspondente).</li>
 * </ul>
 *
 * <p>
 * Instâncias são imutáveis e validadas na construção: componentes fora
 * do formato W3C (tamanho, maiúsculas, todo-zeros) são rejeitados com
 * {@link IllegalArgumentException}.
 * </p>
 *
 * @param traceId identificador do trace — 32 caracteres hexadecimais
 *                minúsculos, não todo-zeros
 * @param spanId  identificador do span (parent-id no header) — 16
 *                caracteres hexadecimais minúsculos, não todo-zeros
 */
record TraceContext(String traceId, String spanId) {

    /** Nome do header HTTP de contexto de trace (W3C Trace Context). */
    static final String TRACEPARENT_HEADER = "traceparent";

    /** Versão do formato traceparent suportada (W3C Trace Context §3.2.2.2). */
    private static final String VERSION = "00";

    /** Flags de trace: {@code sampled} desligado — a lib não grava spans. */
    private static final String FLAGS_NOT_SAMPLED = "00";

    /** Tamanho do trace-id em bytes (W3C Trace Context §3.2.2.3). */
    private static final int TRACE_ID_BYTES = 16;

    /** Tamanho do span-id (parent-id) em bytes (W3C Trace Context §3.2.2.4). */
    private static final int SPAN_ID_BYTES = 8;

    /** Formato válido do trace-id: 32 hex minúsculos, não todo-zeros. */
    private static final Pattern TRACE_ID_PATTERN = Pattern.compile("^(?!0{32}$)[0-9a-f]{32}$");

    /** Formato válido do span-id: 16 hex minúsculos, não todo-zeros. */
    private static final Pattern SPAN_ID_PATTERN = Pattern.compile("^(?!0{16}$)[0-9a-f]{16}$");

    /** Gerador criptográfico compartilhado (thread-safe). */
    private static final SecureRandom RANDOM = new SecureRandom();

    /** Codificador hexadecimal minúsculo. */
    private static final HexFormat HEX = HexFormat.of();

    /**
     * Valida os invariantes do W3C Trace Context na construção.
     *
     * @throws IllegalArgumentException se {@code traceId} ou {@code spanId}
     *                                  não seguirem o formato exigido
     */
    TraceContext {
        if (traceId == null || !TRACE_ID_PATTERN.matcher(traceId).matches()) {
            throw new IllegalArgumentException(
                    "trace-id inválido: exige 32 caracteres hexadecimais minúsculos,"
                            + " não todo-zeros (W3C Trace Context §3.2.2.3)");
        }
        if (spanId == null || !SPAN_ID_PATTERN.matcher(spanId).matches()) {
            throw new IllegalArgumentException(
                    "span-id inválido: exige 16 caracteres hexadecimais minúsculos,"
                            + " não todo-zeros (W3C Trace Context §3.2.2.4)");
        }
    }

    /**
     * Gera um novo contexto de trace com trace-id e span-id aleatórios
     * criptograficamente ({@link SecureRandom}).
     *
     * <p>
     * Deve ser invocado uma vez por requisição HTTP: cada tentativa
     * (inclusive retries) carrega um par trace-id/span-id próprio.
     * </p>
     *
     * @return novo contexto de trace, nunca todo-zeros
     */
    static TraceContext generate() {
        return new TraceContext(randomLowerHex(TRACE_ID_BYTES), randomLowerHex(SPAN_ID_BYTES));
    }

    /**
     * Monta o valor do header {@code traceparent} no formato
     * {@code 00-<trace-id>-<parent-id>-00}, onde parent-id é o span-id
     * desta instância (W3C Trace Context §3.2.2).
     *
     * @return valor pronto para envio no header {@code traceparent}
     */
    String traceparent() {
        return VERSION + "-" + traceId + "-" + spanId + "-" + FLAGS_NOT_SAMPLED;
    }

    /**
     * Produz {@code numBytes} bytes aleatórios criptograficamente,
     * codificados em hexadecimal minúsculo, garantindo que o resultado
     * nunca seja todo-zeros (valor inválido pelo W3C Trace Context).
     *
     * @param numBytes quantidade de bytes aleatórios
     * @return representação hexadecimal minúscula, não todo-zeros
     */
    private static String randomLowerHex(final int numBytes) {
        final byte[] bytes = new byte[numBytes];
        do {
            RANDOM.nextBytes(bytes);
        } while (allZeros(bytes));
        return HEX.formatHex(bytes);
    }

    /**
     * Verifica se todos os bytes do array são zero.
     *
     * @param bytes array a inspecionar
     * @return {@code true} quando todos os bytes são {@code 0x00}
     */
    private static boolean allZeros(final byte[] bytes) {
        for (final byte b : bytes) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }
}
