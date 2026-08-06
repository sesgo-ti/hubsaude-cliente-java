/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.hubsaude.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Testes unitários de {@link TraceContext}: conformidade do header
 * {@code traceparent} com o W3C Trace Context §3.2 (formato, proibição de
 * todo-zeros, flag {@code sampled} desligada) e unicidade entre gerações.
 */
class TraceContextTest {

        /** Formato completo exigido: 00-{32 hex}-{16 hex}-00. */
        private static final String TRACEPARENT_REGEX = "^00-[0-9a-f]{32}-[0-9a-f]{16}-00$";

        private static final String ALL_ZERO_TRACE_ID = "0".repeat(32);
        private static final String ALL_ZERO_SPAN_ID = "0".repeat(16);

        @Test
        @DisplayName("traceparent gerado segue o formato W3C com flags 00 (not sampled)")
        void deveGerarTraceparentNoFormatoW3c() {
                final TraceContext trace = TraceContext.generate();

                assertThat(trace.traceparent()).matches(TRACEPARENT_REGEX);
        }

        @Test
        @DisplayName("componentes têm o tamanho e alfabeto exigidos e nunca são todo-zeros")
        void deveGerarComponentesValidosENaoTodoZeros() {
                final TraceContext trace = TraceContext.generate();

                assertThat(trace.traceId())
                                .hasSize(32)
                                .matches("^[0-9a-f]{32}$")
                                .isNotEqualTo(ALL_ZERO_TRACE_ID);
                assertThat(trace.spanId())
                                .hasSize(16)
                                .matches("^[0-9a-f]{16}$")
                                .isNotEqualTo(ALL_ZERO_SPAN_ID);
        }

        @Test
        @DisplayName("traceparent é composto exatamente por version, traceId, spanId e flags")
        void deveComporTraceparentComOsComponentesDaInstancia() {
                final TraceContext trace = TraceContext.generate();

                assertThat(trace.traceparent())
                                .isEqualTo("00-" + trace.traceId() + "-" + trace.spanId() + "-00");
        }

        @Test
        @DisplayName("gerações sucessivas produzem trace-ids e span-ids únicos")
        void deveGerarValoresUnicosEntreChamadas() {
                final int amostras = 1000;
                final Set<String> traceIds = new HashSet<>();
                final Set<String> spanIds = new HashSet<>();

                for (int i = 0; i < amostras; i++) {
                        final TraceContext trace = TraceContext.generate();
                        traceIds.add(trace.traceId());
                        spanIds.add(trace.spanId());
                }

                assertThat(traceIds).hasSize(amostras);
                assertThat(spanIds).hasSize(amostras);
        }

        @Test
        @DisplayName("construtor rejeita trace-id inválido (todo-zeros, maiúsculas, tamanho errado, nulo)")
        void deveRejeitarTraceIdInvalido() {
                final String spanIdValido = TraceContext.generate().spanId();

                assertThatThrownBy(() -> new TraceContext(ALL_ZERO_TRACE_ID, spanIdValido))
                                .isInstanceOf(IllegalArgumentException.class)
                                .hasMessageContaining("trace-id");
                assertThatThrownBy(() -> new TraceContext("A".repeat(32), spanIdValido))
                                .isInstanceOf(IllegalArgumentException.class);
                assertThatThrownBy(() -> new TraceContext("abc123", spanIdValido))
                                .isInstanceOf(IllegalArgumentException.class);
                assertThatThrownBy(() -> new TraceContext(null, spanIdValido))
                                .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("construtor rejeita span-id inválido (todo-zeros, maiúsculas, tamanho errado, nulo)")
        void deveRejeitarSpanIdInvalido() {
                final String traceIdValido = TraceContext.generate().traceId();

                assertThatThrownBy(() -> new TraceContext(traceIdValido, ALL_ZERO_SPAN_ID))
                                .isInstanceOf(IllegalArgumentException.class)
                                .hasMessageContaining("span-id");
                assertThatThrownBy(() -> new TraceContext(traceIdValido, "F".repeat(16)))
                                .isInstanceOf(IllegalArgumentException.class);
                assertThatThrownBy(() -> new TraceContext(traceIdValido, "0123"))
                                .isInstanceOf(IllegalArgumentException.class);
                assertThatThrownBy(() -> new TraceContext(traceIdValido, null))
                                .isInstanceOf(IllegalArgumentException.class);
        }
}
