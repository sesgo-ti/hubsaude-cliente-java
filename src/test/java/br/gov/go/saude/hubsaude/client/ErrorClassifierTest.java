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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Testes do colaborador {@link ErrorClassifier}: classificação de falhas
 * retriáveis, materialização de respostas HTTP de erro e integração da
 * heurística de rejeição de certificado de cliente no mTLS.
 *
 * <p>A cobertura fina das heurísticas estáticas permanece em
 * {@code SmartTokenClientTest} e {@code SmartTokenClientCertRejectionTest};
 * aqui o foco são os métodos de instância extraídos na issue #1032.
 */
class ErrorClassifierTest {

    private static final String CLIENT_ID = "cliente-teste";
    private static final String ENDPOINT = "https://auth.example/token";

    private final ErrorClassifier classifier = new ErrorClassifier(CLIENT_ID, ENDPOINT);

    private final TraceContext trace = TraceContext.generate();

    @Nested
    @DisplayName("retriableOrRethrow")
    class RetriableOrRethrow {

        @Test
        @DisplayName("devolve a exceção quando a falha é transitória de rede")
        void devolveQuandoTransitoria() throws IOException {
            final IOException timeout = new HttpTimeoutException("request timed out");

            assertThat(classifier.retriableOrRethrow(timeout, trace)).isSameAs(timeout);
        }

        @Test
        @DisplayName("propaga IOException não transitória")
        void propagaNaoTransitoria() {
            final IOException naoTransitoria = new IOException("disco cheio");

            assertThatThrownBy(() -> classifier.retriableOrRethrow(naoTransitoria, trace))
                    .isSameAs(naoTransitoria);
        }

        @Test
        @DisplayName("converte rejeição mTLS em SmartTokenException com orientação")
        void converteRejeicaoMtls() {
            final IOException mtls = new IOException(
                    new SSLHandshakeException("Received fatal alert: certificate_revoked"));

            assertThatThrownBy(() -> classifier.retriableOrRethrow(mtls, trace))
                    .isInstanceOf(SmartTokenException.class)
                    .hasMessageContaining(ENDPOINT)
                    .hasMessageContaining("certificado de cliente rejeitado")
                    .hasCause(mtls);
        }
    }

    @Nested
    @DisplayName("httpFailure")
    class HttpFailure {

        @Test
        @DisplayName("monta mensagem com status, traceId e corpo sanitizado")
        void montaMensagemComTraceId() {
            final SmartTokenException ex = classifier.httpFailure(
                    fakeResponse(401, "{\"error\":\"invalid_client\"}", Map.of()), trace);

            assertThat(ex.getMessage())
                    .contains("HTTP 401")
                    .contains("traceId=" + trace.traceId())
                    .contains("invalid_client");
        }

        @Test
        @DisplayName("redige access_token do corpo de erro")
        void redigeTokenDoCorpo() {
            final SmartTokenException ex = classifier.httpFailure(
                    fakeResponse(400, "{\"access_token\":\"segredo\"}", Map.of()), trace);

            assertThat(ex.getMessage())
                    .contains("[REDACTED]")
                    .doesNotContain("segredo");
        }

        @Test
        @DisplayName("inclui Retry-After e orientação em HTTP 429 sem retry automático")
        void incluiRetryAfterEm429() {
            final SmartTokenException ex = classifier.httpFailure(
                    fakeResponse(429, "{\"error\":\"slow_down\"}",
                            Map.of("Retry-After", List.of("30"))), trace);

            assertThat(ex.getMessage())
                    .contains("HTTP 429")
                    .contains("(Retry-After: 30)")
                    .contains("a decisão de aguardar e reenviar é do chamador");
        }
    }

    /**
     * Constrói um {@link HttpResponse} sintético com status, corpo e headers
     * controlados, suficiente para exercitar {@link ErrorClassifier#httpFailure}.
     *
     * @param status  código HTTP simulado
     * @param body    corpo da resposta
     * @param headers headers da resposta
     * @return resposta HTTP sintética
     */
    private static HttpResponse<String> fakeResponse(
            final int status, final String body, final Map<String, List<String>> headers) {
        final HttpHeaders httpHeaders = HttpHeaders.of(headers, (k, v) -> true);
        return new HttpResponse<>() {
            @Override
            public int statusCode() {
                return status;
            }

            @Override
            public HttpRequest request() {
                throw new UnsupportedOperationException("não usado no teste");
            }

            @Override
            public Optional<HttpResponse<String>> previousResponse() {
                return Optional.empty();
            }

            @Override
            public HttpHeaders headers() {
                return httpHeaders;
            }

            @Override
            public String body() {
                return body;
            }

            @Override
            public Optional<SSLSession> sslSession() {
                return Optional.empty();
            }

            @Override
            public URI uri() {
                return URI.create(ENDPOINT);
            }

            @Override
            public HttpClient.Version version() {
                return HttpClient.Version.HTTP_1_1;
            }
        };
    }
}
