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

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import javax.net.ssl.SSLContext;

import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

/**
 * Descoberta do {@code token_endpoint} via
 * {@code /.well-known/smart-configuration} (SMART on FHIR) e validação de
 * URLs quanto ao uso obrigatório de https.
 *
 * <p>
 * Colaborador interno do {@link SmartTokenClientBuilder}, extraído para
 * reduzir a complexidade do builder (issue #1032). Não faz parte da API
 * pública da biblioteca: consumidores usam
 * {@link SmartTokenClientBuilder#discoverTokenEndpoint(String, SSLContext,
 * Duration, Duration)}.
 * </p>
 */
final class SmartConfigurationDiscovery {

    private static final int HTTP_OK = 200;

    private SmartConfigurationDiscovery() {
        // Classe utilitária; não instanciável.
    }

    /**
     * Descobre o token_endpoint consultando o /.well-known/smart-configuration
     * a partir de uma URL base FHIR.
     *
     * <p>
     * O valor retornado pelo servidor é validado: deve usar o esquema
     * {@code https} (exceção para {@code localhost}/{@code 127.0.0.1}),
     * evitando que um endpoint inseguro seja adotado silenciosamente.
     * </p>
     *
     * <p>
     * A requisição carrega um header {@code traceparent} (W3C Trace
     * Context) gerado localmente; em caso de falha, o trace-id integra a
     * mensagem de erro para correlação com a plataforma.
     * </p>
     *
     * @param fhirBaseUrl    URL base do servidor FHIR
     * @param sslContext     contexto SSL a ser utilizado
     * @param connectTimeout timeout de conexão HTTP
     * @param requestTimeout timeout de requisição HTTP
     * @return a URL do token_endpoint resolvida dinamicamente
     * @throws IOException em caso de erro de rede ou falha de protocolo
     * @throws IllegalArgumentException se o token_endpoint descoberto não
     *                                  usar https (fora de localhost)
     */
    static String discoverTokenEndpoint(
            final String fhirBaseUrl,
            final SSLContext sslContext,
            final Duration connectTimeout,
            final Duration requestTimeout) throws IOException {
        final String wellKnownUrl = fhirBaseUrl.endsWith("/")
                ? fhirBaseUrl + ".well-known/smart-configuration"
                : fhirBaseUrl + "/.well-known/smart-configuration";

        // Contexto de trace W3C próprio desta requisição (correlação com a
        // plataforma; ver TraceContext).
        final TraceContext trace = TraceContext.generate();

        try (HttpClient client = HttpClient.newBuilder()
                .sslContext(sslContext)
                .connectTimeout(connectTimeout)
                .build()) {

            final HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(wellKnownUrl))
                    .header(TraceContext.TRACEPARENT_HEADER, trace.traceparent())
                    .timeout(requestTimeout)
                    .GET()
                    .build();

            final HttpResponse<String> response = sendRequest(client, request);
            if (response.statusCode() != HTTP_OK) {
                throw new SmartTokenException(
                        "Falha ao obter smart-configuration (" + response.statusCode()
                                + ", traceId=" + trace.traceId() + "): "
                                + ErrorClassifier.sanitizeErrorResponse(response.body()));
            }

            final ObjectMapper mapper = JsonMapper.builder()
                    .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                    .build();
            final JsonNode node = mapper.readTree(response.body());

            if (!node.has("token_endpoint")) {
                throw new SmartTokenException("A resposta de smart-configuration não contém 'token_endpoint'");
            }
            final String discovered = node.get("token_endpoint").asString();
            requireHttps(discovered, "token_endpoint descoberto");
            return discovered;
        }
    }

    /**
     * Exige que a URL use o esquema {@code https}, com exceção explícita
     * para {@code localhost}/{@code 127.0.0.1} (útil em desenvolvimento e
     * testes com servidor local).
     *
     * @param url   URL a validar
     * @param campo nome do campo, usado na mensagem de erro
     * @throws IllegalArgumentException se o esquema não for https e o host
     *                                  não for local
     */
    // Endereços de loopback fazem parte da allowlist intencional para
    // desenvolvimento/testes locais — não são IPs de serviços hardcoded.
    @SuppressWarnings("PMD.AvoidUsingHardCodedIP")
    static void requireHttps(final String url, final String campo) {
        final URI uri;
        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    campo + " inválido: '" + url + "' não é uma URL válida", e);
        }
        final String scheme = uri.getScheme();
        if ("https".equalsIgnoreCase(scheme)) {
            return;
        }
        final String host = uri.getHost();
        final boolean hostLocal = host != null
                && ("localhost".equalsIgnoreCase(host)
                        || "127.0.0.1".equals(host)
                        || "[::1]".equals(host)
                        || "::1".equals(host));
        if ("http".equalsIgnoreCase(scheme) && hostLocal) {
            return;
        }
        throw new IllegalArgumentException(
                campo + " deve usar o esquema https (recebido: '" + url + "')."
                        + " O esquema http é permitido apenas para localhost/127.0.0.1,"
                        + " em desenvolvimento e testes locais.");
    }

    private static HttpResponse<String> sendRequest(
            final HttpClient client,
            final HttpRequest request) throws IOException {
        try {
            return client.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Requisição para smart-configuration interrompida", e);
        }
    }
}
