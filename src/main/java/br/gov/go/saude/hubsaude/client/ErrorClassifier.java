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

import java.io.EOFException;
import java.io.IOException;
import java.net.SocketException;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.util.Locale;
import java.util.Objects;

import javax.crypto.AEADBadTagException;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Classifica falhas na obtenção de token: distingue falhas transitórias de
 * rede (elegíveis a retry) de falhas definitivas, reconhece o padrão de
 * rejeição do certificado de cliente no mTLS e materializa respostas HTTP de
 * erro em {@link SmartTokenException} com corpo sanitizado.
 *
 * <p>
 * Colaborador interno do {@link SmartTokenClient} (issue #1032): concentra a
 * taxonomia de erros que antes inflava a complexidade da classe principal.
 * Não faz parte da API pública da biblioteca.
 * </p>
 */
final class ErrorClassifier {

    /** Código HTTP: Rate Limit Exceeded. */
    static final int HTTP_TOO_MANY_REQUESTS = 429;

    /**
     * Logger compartilhado com {@link SmartTokenClient}: este colaborador é
     * detalhe interno de implementação e o contrato de observabilidade
     * (filtros de log por nome da classe pública) deve permanecer estável.
     */
    private static final Logger LOG = LoggerFactory.getLogger(SmartTokenClient.class);

    /** Limite máximo para sanitização de respostas de erro. */
    private static final int MAX_ERROR_RESPONSE_LENGTH = 500;

    /** Identificador do cliente, usado nas mensagens de log. */
    private final String clientId;

    /** URL do token endpoint, usada nas mensagens de erro de mTLS. */
    private final String tokenEndpoint;

    /**
     * Cria o classificador para um cliente/endpoint específicos.
     *
     * @param clientId      identificador do cliente (para logs)
     * @param tokenEndpoint URL do token endpoint (para mensagens de erro)
     */
    ErrorClassifier(final String clientId, final String tokenEndpoint) {
        this.clientId = Objects.requireNonNull(clientId, "clientId não pode ser null");
        this.tokenEndpoint = Objects.requireNonNull(tokenEndpoint, "tokenEndpoint não pode ser null");
    }

    /**
     * Classifica a exceção de I/O: devolve-a quando representa falha
     * transitória de rede (timeout de conexão ou de requisição, recusa ou
     * queda de conexão TCP) para que o chamador realize retry; caso
     * contrário, propaga.
     *
     * @param ex    exceção capturada na tentativa
     * @param trace contexto de trace W3C enviado na tentativa que falhou
     * @return a própria exceção, quando retriável
     * @throws IOException         quando a exceção não é retriável
     * @throws SmartTokenException quando a falha aparenta ser rejeição do
     *                             certificado de cliente no mTLS
     */
    IOException retriableOrRethrow(final IOException ex, final TraceContext trace)
            throws IOException {
        if (isLikelyClientCertificateRejection(ex)) {
            LOG.error("Falha de TLS após handshake mTLS para clientId={} endpoint={} traceId={}: {}."
                    + " Causa provável: certificado de cliente rejeitado pelo servidor"
                    + " (revogado, expirado ou não confiável) — o servidor abortou a conexão"
                    + " em vez de retornar uma resposta HTTP de erro.",
                    clientId, tokenEndpoint, trace.traceId(), ex.toString());
            throw new SmartTokenException(
                    "Conexão TLS abortada pelo servidor após o handshake mTLS contra "
                            + tokenEndpoint
                            + ". Causa provável: certificado de cliente rejeitado"
                            + " (revogado, expirado ou não confiável)."
                            + " Verifique a validade do certificado em uso e, se ele estiver"
                            + " correto, contate o operador do servidor de autorização —"
                            + " a resposta esperada nesse cenário seria um alerta TLS"
                            + " (certificate_revoked/certificate_expired) ou HTTP 401,"
                            + " e não o encerramento abrupto da conexão.",
                    ex);
        }
        if (isTransientNetworkFailure(ex)) {
            return ex;
        }
        throw ex;
    }

    /**
     * Identifica falhas transitórias de rede elegíveis a retry: timeout de
     * conexão ou de requisição HTTP e recusa/queda de conexão TCP
     * (conexão recusada, connection reset ou EOF prematuro).
     *
     * <p>A cadeia de causas é percorrida porque o
     * {@link java.net.http.HttpClient} frequentemente envolve a causa
     * original em {@link IOException} genérica (ex.: "HTTP/1.1 header parser
     * received no bytes" com causa {@link EOFException} ou
     * {@link SocketException}). Em algumas execuções o JDK lança essa mesma
     * {@link IOException} sem causa anexada; por isso a mensagem também é
     * inspecionada — ela indica conexão encerrada pelo servidor antes de
     * qualquer byte de resposta. Falhas da camada TLS ({@link SSLException})
     * nunca são consideradas transitórias — são tratadas pela heurística de
     * {@link #isLikelyClientCertificateRejection(Throwable)} ou propagadas
     * como estão.</p>
     *
     * @param ex exceção de I/O capturada
     * @return {@code true} quando a falha é transitória de rede
     */
    static boolean isTransientNetworkFailure(final IOException ex) {
        for (Throwable t = ex; t != null; t = t.getCause()) {
            if (t instanceof SSLException) {
                return false;
            }
            if (t instanceof HttpTimeoutException
                    || t instanceof SocketException
                    || t instanceof EOFException) {
                return true;
            }
            final String msg = t.getMessage();
            if (msg != null && msg.toLowerCase(Locale.ROOT).contains("received no bytes")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Heurística para identificar falhas de TLS que tipicamente indicam que o
     * servidor rejeitou o certificado de cliente (revogado, expirado ou não
     * confiável) sem produzir uma resposta HTTP de erro adequada.
     *
     * <p>São tratadas como suspeitas:
     * <ul>
     *   <li>{@link SSLHandshakeException} — rejeição durante o handshake;</li>
     *   <li>{@link AEADBadTagException} na cadeia de causas — record cifrado
     *       com tag AEAD inválido, sintoma típico de servidor que aceita o
     *       handshake mas corrompe o estado da conexão ao decidir rejeitar
     *       o certificado de cliente após o {@code Finished};</li>
     *   <li>{@link SSLException} com mensagem mencionando {@code bad_record_mac}
     *       — equivalente do ponto anterior visto pelo lado JSSE.</li>
     * </ul>
     *
     * <p>Falhas cuja cadeia de causas contém
     * {@link java.security.cert.CertificateException},
     * {@link java.security.cert.CertPathBuilderException} ou
     * {@link java.security.cert.CertPathValidatorException} são excluídas:
     * indicam que foi ESTE cliente que rejeitou o certificado do servidor
     * (ex.: {@code PKIX path building failed} por trust anchor ausente ou
     * incorreto), e não o contrário.</p>
     *
     * <p>Esta verificação é heurística e deve ser usada apenas para enriquecer
     * mensagens de erro; não substitui o diagnóstico do servidor.
     *
     * @param ex exceção a inspecionar (aceita {@code null})
     * @return {@code true} quando o padrão sugere rejeição do certificado
     *         de cliente pelo servidor
     */
    static boolean isLikelyClientCertificateRejection(final @Nullable Throwable ex) {
        for (Throwable t = ex; t != null; t = t.getCause()) {
            if (t instanceof java.security.cert.CertificateException
                    || t instanceof java.security.cert.CertPathBuilderException
                    || t instanceof java.security.cert.CertPathValidatorException) {
                // Cliente rejeitou o certificado do SERVIDOR (validação
                // local do trust anchor) — não é rejeição mTLS pelo servidor.
                return false;
            }
        }
        for (Throwable t = ex; t != null; t = t.getCause()) {
            if (t instanceof AEADBadTagException || t instanceof SSLHandshakeException) {
                return true;
            }
            if (t instanceof SSLException) {
                final String msg = t.getMessage();
                if (msg != null && msg.toLowerCase(Locale.ROOT).contains("bad_record_mac")) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Materializa uma resposta HTTP de erro (status ≠ 200) em
     * {@link SmartTokenException}, registrando o log adequado: WARN para
     * rate limit (HTTP 429, sem retry automático) e ERROR para os demais.
     *
     * @param response resposta recebida do servidor de autorização
     * @param trace    contexto de trace W3C enviado na requisição
     * @return exceção pronta para ser lançada pelo chamador
     */
    SmartTokenException httpFailure(final HttpResponse<String> response, final TraceContext trace) {
        final int statusCode = response.statusCode();
        if (statusCode == HTTP_TOO_MANY_REQUESTS) {
            LOG.warn("Rate limit (HTTP 429) para clientId={} traceId={} — sem retry automático",
                    clientId, trace.traceId());
        } else {
            LOG.error("Falha ao obter token: HTTP {} para clientId={} traceId={}",
                    statusCode, clientId, trace.traceId());
        }
        return new SmartTokenException(buildHttpErrorMessage(statusCode, response, trace));
    }

    /**
     * Monta a mensagem de erro para resposta HTTP ≠ 200: status, trace-id
     * enviado na requisição (correlaciona com o {@code correlation-id} da
     * plataforma), valor de {@code Retry-After} quando presente (apenas
     * diagnóstico — nenhuma resposta HTTP recebida sofre retry automático;
     * a decisão de aguardar e reenviar é do chamador) e corpo sanitizado.
     *
     * @param statusCode status HTTP da resposta
     * @param response   resposta recebida do servidor de autorização
     * @param trace      contexto de trace W3C enviado na requisição
     * @return mensagem de erro pronta para {@link SmartTokenException}
     */
    private static String buildHttpErrorMessage(
            final int statusCode, final HttpResponse<String> response, final TraceContext trace) {
        final String retryAfter = response.headers().firstValue("Retry-After")
                .map(value -> " (Retry-After: " + value.trim() + ")")
                .orElse("");
        final String hint = statusCode == HTTP_TOO_MANY_REQUESTS
                ? " Rate limit atingido; a decisão de aguardar e reenviar é do chamador."
                : "";
        return "Falha ao obter token: HTTP " + statusCode + retryAfter
                + " (traceId=" + trace.traceId() + ")"
                + " — " + sanitizeErrorResponse(response.body()) + hint;
    }

    /**
     * Sanitiza a resposta de erro para evitar vazamento de tokens em logs.
     *
     * <p>
     * A redação de tokens é aplicada <strong>antes</strong> do truncamento,
     * garantindo que nenhum token apareça mesmo em respostas longas.
     * </p>
     *
     * @param responseBody corpo da resposta HTTP (aceita {@code null})
     * @return resposta sanitizada
     */
    static String sanitizeErrorResponse(final @Nullable String responseBody) {
        if (responseBody == null) {
            return "<empty>";
        }
        // Remove possíveis tokens do erro (JSON e form-encoded) ANTES de truncar
        final String redacted = responseBody
                .replaceAll("(\"(?:access_token|token)\")\\s*:\\s*\"[^\"]*\"", "$1:\"[REDACTED]\"")
                .replaceAll("(access_token|token)=[^&\\s]*", "$1=[REDACTED]");
        if (redacted.length() > MAX_ERROR_RESPONSE_LENGTH) {
            return redacted.substring(0, MAX_ERROR_RESPONSE_LENGTH) + "...";
        }
        return redacted;
    }
}
