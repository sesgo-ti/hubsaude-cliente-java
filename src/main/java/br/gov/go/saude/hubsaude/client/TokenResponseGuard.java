/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.hubsaude.client;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tools.jackson.databind.JsonNode;

/**
 * Salvaguardas de sanidade para a resposta do token endpoint (issue #730):
 * validação/normalização do campo {@code expires_in} e leitura do corpo da
 * resposta HTTP com teto de tamanho.
 *
 * <p>Ambas as proteções mitigam um servidor de autorização comprometido ou
 * malicioso: um {@code expires_in} adulterado não pode reter tokens no cache
 * além do teto de sanidade, e uma resposta gigante não pode consumir memória
 * sem limite.</p>
 */
final class TokenResponseGuard {

    /**
     * Valor assumido para {@code expires_in} (segundos) quando ausente na
     * resposta — campo opcional na RFC 6749 §5.1; 1 hora é o valor usual
     * em servidores de autorização SMART.
     */
    static final int DEFAULT_EXPIRES_IN_SECONDS = 3600;

    /**
     * Teto de sanidade para {@code expires_in} (24h). Valores acima são
     * normalizados antes de alimentar o cache de tokens.
     */
    static final int MAX_EXPIRES_IN_SECONDS = 86_400;

    /**
     * Limite (bytes) do corpo da resposta do token endpoint: 1 MiB.
     * Respostas legítimas têm poucos KiB; acima disso a leitura é
     * abortada com erro claro.
     */
    static final long MAX_RESPONSE_BODY_BYTES = 1_048_576L;

    private static final Logger LOG = LoggerFactory.getLogger(TokenResponseGuard.class);

    private TokenResponseGuard() {
        // Classe utilitária — não instanciável.
    }

    /**
     * Aplica a política de sanidade ao campo {@code expires_in}. Regras
     * explícitas:
     *
     * <ul>
     *   <li><strong>Ausente</strong> — assume
     *       {@link #DEFAULT_EXPIRES_IN_SECONDS} (1 hora), conforme prática
     *       usual quando o servidor omite o campo (RFC 6749 §5.1);</li>
     *   <li><strong>Zero, negativo ou não numérico</strong> — rejeitado com
     *       {@link SmartTokenException}: um token já expirado (ou com
     *       validade sem sentido) indica resposta malformada e nunca deve
     *       alimentar o cache;</li>
     *   <li><strong>Acima de {@link #MAX_EXPIRES_IN_SECONDS}</strong> (24h)
     *       — normalizado para o teto, com log de aviso: o token continua
     *       utilizável, mas o cache não retém entradas além do limite de
     *       sanidade.</li>
     * </ul>
     *
     * @param node nó raiz da resposta JSON do token endpoint
     * @return valor saneado de {@code expires_in}, em segundos
     * @throws SmartTokenException quando o valor é zero, negativo ou não
     *                             numérico
     */
    static int sanitizeExpiresIn(final JsonNode node) {
        if (!node.has("expires_in")) {
            LOG.debug("Resposta sem 'expires_in' — assumindo padrão de {}s",
                    DEFAULT_EXPIRES_IN_SECONDS);
            return DEFAULT_EXPIRES_IN_SECONDS;
        }
        final long value = node.get("expires_in").asLong(0L);
        if (value <= 0) {
            throw new SmartTokenException(
                    "'expires_in' inválido na resposta do token endpoint: "
                            + node.get("expires_in")
                            + " (esperado inteiro em 0 < x <= " + MAX_EXPIRES_IN_SECONDS + ")");
        }
        if (value > MAX_EXPIRES_IN_SECONDS) {
            LOG.warn("'expires_in'={}s acima do teto de sanidade — normalizando para {}s",
                    value, MAX_EXPIRES_IN_SECONDS);
            return MAX_EXPIRES_IN_SECONDS;
        }
        return (int) value;
    }

    /**
     * Cria um {@link HttpResponse.BodyHandler} que lê o corpo como String
     * UTF-8, impondo o teto de {@code maxBytes}: rejeita de imediato
     * respostas cujo {@code Content-Length} declarado excede o limite e,
     * para respostas sem esse cabeçalho (ex.: transferência chunked),
     * aborta a leitura assim que os bytes recebidos ultrapassam o teto.
     *
     * @param maxBytes limite máximo do corpo, em bytes
     * @return body handler com leitura limitada
     */
    static HttpResponse.BodyHandler<String> boundedStringBodyHandler(final long maxBytes) {
        return responseInfo -> {
            final long contentLength = responseInfo.headers()
                    .firstValueAsLong("Content-Length").orElse(-1L);
            if (contentLength > maxBytes) {
                throw bodyLimitExceeded(contentLength, maxBytes);
            }
            return new BoundedStringBodySubscriber(maxBytes);
        };
    }

    /**
     * Constrói a exceção padronizada de estouro do limite do corpo.
     *
     * @param received bytes recebidos ou declarados (Content-Length)
     * @param maxBytes teto configurado
     * @return exceção com mensagem clara
     */
    private static SmartTokenException bodyLimitExceeded(final long received, final long maxBytes) {
        return new SmartTokenException(
                "Resposta do token endpoint excede o limite de " + maxBytes
                        + " bytes (recebido/declarado: " + received + " bytes)");
    }

    /**
     * Desembrulha a violação do limite de corpo quando o {@link HttpClient}
     * a reporta envolvida em {@link IOException}; caso contrário devolve a
     * exceção original para tratamento normal (retry, heurísticas de TLS).
     *
     * @param ex exceção lançada por {@code HttpClient.send}
     * @return a própria exceção, quando não relacionada ao limite de corpo
     * @throws SmartTokenException quando a causa raiz é o estouro do limite
     */
    static IOException unwrapBodyLimitViolation(final IOException ex) {
        for (Throwable t = ex; t != null; t = t.getCause()) {
            if (t instanceof SmartTokenException ste) {
                throw ste;
            }
        }
        return ex;
    }

    /**
     * {@link HttpResponse.BodySubscriber} que delega a
     * {@link HttpResponse.BodySubscribers#ofString} contabilizando os bytes
     * recebidos; ao ultrapassar o teto, cancela a assinatura e completa o
     * corpo com {@link SmartTokenException} clara.
     */
    private static final class BoundedStringBodySubscriber
            implements HttpResponse.BodySubscriber<String> {

        private final HttpResponse.BodySubscriber<String> delegate =
                HttpResponse.BodySubscribers.ofString(StandardCharsets.UTF_8);
        private final long maxBytes;
        private long received;
        private boolean failed;
        private Flow.@Nullable Subscription subscription;

        BoundedStringBodySubscriber(final long maxBytes) {
            this.maxBytes = maxBytes;
        }

        @Override
        public CompletionStage<String> getBody() {
            return delegate.getBody();
        }

        @Override
        public void onSubscribe(final Flow.Subscription sub) {
            this.subscription = sub;
            delegate.onSubscribe(sub);
        }

        @Override
        public void onNext(final List<ByteBuffer> item) {
            if (failed) {
                return;
            }
            for (final ByteBuffer buffer : item) {
                received += buffer.remaining();
            }
            if (received > maxBytes) {
                failed = true;
                if (subscription != null) {
                    subscription.cancel();
                }
                delegate.onError(bodyLimitExceeded(received, maxBytes));
                return;
            }
            delegate.onNext(item);
        }

        @Override
        public void onError(final Throwable throwable) {
            if (!failed) {
                delegate.onError(throwable);
            }
        }

        @Override
        public void onComplete() {
            if (!failed) {
                delegate.onComplete();
            }
        }
    }
}
