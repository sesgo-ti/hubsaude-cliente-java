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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import br.gov.go.saude.hubsaude.client.SmartTokenClient.TokenResponse;

/**
 * Cache de tokens por scope com lock striping para single-flight de
 * renovação: no máximo uma requisição HTTP em voo por scope e uma janela LRU
 * limitada de tokens (issues #731 e #1804).
 *
 * <p>
 * Colaborador interno do {@link SmartTokenClient} (issue #1032): concentra a
 * política de cache (validade com margem de renovação, invalidação) e a
 * seleção de locks por scope que antes inflavam a complexidade da classe
 * principal. Não faz parte da API pública da biblioteca.
 * </p>
 *
 * <p>
 * Os scopes recebidos por esta classe devem estar <strong>normalizados</strong>
 * ({@code trim}; {@code null} → string vazia) — responsabilidade do chamador.
 * </p>
 */
final class TokenCacheStrategy {

    /**
     * Logger compartilhado com {@link SmartTokenClient}: este colaborador é
     * detalhe interno de implementação e o contrato de observabilidade
     * (filtros de log por nome da classe pública) deve permanecer estável.
     */
    private static final Logger LOG = LoggerFactory.getLogger(SmartTokenClient.class);

    /**
     * Quantidade fixa de locks usados no striping de {@link #scopeLocks}.
     * Limita a memória a O(1) — constante, independentemente do número
     * de scopes distintos (ver issue #731).
     */
    private static final int SCOPE_LOCK_STRIPES = 32;

    /** Indica se o cache está habilitado. */
    private final boolean enabled;

    /** Margem em segundos para renovar o token antes da expiração. */
    private final int marginSeconds;

    /** Identificador do cliente, usado nas mensagens de log. */
    private final String clientId;

    /** Fonte de tempo, substituível para testes determinísticos. */
    private final Clock clock;

    /** Cache LRU de tokens por scope, sincronizado e com teto exato. */
    private final Map<String, CachedToken> tokenCache;

    /**
     * Locks (lock striping) para evitar múltiplas renovações simultâneas
     * do mesmo scope.
     *
     * <p>
     * Cada scope é mapeado de forma determinística a um dos
     * {@link #SCOPE_LOCK_STRIPES} locks via hash. Scopes distintos podem
     * compartilhar o mesmo lock (contenção falsa ocasional), mas o
     * single-flight por scope é preservado e a memória é fixa —
     * independentemente da quantidade de scopes distintos usados ao longo
     * da vida do cliente.
     * </p>
     */
    private final ReentrantLock[] scopeLocks;

    /**
     * Cria a estratégia de cache.
     *
     * @param enabled       se {@code true}, tokens são cacheados por scope
     * @param marginSeconds margem em segundos antes da expiração; deve ser
     *                      positiva (normalização a cargo do chamador)
     * @param clientId      identificador do cliente (para logs)
     */
    TokenCacheStrategy(final boolean enabled, final int marginSeconds, final String clientId) {
        this(enabled, marginSeconds, clientId, SmartTokenClient.DEFAULT_TOKEN_CACHE_MAX_ENTRIES);
    }

    /**
     * Cria a estratégia com capacidade configurável.
     *
     * @param enabled       se {@code true}, tokens são cacheados por scope
     * @param marginSeconds margem em segundos antes da expiração
     * @param clientId      identificador do cliente
     * @param maxEntries    quantidade máxima de scopes retidos
     */
    TokenCacheStrategy(
            final boolean enabled,
            final int marginSeconds,
            final String clientId,
            final int maxEntries) {
        this(enabled, marginSeconds, clientId, maxEntries, Clock.systemUTC());
    }

    /**
     * Cria a estratégia com capacidade e relógio configuráveis.
     *
     * @param enabled       se {@code true}, tokens são cacheados por scope
     * @param marginSeconds margem em segundos antes da expiração
     * @param clientId      identificador do cliente
     * @param maxEntries    quantidade máxima de scopes retidos
     * @param clock         fonte de tempo
     */
    TokenCacheStrategy(
            final boolean enabled,
            final int marginSeconds,
            final String clientId,
            final int maxEntries,
            final Clock clock) {
        if (maxEntries <= 0) {
            throw new IllegalArgumentException("maxEntries deve ser positivo: " + maxEntries);
        }
        this.enabled = enabled;
        this.marginSeconds = marginSeconds;
        this.clientId = Objects.requireNonNull(clientId, "clientId não pode ser null");
        this.clock = Objects.requireNonNull(clock, "clock não pode ser null");
        this.tokenCache = Collections.synchronizedMap(new LruTokenCache(maxEntries));
        this.scopeLocks = new ReentrantLock[SCOPE_LOCK_STRIPES];
        for (int i = 0; i < SCOPE_LOCK_STRIPES; i++) {
            this.scopeLocks[i] = new ReentrantLock();
        }
    }

    /**
     * Retorna o token em cache para o scope, quando o cache está habilitado
     * e o token ainda é válido; caso contrário, {@code null}.
     *
     * @param normalizedScope scope normalizado
     * @return resposta reconstruída do cache ou {@code null}
     */
    @Nullable TokenResponse cachedResponseIfValid(final String normalizedScope) {
        if (!enabled) {
            return null;
        }
        final CachedToken cached = tokenCache.get(normalizedScope);
        if (cached != null && cached.isValid(marginSeconds, clock.instant())) {
            LOG.debug("Retornando token em cache para clientId={} scope={}",
                    clientId, normalizedScope);
            return fromCache(cached);
        }
        if (cached != null) {
            tokenCache.remove(normalizedScope, cached);
        }
        return null;
    }

    /**
     * Retorna o lock associado ao scope via striping: o hash do scope
     * seleciona um dos {@link #SCOPE_LOCK_STRIPES} locks fixos. O mesmo
     * scope sempre mapeia para o mesmo lock, preservando o single-flight
     * por scope; scopes distintos podem compartilhar um lock.
     *
     * @param normalizedScope scope normalizado
     * @return lock associado ao scope
     */
    ReentrantLock lockFor(final String normalizedScope) {
        final int index = Math.floorMod(normalizedScope.hashCode(), SCOPE_LOCK_STRIPES);
        return scopeLocks[index];
    }

    /**
     * Armazena o token no cache quando habilitado; caso contrário, no-op.
     *
     * @param normalizedScope scope normalizado
     * @param tokenResponse   resposta recém-obtida do token endpoint
     */
    void store(final String normalizedScope, final TokenResponse tokenResponse) {
        if (!enabled) {
            return;
        }
        final Instant expiresAt = clock.instant().plusSeconds(tokenResponse.expiresIn());
        tokenCache.put(normalizedScope, new CachedToken(tokenResponse.accessToken(), expiresAt));
        LOG.debug("Token cacheado para clientId={} scope={} expiresIn={}s",
                clientId, normalizedScope, tokenResponse.expiresIn());
    }

    /** Invalida o cache de tokens de todos os scopes. */
    void invalidateAll() {
        tokenCache.clear();
        LOG.info("Cache de tokens invalidado para clientId={}", clientId);
    }

    /**
     * Invalida o cache para um scope específico.
     *
     * @param normalizedScope scope normalizado cujo token deve ser invalidado
     */
    void invalidate(final String normalizedScope) {
        tokenCache.remove(normalizedScope);
        LOG.info("Cache invalidado para clientId={} scope={}", clientId, normalizedScope);
    }

    /**
     * Retorna a quantidade de entradas retidas para testes do teto.
     *
     * @return tamanho atual do cache
     */
    int size() {
        return tokenCache.size();
    }

    /**
     * Reconstrói uma {@link TokenResponse} a partir de um token em cache.
     * O corpo JSON original não é preservado em cache, portanto
     * {@code rawJson} é {@code null}.
     *
     * @param cached token em cache
     * @return resposta reconstruída, sem o JSON cru
     */
    private TokenResponse fromCache(final CachedToken cached) {
        final long remaining = Duration.between(clock.instant(), cached.expiresAt()).getSeconds();
        return new TokenResponse(cached.accessToken(), (int) Math.max(0, remaining), null);
    }

    /**
     * Representa um token em cache com seu tempo de expiração.
     *
     * @param accessToken token de acesso cacheado
     * @param expiresAt   instante de expiração do token
     */
    record CachedToken(String accessToken, Instant expiresAt) {
        /**
         * Verifica a validade usando o relógio do sistema.
         *
         * @param marginSeconds segundos de margem antes da expiração
         * @return true se o token ainda pode ser usado
         */
        boolean isValid(final int marginSeconds) {
            return isValid(marginSeconds, Instant.now());
        }

        /**
         * Verifica se o token ainda é válido considerando a margem.
         *
         * @param marginSeconds segundos de margem antes da expiração
         * @param now instante corrente
         * @return true se o token ainda pode ser usado
         */
        boolean isValid(final int marginSeconds, final Instant now) {
            return now.plusSeconds(marginSeconds).isBefore(expiresAt);
        }

        /**
         * Representação textual com o token mascarado, evitando exposição
         * acidental em logs.
         *
         * @return string sem o valor do access token
         */
        @Override
        public String toString() {
            return "CachedToken[accessToken=[REDACTED], expiresAt=" + expiresAt + "]";
        }
    }

    /** Janela LRU de capacidade fixa. */
    private static final class LruTokenCache extends LinkedHashMap<String, CachedToken> {

        private static final long serialVersionUID = 1L;
        private static final float LOAD_FACTOR = 0.75f;

        private final int capacity;

        LruTokenCache(final int capacity) {
            super((int) (capacity / LOAD_FACTOR) + 1, LOAD_FACTOR, true);
            this.capacity = capacity;
        }

        @Override
        protected boolean removeEldestEntry(final Map.Entry<String, CachedToken> eldest) {
            return size() > capacity;
        }
    }
}
