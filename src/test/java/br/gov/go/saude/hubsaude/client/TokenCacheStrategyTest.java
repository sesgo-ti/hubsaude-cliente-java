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

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import br.gov.go.saude.hubsaude.client.SmartTokenClient.TokenResponse;

/**
 * Testes do colaborador {@link TokenCacheStrategy}: política de cache por
 * scope (validade com margem, invalidação) e lock striping para
 * single-flight de renovação, extraídos do {@code SmartTokenClient} na
 * issue #1032.
 */
class TokenCacheStrategyTest {

    private static final String CLIENT_ID = "cliente-teste";
    private static final String SCOPE = "system/Patient.rs";
    private static final int MARGIN_SECONDS = 30;

    @Nested
    @DisplayName("cache habilitado")
    class CacheHabilitado {

        private final TokenCacheStrategy cache =
                new TokenCacheStrategy(true, MARGIN_SECONDS, CLIENT_ID);

        @Test
        @DisplayName("retorna null quando não há token para o scope")
        void retornaNullSemEntrada() {
            assertThat(cache.cachedResponseIfValid(SCOPE)).isNull();
        }

        @Test
        @DisplayName("serve token armazenado, sem o JSON cru")
        void serveTokenArmazenado() {
            cache.store(SCOPE, new TokenResponse("tok-1", 3600, "{\"raw\":true}"));

            final TokenResponse cached = cache.cachedResponseIfValid(SCOPE);

            assertThat(cached).isNotNull();
            assertThat(cached.accessToken()).isEqualTo("tok-1");
            assertThat(cached.rawJson()).isNull();
            assertThat(cached.expiresIn()).isBetween(3500, 3600);
        }

        @Test
        @DisplayName("não serve token dentro da margem de renovação")
        void naoServeTokenDentroDaMargem() {
            // Expira em 10s < margem de 30s: deve forçar renovação
            cache.store(SCOPE, new TokenResponse("tok-quase-expirado", 10, null));

            assertThat(cache.cachedResponseIfValid(SCOPE)).isNull();
        }

        @Test
        @DisplayName("invalidate remove somente o scope informado")
        void invalidateRemoveScope() {
            cache.store(SCOPE, new TokenResponse("tok-1", 3600, null));
            cache.store("outro/scope", new TokenResponse("tok-2", 3600, null));

            cache.invalidate(SCOPE);

            assertThat(cache.cachedResponseIfValid(SCOPE)).isNull();
            assertThat(cache.cachedResponseIfValid("outro/scope")).isNotNull();
        }

        @Test
        @DisplayName("invalidateAll remove todos os scopes")
        void invalidateAllRemoveTudo() {
            cache.store(SCOPE, new TokenResponse("tok-1", 3600, null));
            cache.store("outro/scope", new TokenResponse("tok-2", 3600, null));

            cache.invalidateAll();

            assertThat(cache.cachedResponseIfValid(SCOPE)).isNull();
            assertThat(cache.cachedResponseIfValid("outro/scope")).isNull();
        }

        @Test
        @DisplayName("remove entrada quando o token não é mais válido")
        void removeEntradaExpirada() {
            final Clock clock = Clock.fixed(Instant.parse("2026-08-01T12:00:00Z"), ZoneOffset.UTC);
            final TokenCacheStrategy expiring =
                    new TokenCacheStrategy(true, MARGIN_SECONDS, CLIENT_ID, 2, clock);
            expiring.store(SCOPE, new TokenResponse("tok-expirado", 10, null));

            assertThat(expiring.cachedResponseIfValid(SCOPE)).isNull();
            assertThat(expiring.size()).isZero();
        }

        @Test
        @DisplayName("não cresce além do teto e preserva a entrada mais recentemente acessada")
        void limitaCachePorLru() {
            final TokenCacheStrategy bounded =
                    new TokenCacheStrategy(true, MARGIN_SECONDS, CLIENT_ID, 2);
            bounded.store("scope-1", new TokenResponse("tok-1", 3600, null));
            bounded.store("scope-2", new TokenResponse("tok-2", 3600, null));
            bounded.cachedResponseIfValid("scope-1");

            bounded.store("scope-3", new TokenResponse("tok-3", 3600, null));

            assertThat(bounded.size()).isEqualTo(2);
            assertThat(bounded.cachedResponseIfValid("scope-1")).isNotNull();
            assertThat(bounded.cachedResponseIfValid("scope-2")).isNull();
            assertThat(bounded.cachedResponseIfValid("scope-3")).isNotNull();
        }

        @Test
        @DisplayName("mantém o teto sob inserções concorrentes")
        void limitaCacheSobConcorrencia() throws InterruptedException {
            final int capacity = 32;
            final int threads = 8;
            final TokenCacheStrategy bounded =
                    new TokenCacheStrategy(true, MARGIN_SECONDS, CLIENT_ID, capacity);
            final CountDownLatch start = new CountDownLatch(1);
            final CountDownLatch done = new CountDownLatch(threads);
            try (var executor = Executors.newFixedThreadPool(threads)) {
                for (int thread = 0; thread < threads; thread++) {
                    final int offset = thread * 100;
                    executor.submit(() -> {
                        try {
                            start.await();
                            for (int i = 0; i < 100; i++) {
                                bounded.store("scope-" + (offset + i), new TokenResponse("tok", 3600, null));
                            }
                        } catch (InterruptedException ex) {
                            Thread.currentThread().interrupt();
                        } finally {
                            done.countDown();
                        }
                    });
                }
                start.countDown();
                assertThat(done.await(10, TimeUnit.SECONDS)).isTrue();
            }

            assertThat(bounded.size()).isEqualTo(capacity);
        }

        @Test
        @DisplayName("rejeita teto não positivo")
        void rejeitaCapacidadeInvalida() {
            assertThatThrownBy(() -> new TokenCacheStrategy(true, MARGIN_SECONDS, CLIENT_ID, 0))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("maxEntries");
        }
    }

    @Nested
    @DisplayName("cache desabilitado")
    class CacheDesabilitado {

        private final TokenCacheStrategy cache =
                new TokenCacheStrategy(false, MARGIN_SECONDS, CLIENT_ID);

        @Test
        @DisplayName("store é no-op e nada é servido do cache")
        void storeEhNoOp() {
            cache.store(SCOPE, new TokenResponse("tok-1", 3600, null));

            assertThat(cache.cachedResponseIfValid(SCOPE)).isNull();
        }
    }

    @Nested
    @DisplayName("lock striping")
    class LockStriping {

        private final TokenCacheStrategy cache =
                new TokenCacheStrategy(true, MARGIN_SECONDS, CLIENT_ID);

        @Test
        @DisplayName("o mesmo scope sempre mapeia para o mesmo lock")
        void mesmoScopeMesmoLock() {
            assertThat(cache.lockFor(SCOPE)).isSameAs(cache.lockFor(SCOPE));
        }

        @Test
        @DisplayName("scopes de hash distinto podem mapear para locks distintos")
        void scopesDistintosPodemTerLocksDistintos() {
            // Com 32 stripes, dois scopes com hash % 32 distintos não colidem
            assertThat(cache.lockFor("a")).isNotSameAs(cache.lockFor("b"));
        }
    }

    @Nested
    @DisplayName("CachedToken")
    class CachedTokenRecord {

        @Test
        @DisplayName("toString não expõe o access token")
        void toStringNaoExpoeToken() {
            final var token = new TokenCacheStrategy.CachedToken(
                    "super-secreto", java.time.Instant.now().plusSeconds(60));

            assertThat(token.toString())
                    .contains("[REDACTED]")
                    .doesNotContain("super-secreto");
        }
    }
}
