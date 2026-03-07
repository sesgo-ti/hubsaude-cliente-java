/*
 * Copyright (c) 2026 SES-GO / UFG
 * Todos os direitos reservados.
 */

package br.gov.go.saude.hubsaude.client;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Testes unitários para {@link FaultToleranceConfig}.
 */
class FaultToleranceConfigTest {

    private static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(30);

    @Test
    void deveCriarConfigComValoresValidos() {
        var config = new FaultToleranceConfig(
                Duration.ofSeconds(5),
                Duration.ofSeconds(15),
                120,
                5
        );

        assertThat(config.connectTimeout()).isEqualTo(Duration.ofSeconds(5));
        assertThat(config.requestTimeout()).isEqualTo(Duration.ofSeconds(15));
        assertThat(config.assertionTtlSeconds()).isEqualTo(120);
        assertThat(config.maxRetries()).isEqualTo(5);
    }

    @Test
    void deveUsarPadraoQuandoAssertionTtlZero() {
        var config = new FaultToleranceConfig(
                DEFAULT_CONNECT_TIMEOUT,
                DEFAULT_REQUEST_TIMEOUT,
                0,
                3
        );

        assertThat(config.assertionTtlSeconds())
                .isEqualTo(SmartTokenClient.DEFAULT_ASSERTION_TTL_SECONDS);
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, -10, -100, Integer.MIN_VALUE})
    void deveUsarPadraoQuandoAssertionTtlNegativo(int ttl) {
        var config = new FaultToleranceConfig(
                DEFAULT_CONNECT_TIMEOUT,
                DEFAULT_REQUEST_TIMEOUT,
                ttl,
                3
        );

        assertThat(config.assertionTtlSeconds())
                .isEqualTo(SmartTokenClient.DEFAULT_ASSERTION_TTL_SECONDS);
    }

    @Test
    void deveUsarPadraoQuandoMaxRetriesZero() {
        var config = new FaultToleranceConfig(
                DEFAULT_CONNECT_TIMEOUT,
                DEFAULT_REQUEST_TIMEOUT,
                60,
                0
        );

        assertThat(config.maxRetries())
                .isEqualTo(SmartTokenClient.DEFAULT_MAX_RETRIES);
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, -5, -100, Integer.MIN_VALUE})
    void deveUsarPadraoQuandoMaxRetriesNegativo(int retries) {
        var config = new FaultToleranceConfig(
                DEFAULT_CONNECT_TIMEOUT,
                DEFAULT_REQUEST_TIMEOUT,
                60,
                retries
        );

        assertThat(config.maxRetries())
                .isEqualTo(SmartTokenClient.DEFAULT_MAX_RETRIES);
    }

    @Test
    void deveLancarExcecaoQuandoConnectTimeoutNull() {
        assertThatThrownBy(() -> new FaultToleranceConfig(
                null,
                DEFAULT_REQUEST_TIMEOUT,
                60,
                3
        ))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("connectTimeout");
    }

    @Test
    void deveLancarExcecaoQuandoRequestTimeoutNull() {
        assertThatThrownBy(() -> new FaultToleranceConfig(
                DEFAULT_CONNECT_TIMEOUT,
                null,
                60,
                3
        ))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("requestTimeout");
    }

    @Test
    void deveAceitarValoresLimite() {
        var config = new FaultToleranceConfig(
                Duration.ofMillis(1),
                Duration.ofMillis(1),
                1,
                1
        );

        assertThat(config.connectTimeout()).isEqualTo(Duration.ofMillis(1));
        assertThat(config.requestTimeout()).isEqualTo(Duration.ofMillis(1));
        assertThat(config.assertionTtlSeconds()).isEqualTo(1);
        assertThat(config.maxRetries()).isEqualTo(1);
    }

    @Test
    void deveAceitarValoresGrandes() {
        var config = new FaultToleranceConfig(
                Duration.ofHours(1),
                Duration.ofHours(2),
                3600,
                100
        );

        assertThat(config.connectTimeout()).isEqualTo(Duration.ofHours(1));
        assertThat(config.requestTimeout()).isEqualTo(Duration.ofHours(2));
        assertThat(config.assertionTtlSeconds()).isEqualTo(3600);
        assertThat(config.maxRetries()).isEqualTo(100);
    }

    @Test
    void deveSerImutavel() {
        var config = new FaultToleranceConfig(
                DEFAULT_CONNECT_TIMEOUT,
                DEFAULT_REQUEST_TIMEOUT,
                60,
                3
        );

        // Guarda referências para verificar que os getters retornam valores consistentes
        Duration connectTimeout1 = config.connectTimeout();
        Duration connectTimeout2 = config.connectTimeout();
        Duration requestTimeout1 = config.requestTimeout();
        Duration requestTimeout2 = config.requestTimeout();

        // Verifica que os getters retornam a mesma instância (Duration é imutável)
        assertThat(connectTimeout1).isSameAs(connectTimeout2);
        assertThat(requestTimeout1).isSameAs(requestTimeout2);

        // Primitivos são sempre consistentes
        assertThat(config.assertionTtlSeconds()).isEqualTo(60);
        assertThat(config.maxRetries()).isEqualTo(3);
    }

    @Test
    void valoresPadraoDevemSerConsistentesComSmartTokenClient() {
        assertThat(SmartTokenClient.DEFAULT_ASSERTION_TTL_SECONDS).isEqualTo(60);
        assertThat(SmartTokenClient.DEFAULT_MAX_RETRIES).isEqualTo(3);
        assertThat(Duration.ofSeconds(10)).isEqualTo(SmartTokenClient.DEFAULT_CONNECT_TIMEOUT);
        assertThat(Duration.ofSeconds(30)).isEqualTo(SmartTokenClient.DEFAULT_REQUEST_TIMEOUT);
    }
}


