/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.hubsaude.client;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Testes unitários para {@link SigningException}.
 */
class SigningExceptionTest {

    @Test
    void deveCriarExcecaoComMensagem() {
        final SigningException exception = new SigningException("Erro de teste");

        assertThat(exception.getMessage()).isEqualTo("Erro de teste");
        assertThat(exception.getCause()).isNull();
    }

    @Test
    void deveCriarExcecaoComMensagemECausa() {
        final Throwable causa = new RuntimeException("causa original");
        final SigningException exception = new SigningException("Erro de teste", causa);

        assertThat(exception.getMessage()).isEqualTo("Erro de teste");
        assertThat(exception.getCause()).isSameAs(causa);
    }

    @Test
    void deveSerRuntimeException() {
        final SigningException exception = new SigningException("Erro");

        assertThat(exception).isInstanceOf(RuntimeException.class);
    }
}
