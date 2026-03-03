/*
 * Copyright (c) 2026 SES-GO / UFG
 * Todos os direitos reservados.
 */

package br.gov.go.saude.hubsaude.client;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

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
