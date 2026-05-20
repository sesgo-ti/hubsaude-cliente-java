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

import org.junit.jupiter.api.Test;
import br.gov.go.saude.hubsaude.core.rastreabilidade.Requirement;
import br.gov.go.saude.hubsaude.core.rastreabilidade.Requirements;

/**
 * Testes unitários para {@link SigningException}.
 */
@Requirements({@Requirement("A8"), @Requirement("C11")})
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
