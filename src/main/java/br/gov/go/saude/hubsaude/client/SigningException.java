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

/**
 * Exceção lançada quando ocorre falha durante operação de assinatura digital.
 *
 * <p>
 * Esta exceção é utilizada pela {@link SigningStrategy} para encapsular
 * erros criptográficos de forma consistente, independente da fonte da chave
 * (memória, HSM, Vault, etc.).
 * </p>
 *
 * @see SigningStrategy
 */
public class SigningException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Cria exceção com mensagem descritiva.
     *
     * @param message descrição do erro
     */
    public SigningException(final String message) {
        super(message);
    }

    /**
     * Cria exceção com mensagem e causa original.
     *
     * @param message descrição do erro
     * @param cause   exceção original que causou a falha
     */
    public SigningException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
