/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.hubsaude.client;

import org.jspecify.annotations.Nullable;

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
     * @param cause   exceção original que causou a falha; {@code null}
     *                quando não há causa a preservar
     */
    public SigningException(final String message, final @Nullable Throwable cause) {
        super(message, cause);
    }
}
