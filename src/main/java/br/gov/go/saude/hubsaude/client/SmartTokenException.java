/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.hubsaude.client;

import org.jspecify.annotations.Nullable;

/**
 * Exceção de domínio para operações utilitárias do {@link SmartTokenClient}.
 *
 * <p>
 * Sinaliza falhas de parsing de PEM/JSON ou respostas inesperadas do
 * servidor de autorização, preservando a causa original para facilitar o diagnóstico.
 * </p>
 */
public class SmartTokenException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Cria a exceção apenas com a mensagem.
     *
     * @param message descrição da falha
     */
    public SmartTokenException(final String message) {
        super(message);
    }

    /**
     * Cria a exceção preservando a causa original.
     *
     * @param message descrição da falha
     * @param cause   exceção original que motivou esta; {@code null} quando
     *                não há causa a preservar
     */
    public SmartTokenException(final String message, final @Nullable Throwable cause) {
        super(message, cause);
    }
}
