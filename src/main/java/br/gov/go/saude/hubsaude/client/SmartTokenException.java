/*
 * Copyright (c) 2026 SES-GO / UFG
 * Todos os direitos reservados.
 */

package br.gov.go.saude.hubsaude.simulador.client;

/**
 * Exceção de domínio para operações utilitárias do {@link SmartTokenClient}.
 *
 * <p>
 * Sinaliza falhas de parsing de PEM/JSON ou respostas inesperadas do
 * simulador, preservando a causa original para facilitar o diagnóstico.
 * </p>
 */
public class SmartTokenException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public SmartTokenException(final String message) {
        super(message);
    }

    public SmartTokenException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
