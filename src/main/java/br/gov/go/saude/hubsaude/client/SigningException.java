/*
 * Copyright (c) 2026 SES-GO / UFG
 * Todos os direitos reservados.
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
