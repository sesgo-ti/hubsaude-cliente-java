/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.hubsaude.client;

import java.io.IOException;
import java.nio.file.Path;
import java.security.PrivateKey;

import org.jspecify.annotations.Nullable;

/**
 * Agrupa a configuração de assinatura do client_assertion JWT do
 * {@link SmartTokenClientBuilder} e resolve a {@link SigningStrategy}
 * efetiva a partir dela.
 *
 * <p>
 * Colaborador interno do {@link SmartTokenClientBuilder}, extraído para
 * reduzir o número de campos e a complexidade de {@code build()}
 * (issue #1032). Não faz parte da API pública da biblioteca: os valores
 * são definidos exclusivamente pelos métodos fluentes do builder.
 * </p>
 *
 * <p>
 * As fontes de assinatura são mutuamente exclusivas: ou uma
 * {@link SigningStrategy} própria (HSM, cofre de segredos) ou uma chave
 * privada em arquivo PEM, da qual a estratégia é derivada conforme o
 * algoritmo JWT configurado.
 * </p>
 */
final class SigningSettings {

    /** Caminho da chave privada PEM; exclusivo com {@code signingStrategy}. */
    private @Nullable Path privateKeyPem;

    /** Senha da chave privada PEM; zerada por {@link #clearSecrets()}. */
    private char @Nullable [] privateKeyPassword;

    /** Estratégia de assinatura própria; exclusiva com {@code privateKeyPem}. */
    private @Nullable SigningStrategy signingStrategy;

    /** Algoritmo JWT do client_assertion (padrão: RS384). */
    private String jwtAlgorithm = SmartTokenClient.DEFAULT_JWT_ALGORITHM;

    /** Identificador da chave ({@code kid}) no header do JWT; opcional. */
    private @Nullable String keyId;

    /**
     * Define o caminho da chave privada PEM.
     *
     * @param privateKeyPem caminho absoluto da chave
     */
    void setPrivateKeyPem(final Path privateKeyPem) {
        this.privateKeyPem = privateKeyPem;
    }

    /**
     * Define a senha da chave privada PEM.
     *
     * @param privateKeyPassword senha; o array não é copiado e é zerado
     *                           por {@link #clearSecrets()}
     */
    @SuppressWarnings("PMD.UseVarargs")
    void setPrivateKeyPassword(final char @Nullable [] privateKeyPassword) {
        this.privateKeyPassword = privateKeyPassword;
    }

    /**
     * Define a estratégia de assinatura diretamente (HSM, cofre etc.).
     *
     * @param signingStrategy estratégia de assinatura configurada
     */
    void setSigningStrategy(final SigningStrategy signingStrategy) {
        this.signingStrategy = signingStrategy;
    }

    /**
     * Define o algoritmo JWT do client_assertion.
     *
     * @param jwtAlgorithm nome do algoritmo JWT (ex.: RS384, ES384)
     */
    void setJwtAlgorithm(final String jwtAlgorithm) {
        this.jwtAlgorithm = jwtAlgorithm;
    }

    /**
     * Define o identificador da chave ({@code kid}) do header do JWT.
     *
     * @param keyId identificador da chave registrado junto ao servidor
     */
    void setKeyId(final String keyId) {
        this.keyId = keyId;
    }

    /**
     * Obtém o algoritmo JWT configurado.
     *
     * @return nome do algoritmo JWT (ex.: RS384)
     */
    String getJwtAlgorithm() {
        return jwtAlgorithm;
    }

    /**
     * Obtém o identificador da chave ({@code kid}) configurado.
     *
     * @return identificador da chave ou {@code null} quando não definido
     */
    @Nullable String getKeyId() {
        return keyId;
    }

    /**
     * Resolve a estratégia de assinatura efetiva, validando a exclusividade
     * mútua entre {@code signingStrategy} e {@code privateKeyPem}.
     *
     * <p>
     * Quando a chave vem de arquivo PEM, a estratégia é criada a partir do
     * algoritmo JWT configurado, incluindo os parâmetros PSS quando
     * aplicável (PS256/PS384/PS512), e a chave carregada fica disponível
     * para uso em mTLS.
     * </p>
     *
     * @return estratégia efetiva e, quando aplicável, a chave privada
     *         carregada do PEM
     * @throws IOException           se o arquivo PEM não puder ser lido
     * @throws IllegalStateException se ambas ou nenhuma das fontes de
     *                               assinatura forem definidas
     */
    Resolved resolve() throws IOException {
        if (signingStrategy != null) {
            if (privateKeyPem != null) {
                throw new IllegalStateException(
                        "Defina signingStrategy OU privateKeyPem, não ambos");
            }
            return new Resolved(signingStrategy, null);
        }
        if (privateKeyPem == null) {
            throw new IllegalStateException(
                    "É obrigatório definir signingStrategy ou privateKeyPem");
        }
        final PrivateKey clientKey = PemLoader.loadPrivateKey(privateKeyPem, privateKeyPassword);
        // Cria a estratégia a partir do algoritmo JWT, incluindo os
        // parâmetros PSS quando aplicável (PS256/PS384/PS512)
        return new Resolved(
                SigningStrategyFactory.fromPrivateKeyForJwt(clientKey, jwtAlgorithm),
                clientKey);
    }

    /**
     * Zera e descarta a senha da chave privada PEM, minimizando a exposição
     * do segredo em memória após a construção do cliente.
     */
    void clearSecrets() {
        PemLoader.clearPassword(privateKeyPassword);
        privateKeyPassword = null;
    }

    /**
     * Resultado da resolução da configuração de assinatura.
     *
     * @param strategy  estratégia de assinatura efetiva do client_assertion
     * @param clientKey chave privada carregada do PEM, disponível para mTLS;
     *                  {@code null} quando a estratégia foi fornecida
     *                  diretamente (HSM, cofre)
     */
    record Resolved(SigningStrategy strategy, @Nullable PrivateKey clientKey) {
    }
}
