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

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;

import org.jspecify.annotations.Nullable;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

/**
 * Implementação de {@link SigningStrategy} baseada em {@link PrivateKey}.
 *
 * <p>
 * Esta é a implementação central de assinatura, reutilizada por todas as
 * fontes de material criptográfico:
 * </p>
 * <ul>
 *   <li><strong>Chaves em memória:</strong> carregadas de arquivos PEM</li>
 *   <li><strong>HSM/PKCS#11:</strong> handle para chave no hardware</li>
 *   <li><strong>KeyStore:</strong> chaves em JKS/PKCS#12</li>
 * </ul>
 *
 * <h2>PKCS#11 e HSM</h2>
 * <p>
 * Quando utilizada com PKCS#11, o objeto {@link PrivateKey} fornecido é
 * um <em>handle</em> para a chave real no hardware — a chave nunca sai
 * do dispositivo. A assinatura é delegada ao HSM de forma transparente
 * através do {@link Provider} PKCS#11.
 * </p>
 *
 * <h2>Thread Safety</h2>
 * <p>
 * Esta classe é thread-safe. Cada chamada a {@link #sign(byte[])} cria
 * uma nova instância de {@link Signature}, evitando problemas de concorrência.
 * </p>
 *
 * <h2>Tamanho mínimo de chave</h2>
 * <p>
 * Chaves fracas são rejeitadas na construção (fail-fast): RSA exige módulo
 * de pelo menos 2048 bits e EC exige curva com campo de pelo menos 256 bits
 * (P-256), conforme NIST SP 800-57. Handles PKCS#11 opacos que não expõem os
 * parâmetros da chave não são validados.
 * </p>
 *
 * @see SigningStrategyFactory factory methods para criação
 */
public final class PrivateKeySigningStrategy implements SigningStrategy {

    /**
     * Algoritmo padrão (RS384 — concern client-assertion-contexto-ig.md
     * §3.2).
     */
    public static final String DEFAULT_ALGORITHM = "SHA384withRSA";

    private final PrivateKey privateKey;
    private final @Nullable Provider provider;
    private final String algorithm;
    private final @Nullable AlgorithmParameterSpec parameterSpec;

    /**
     * Cria estratégia com chave e algoritmo padrão
     * ({@value #DEFAULT_ALGORITHM}, correspondente a RS384).
     *
     * <p>
     * Utiliza o provider padrão da JVM para operações criptográficas.
     * </p>
     *
     * @param privateKey chave privada ou handle PKCS#11
     */
    public PrivateKeySigningStrategy(final PrivateKey privateKey) {
        this(privateKey, null, DEFAULT_ALGORITHM);
    }

    /**
     * Cria estratégia com chave e algoritmo específico.
     *
     * @param privateKey chave privada ou handle PKCS#11
     * @param algorithm  algoritmo de assinatura (ex: "SHA384withRSA")
     */
    public PrivateKeySigningStrategy(final PrivateKey privateKey, final String algorithm) {
        this(privateKey, null, algorithm);
    }

    /**
     * Cria estratégia completa com provider específico.
     *
     * <p>
     * Este construtor é necessário para PKCS#11, onde o provider deve
     * ser especificado para que a assinatura ocorra no hardware.
     * </p>
     *
     * @param privateKey chave privada ou handle PKCS#11
     * @param provider   provider criptográfico (null = padrão da JVM)
     * @param algorithm  algoritmo de assinatura
     */
    public PrivateKeySigningStrategy(
            final PrivateKey privateKey,
            final @Nullable Provider provider,
            final String algorithm) {
        this(privateKey, provider, algorithm, null);
    }

    /**
     * Cria estratégia completa com provider e parâmetros de algoritmo.
     *
     * <p>
     * Necessário para algoritmos parametrizados, como {@code RSASSA-PSS}
     * (usado pelos algoritmos JWT PS256/PS384/PS512), que exigem um
     * {@link java.security.spec.PSSParameterSpec} definindo digest, MGF e
     * comprimento do salt.
     * </p>
     *
     * @param privateKey    chave privada ou handle PKCS#11
     * @param provider      provider criptográfico (null = padrão da JVM)
     * @param algorithm     algoritmo de assinatura (ex: "RSASSA-PSS")
     * @param parameterSpec parâmetros do algoritmo (null se não requeridos)
     * @throws IllegalArgumentException se a chave estiver abaixo do tamanho
     *                                  mínimo aceito (RSA &lt; 2048 bits ou
     *                                  EC &lt; P-256 — NIST SP 800-57)
     */
    @SuppressFBWarnings(value = "EI_EXPOSE_REP2",
            justification = "Provider e AlgorithmParameterSpec são efetivamente imutáveis")
    public PrivateKeySigningStrategy(
            final PrivateKey privateKey,
            final @Nullable Provider provider,
            final String algorithm,
            final @Nullable AlgorithmParameterSpec parameterSpec) {
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey não pode ser null");
        PemLoader.validateMinimumKeySize(privateKey, "privateKey");
        this.provider = provider; // pode ser null (usa padrão)
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm não pode ser null");
        this.parameterSpec = parameterSpec; // pode ser null (sem parâmetros)
    }

    /**
     * Assina os dados usando a chave privada configurada.
     *
     * <p>
     * Para PKCS#11, a assinatura é delegada ao hardware de forma transparente.
     * </p>
     *
     * @param data bytes a serem assinados
     * @return assinatura digital
     * @throws SigningException se ocorrer erro criptográfico
     */
    @Override
    public byte[] sign(final byte[] data) {
        Objects.requireNonNull(data, "data não pode ser null");
        try {
            final Signature sig = provider != null
                    ? Signature.getInstance(algorithm, provider)
                    : Signature.getInstance(algorithm);
            if (parameterSpec != null) {
                sig.setParameter(parameterSpec);
            }
            sig.initSign(privateKey);
            sig.update(data);
            return sig.sign();
        } catch (GeneralSecurityException e) {
            throw new SigningException("Falha ao assinar dados com algoritmo " + algorithm, e);
        }
    }

    /**
     * Retorna o algoritmo de assinatura configurado.
     *
     * @return nome do algoritmo (ex: "SHA384withRSA")
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Retorna os parâmetros do algoritmo, quando configurados.
     *
     * @return parâmetros do algoritmo ou {@code null}
     */
    @Nullable AlgorithmParameterSpec getParameterSpec() {
        return parameterSpec;
    }
}
