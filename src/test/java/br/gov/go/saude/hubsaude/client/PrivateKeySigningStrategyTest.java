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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import br.gov.go.saude.hubsaude.core.rastreabilidade.Requirement;
import br.gov.go.saude.hubsaude.core.rastreabilidade.Requirements;

/**
 * Testes unitários para {@link PrivateKeySigningStrategy}.
 */
@Requirements({@Requirement("C1"), @Requirement("P1"), @Requirement("P5"), @Requirement("C11")})
class PrivateKeySigningStrategyTest {

        private static PrivateKey rsaPrivateKey;
        private static PublicKey rsaPublicKey;
        private static PrivateKey ecPrivateKey;
        private static PublicKey ecPublicKey;

        @BeforeAll
        static void gerarChaves() throws Exception {
                // RSA
                final KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
                rsaGen.initialize(2048);
                final KeyPair rsaPair = rsaGen.generateKeyPair();
                rsaPrivateKey = rsaPair.getPrivate();
                rsaPublicKey = rsaPair.getPublic();

                // EC (para teste de algoritmo inválido)
                final KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
                ecGen.initialize(256);
                final KeyPair ecPair = ecGen.generateKeyPair();
                ecPrivateKey = ecPair.getPrivate();
                ecPublicKey = ecPair.getPublic();
        }

        @Test
        void deveAssinarComChaveRSA() throws Exception {
                final PrivateKeySigningStrategy strategy = new PrivateKeySigningStrategy(
                                rsaPrivateKey, "SHA384withRSA");
                final byte[] dados = "mensagem para assinar".getBytes(StandardCharsets.UTF_8);

                final byte[] assinatura = strategy.sign(dados);

                assertThat(assinatura).isNotNull();
                assertThat(assinatura).hasSizeGreaterThan(0);

                // Verificar assinatura
                final Signature verifier = Signature.getInstance("SHA384withRSA");
                verifier.initVerify(rsaPublicKey);
                verifier.update(dados);
                assertThat(verifier.verify(assinatura)).isTrue();
        }

        @Test
        void deveAssinarComDiferentesAlgoritmosRSA() throws Exception {
                final byte[] dados = "dados de teste".getBytes(StandardCharsets.UTF_8);

                // SHA256withRSA
                final PrivateKeySigningStrategy sha256Strategy = new PrivateKeySigningStrategy(
                                rsaPrivateKey, "SHA256withRSA");
                final byte[] sig256 = sha256Strategy.sign(dados);

                final Signature verifier256 = Signature.getInstance("SHA256withRSA");
                verifier256.initVerify(rsaPublicKey);
                verifier256.update(dados);
                assertThat(verifier256.verify(sig256)).isTrue();

                // SHA512withRSA
                final PrivateKeySigningStrategy sha512Strategy = new PrivateKeySigningStrategy(
                                rsaPrivateKey, "SHA512withRSA");
                final byte[] sig512 = sha512Strategy.sign(dados);

                final Signature verifier512 = Signature.getInstance("SHA512withRSA");
                verifier512.initVerify(rsaPublicKey);
                verifier512.update(dados);
                assertThat(verifier512.verify(sig512)).isTrue();
        }

        @Test
        void deveFalharComChaveIncompativelComAlgoritmo() {
                // EC key com RSA algorithm
                final PrivateKeySigningStrategy strategy = new PrivateKeySigningStrategy(
                                ecPrivateKey, "SHA384withRSA");
                final byte[] dados = "dados".getBytes(StandardCharsets.UTF_8);

                assertThatThrownBy(() -> strategy.sign(dados))
                                .isInstanceOf(SigningException.class)
                                .hasMessageContaining("Falha ao assinar dados");
        }

        @Test
        void deveFalharComAlgoritmoInvalido() {
                final PrivateKeySigningStrategy strategy = new PrivateKeySigningStrategy(
                                rsaPrivateKey, "AlgoritmoInexistente");
                final byte[] dados = "dados".getBytes(StandardCharsets.UTF_8);

                assertThatThrownBy(() -> strategy.sign(dados))
                                .isInstanceOf(SigningException.class);
        }

        @Test
        void deveFalharComChaveNula() {
                assertThatThrownBy(() -> new PrivateKeySigningStrategy(null, "SHA384withRSA"))
                                .isInstanceOf(NullPointerException.class);
        }

        @Test
        void deveFalharComAlgoritmoNulo() {
                assertThatThrownBy(() -> new PrivateKeySigningStrategy(rsaPrivateKey, null))
                                .isInstanceOf(NullPointerException.class);
        }

        @Test
        void deveFalharComDadosNulos() {
                final PrivateKeySigningStrategy strategy = new PrivateKeySigningStrategy(
                                rsaPrivateKey, "SHA384withRSA");

                assertThatThrownBy(() -> strategy.sign(null))
                                .isInstanceOf(NullPointerException.class);
        }

        @Test
        void deveSerIdempotente() throws Exception {
                final PrivateKeySigningStrategy strategy = new PrivateKeySigningStrategy(
                                rsaPrivateKey, "SHA384withRSA");
                final byte[] dados = "mesmos dados".getBytes(StandardCharsets.UTF_8);

                final byte[] sig1 = strategy.sign(dados);
                final byte[] sig2 = strategy.sign(dados);

                // RSA com mesmo padding é determinístico
                assertThat(sig1).isEqualTo(sig2);
        }

        @Test
        void deveAssinarDadosVazios() throws Exception {
                final PrivateKeySigningStrategy strategy = new PrivateKeySigningStrategy(
                                rsaPrivateKey, "SHA384withRSA");
                final byte[] dadosVazios = new byte[0];

                final byte[] assinatura = strategy.sign(dadosVazios);

                assertThat(assinatura).isNotNull();

                // Verificar
                final Signature verifier = Signature.getInstance("SHA384withRSA");
                verifier.initVerify(rsaPublicKey);
                verifier.update(dadosVazios);
                assertThat(verifier.verify(assinatura)).isTrue();
        }

        @Test
        void deveRetornarAlgoritmoPadrao() {
                final PrivateKeySigningStrategy strategy = new PrivateKeySigningStrategy(rsaPrivateKey);

                assertThat(strategy.getAlgorithm()).isEqualTo(PrivateKeySigningStrategy.DEFAULT_ALGORITHM);
        }

        @Test
        void deveRetornarAlgoritmoCustomizado() {
                final PrivateKeySigningStrategy strategy = new PrivateKeySigningStrategy(
                                rsaPrivateKey, "SHA512withRSA");

                assertThat(strategy.getAlgorithm()).isEqualTo("SHA512withRSA");
        }

        @Test
        void deveAssinarComProviderExplicito() throws Exception {
                // Usa o BouncyCastle como provider explícito, exercitando
                // Signature.getInstance(algorithm, provider) na linha 116
                final java.security.Provider bcProvider = new org.bouncycastle.jce.provider.BouncyCastleProvider();

                final PrivateKeySigningStrategy strategy = new PrivateKeySigningStrategy(
                                rsaPrivateKey, bcProvider, "SHA384withRSA");

                final byte[] dados = "dados assinados via provider".getBytes(StandardCharsets.UTF_8);
                final byte[] assinatura = strategy.sign(dados);

                assertThat(assinatura).isNotNull().hasSizeGreaterThan(0);
                assertThat(strategy.getAlgorithm()).isEqualTo("SHA384withRSA");

                // Verificar assinatura com provider padrão (interoperabilidade)
                final Signature verifier = Signature.getInstance("SHA384withRSA");
                verifier.initVerify(rsaPublicKey);
                verifier.update(dados);
                assertThat(verifier.verify(assinatura)).isTrue();
        }

        @Test
        void deveAssinarECComProviderExplicito() throws Exception {
                final java.security.Provider bcProvider = new org.bouncycastle.jce.provider.BouncyCastleProvider();

                final PrivateKeySigningStrategy strategy = new PrivateKeySigningStrategy(
                                ecPrivateKey, bcProvider, "SHA256withECDSA");

                final byte[] dados = "dados EC via provider".getBytes(StandardCharsets.UTF_8);
                final byte[] assinatura = strategy.sign(dados);

                assertThat(assinatura).isNotNull().hasSizeGreaterThan(0);

                // Verificar
                final Signature verifier = Signature.getInstance("SHA256withECDSA");
                verifier.initVerify(ecPublicKey);
                verifier.update(dados);
                assertThat(verifier.verify(assinatura)).isTrue();
        }
}
