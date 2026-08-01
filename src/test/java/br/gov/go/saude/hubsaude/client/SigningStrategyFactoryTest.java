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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Testes unitários para {@link SigningStrategyFactory}.
 */
class SigningStrategyFactoryTest {

    private static Path keyFile;
    private static PrivateKey privateKey;
    private static PublicKey publicKey;

    @BeforeAll
    static void gerarParChaves(@TempDir final Path tempDir) throws Exception {
        final KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        final KeyPair pair = gen.generateKeyPair();
        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();

        // Escrever chave privada PEM (PKCS#8)
        keyFile = tempDir.resolve("strategy-test-key.pem");
        final String pkcs8Pem = toPkcs8Pem(pair.getPrivate().getEncoded());
        Files.writeString(keyFile, pkcs8Pem, StandardCharsets.UTF_8);
    }

    @Test
    void deveAssinarComChavePrivadaDireta() throws Exception {
        final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(privateKey);
        final byte[] dados = "dados para assinar".getBytes(StandardCharsets.UTF_8);

        final byte[] assinatura = strategy.sign(dados);

        assertThat(assinatura).isNotNull().hasSizeGreaterThan(0);

        // Verificar assinatura (default RS384 = SHA384withRSA)
        final Signature verifier = Signature.getInstance("SHA384withRSA");
        verifier.initVerify(publicKey);
        verifier.update(dados);
        assertThat(verifier.verify(assinatura)).isTrue();
    }

    @Test
    void deveAceitarAlgoritmosJwtEmMinusculas() {
        // RF: aceitação case-insensitive de algoritmos JWT
        assertThat(SigningStrategyFactory.jwtAlgorithmToJava("rs256"))
                .isEqualTo("SHA256withRSA");
        assertThat(SigningStrategyFactory.jwtAlgorithmToJava("rs384"))
                .isEqualTo("SHA384withRSA");
        assertThat(SigningStrategyFactory.jwtAlgorithmToJava("rs512"))
                .isEqualTo("SHA512withRSA");
        assertThat(SigningStrategyFactory.jwtAlgorithmToJava("ps256"))
                .isEqualTo("RSASSA-PSS");
        assertThat(SigningStrategyFactory.jwtAlgorithmToJava("es256"))
                .isEqualTo("SHA256withECDSAinP1363Format");
        assertThat(SigningStrategyFactory.pssParameterSpecFor("ps384")).isNotNull();
    }

    @Test
    void deveAssinarComAlgoritmoJwtEmMinusculas() throws Exception {
        final SigningStrategy strategy =
                SigningStrategyFactory.fromPrivateKeyForJwt(privateKey, "rs384");
        final byte[] dados = "dados para assinar".getBytes(StandardCharsets.UTF_8);

        final byte[] assinatura = strategy.sign(dados);

        final Signature verifier = Signature.getInstance("SHA384withRSA");
        verifier.initVerify(publicKey);
        verifier.update(dados);
        assertThat(verifier.verify(assinatura)).isTrue();
    }

    @Test
    void deveAssinarComOverloadSemSenha() throws Exception {
        final SigningStrategy strategy = SigningStrategyFactory.fromPemFile(keyFile);
        final byte[] dados = "overload sem senha".getBytes(StandardCharsets.UTF_8);

        final byte[] assinatura = strategy.sign(dados);

        assertThat(assinatura).isNotNull();
    }

    @Test
    void deveAssinarComArquivoPemSemSenha() throws Exception {
        final SigningStrategy strategy = SigningStrategyFactory.fromPemFile(keyFile, null);
        final byte[] dados = "mensagem de teste".getBytes(StandardCharsets.UTF_8);

        final byte[] assinatura = strategy.sign(dados);

        assertThat(assinatura).isNotNull();

        // Verificar assinatura (default RS384 = SHA384withRSA)
        final Signature verifier = Signature.getInstance("SHA384withRSA");
        verifier.initVerify(publicKey);
        verifier.update(dados);
        assertThat(verifier.verify(assinatura)).isTrue();
    }

    @Test
    void deveAssinarComPemString() throws Exception {
        final String pemContent = Files.readString(keyFile, StandardCharsets.UTF_8);
        final SigningStrategy strategy = SigningStrategyFactory.fromPemString(pemContent, null);
        final byte[] dados = "dados string pem".getBytes(StandardCharsets.UTF_8);

        final byte[] assinatura = strategy.sign(dados);

        assertThat(assinatura).isNotNull();

        // Verificar assinatura (default RS384 = SHA384withRSA)
        final Signature verifier = Signature.getInstance("SHA384withRSA");
        verifier.initVerify(publicKey);
        verifier.update(dados);
        assertThat(verifier.verify(assinatura)).isTrue();
    }

    @Test
    void deveFalharComArquivoPemInexistente(@TempDir final Path tempDir) {
        final Path naoExiste = tempDir.resolve("nao-existe.pem");

        assertThatThrownBy(() -> SigningStrategyFactory.fromPemFile(naoExiste, null))
                .isInstanceOf(IOException.class);
    }

    @Test
    void deveFalharComChavePrivadaNula() {
        assertThatThrownBy(() -> SigningStrategyFactory.fromPrivateKey(null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void deveFalharComPathNulo() {
        assertThatThrownBy(() -> SigningStrategyFactory.fromPemFile(null, null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void deveFalharComPemStringNula() {
        assertThatThrownBy(() -> SigningStrategyFactory.fromPemString(null, null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void estrategiasDevemSerIdempotentes() {
        final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(privateKey);
        final byte[] dados = "dados idempotentes".getBytes(StandardCharsets.UTF_8);

        final byte[] assinatura1 = strategy.sign(dados);
        final byte[] assinatura2 = strategy.sign(dados);

        // Ambas devem ser válidas (RSA é determinístico para mesmo input)
        assertThat(assinatura1).isEqualTo(assinatura2);
    }

    @Test
    void deveUsarAlgoritmoRS384PorPadrao() throws Exception {
        final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(privateKey);
        final byte[] dados = "teste RS384".getBytes(StandardCharsets.UTF_8);

        final byte[] assinatura = strategy.sign(dados);

        // Verificar com SHA384withRSA (RS384) - deve funcionar
        final Signature sha384Verifier = Signature.getInstance("SHA384withRSA");
        sha384Verifier.initVerify(publicKey);
        sha384Verifier.update(dados);
        assertThat(sha384Verifier.verify(assinatura)).isTrue();

        // Verificar com SHA256withRSA (RS256) - deve falhar
        // Comportamento varia entre JVMs: pode lançar SignatureException ou retornar false
        final Signature sha256Verifier = Signature.getInstance("SHA256withRSA");
        sha256Verifier.initVerify(publicKey);
        sha256Verifier.update(dados);
        try {
            final boolean result = sha256Verifier.verify(assinatura);
            assertThat(result).isFalse();
        } catch (java.security.SignatureException e) {
            // Algumas JVMs lançam exceção ao invés de retornar false - também é válido
        }
    }

    @Test
    void deveAssinarComChavePrivadaEAlgoritmoCustomizado() throws Exception {
        final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(privateKey, "SHA256withRSA");
        final byte[] dados = "teste SHA256".getBytes(StandardCharsets.UTF_8);

        final byte[] assinatura = strategy.sign(dados);

        // Verificar com SHA256withRSA
        final Signature sha256Verifier = Signature.getInstance("SHA256withRSA");
        sha256Verifier.initVerify(publicKey);
        sha256Verifier.update(dados);
        assertThat(sha256Verifier.verify(assinatura)).isTrue();
    }

    @Test
    void deveFalharComAlgorithmNeNulo() {
        assertThatThrownBy(() -> SigningStrategyFactory.fromPrivateKey(privateKey, null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void deveAssinarComKeyStore() throws Exception {
        // Criar KeyStore PKCS12 com a chave
        final KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        
        // Gerar certificado self-signed para o keystore
        final java.security.cert.X509Certificate cert = generateSelfSignedCert(privateKey, publicKey);
        ks.setKeyEntry("test-alias", privateKey, "senha123".toCharArray(),
                new java.security.cert.Certificate[]{cert});

        // Criar estratégia
        final SigningStrategy strategy = SigningStrategyFactory.fromKeyStore(ks, "test-alias", "senha123".toCharArray());
        final byte[] dados = "dados keystore".getBytes(StandardCharsets.UTF_8);

        final byte[] assinatura = strategy.sign(dados);

        // Verificar (default RS384 = SHA384withRSA)
        final Signature verifier = Signature.getInstance("SHA384withRSA");
        verifier.initVerify(publicKey);
        verifier.update(dados);
        assertThat(verifier.verify(assinatura)).isTrue();
    }

    @Test
    void devePreservarSenhaDoChamadorEmFromKeyStore() throws Exception {
        final KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        final java.security.cert.X509Certificate cert = generateSelfSignedCert(privateKey, publicKey);
        ks.setKeyEntry("test-alias", privateKey, "senha123".toCharArray(),
                new java.security.cert.Certificate[]{cert});

        final char[] senha = "senha123".toCharArray();

        final SigningStrategy primeira = SigningStrategyFactory.fromKeyStore(ks, "test-alias", senha);

        // O array do chamador permanece intacto (cópia defensiva interna)
        assertThat(senha).containsExactly("senha123".toCharArray());

        // Reutilização do mesmo PIN em chamada subsequente funciona
        final SigningStrategy segunda = SigningStrategyFactory.fromKeyStore(ks, "test-alias", senha);

        assertThat(primeira).isNotNull();
        assertThat(segunda).isNotNull();
        assertThat(senha).containsExactly("senha123".toCharArray());
    }

    @Test
    void devePreservarSenhaDoChamadorMesmoEmErroNoFromKeyStore() throws Exception {
        final KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);

        final char[] senha = "senha123".toCharArray();

        assertThatThrownBy(() -> SigningStrategyFactory.fromKeyStore(ks, "alias-inexistente", senha))
                .isInstanceOf(SmartTokenException.class);

        // Mesmo no caminho de erro, o array do chamador não é modificado
        assertThat(senha).containsExactly("senha123".toCharArray());
    }

    @Test
    void deveFalharComAliasInexistenteNoKeyStore() throws Exception {
        final KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);

        assertThatThrownBy(() -> SigningStrategyFactory.fromKeyStore(ks, "alias-inexistente", null))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("Chave não encontrada");
    }

    @Test
    void deveFalharComKeyStoreNulo() {
        assertThatThrownBy(() -> SigningStrategyFactory.fromKeyStore(null, "alias", null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void deveFalharComAliasNuloNoKeyStore() throws Exception {
        final KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);

        assertThatThrownBy(() -> SigningStrategyFactory.fromKeyStore(ks, null, null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void deveFalharComPkcs11ProviderNulo() {
        assertThatThrownBy(() -> SigningStrategyFactory.fromPkcs11(null, "alias", new char[]{ 'p' }))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void deveFalharComPkcs11AliasNulo() {
        // Usar provider fictício apenas para teste de validação
        final java.security.Provider provider = java.security.Security.getProvider("SunJCE");
        
        assertThatThrownBy(() -> SigningStrategyFactory.fromPkcs11(provider, null, new char[]{ 'p' }))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void deveFalharComPkcs11PinNulo() {
        final java.security.Provider provider = java.security.Security.getProvider("SunJCE");
        
        assertThatThrownBy(() -> SigningStrategyFactory.fromPkcs11(provider, "alias", null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void deveFalharComConfigPathNuloParaPkcs11() {
        assertThatThrownBy(() -> SigningStrategyFactory.configurePkcs11Provider(null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void deveMapearEsParaFormatoP1363() {
        assertThat(SigningStrategyFactory.jwtAlgorithmToJava("ES256"))
                .isEqualTo("SHA256withECDSAinP1363Format");
        assertThat(SigningStrategyFactory.jwtAlgorithmToJava("ES384"))
                .isEqualTo("SHA384withECDSAinP1363Format");
        assertThat(SigningStrategyFactory.jwtAlgorithmToJava("ES512"))
                .isEqualTo("SHA512withECDSAinP1363Format");
    }

    @Test
    void deveMapearPsParaRsassaPss() {
        assertThat(SigningStrategyFactory.jwtAlgorithmToJava("PS256")).isEqualTo("RSASSA-PSS");
        assertThat(SigningStrategyFactory.jwtAlgorithmToJava("PS384")).isEqualTo("RSASSA-PSS");
        assertThat(SigningStrategyFactory.jwtAlgorithmToJava("PS512")).isEqualTo("RSASSA-PSS");
    }

    @Test
    void deveRejeitarAlgoritmoNone() {
        assertThatThrownBy(() -> SigningStrategyFactory.jwtAlgorithmToJava("none"))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("não suportado");
        assertThatThrownBy(() -> SigningStrategyFactory.jwtAlgorithmToJava("HS256"))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("não suportado");
    }

    @Test
    void deveRetornarPssParameterSpecCorretoPorVariante() {
        final var ps256 = SigningStrategyFactory.pssParameterSpecFor("PS256");
        assertThat(ps256.getDigestAlgorithm()).isEqualTo("SHA-256");
        assertThat(ps256.getSaltLength()).isEqualTo(32);

        final var ps384 = SigningStrategyFactory.pssParameterSpecFor("PS384");
        assertThat(ps384.getDigestAlgorithm()).isEqualTo("SHA-384");
        assertThat(ps384.getSaltLength()).isEqualTo(48);

        final var ps512 = SigningStrategyFactory.pssParameterSpecFor("PS512");
        assertThat(ps512.getDigestAlgorithm()).isEqualTo("SHA-512");
        assertThat(ps512.getSaltLength()).isEqualTo(64);

        assertThat(SigningStrategyFactory.pssParameterSpecFor("RS256")).isNull();
    }

    @Test
    void fromPrivateKeyForJwtDeveAssinarEs256Verificavel() throws Exception {
        final KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
        ecGen.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        final KeyPair ecPair = ecGen.generateKeyPair();

        final SigningStrategy strategy = SigningStrategyFactory
                .fromPrivateKeyForJwt(ecPair.getPrivate(), "ES256");
        final byte[] data = "dados-teste".getBytes(StandardCharsets.UTF_8);
        final byte[] signature = strategy.sign(data);

        // Assinatura P1363 de P-256 tem exatamente 64 bytes (R||S)
        assertThat(signature).hasSize(64);

        final Signature verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
        verifier.initVerify(ecPair.getPublic());
        verifier.update(data);
        assertThat(verifier.verify(signature)).isTrue();
    }

    @Test
    void fromPrivateKeyForJwtDeveAssinarPs256Verificavel() throws Exception {
        final SigningStrategy strategy = SigningStrategyFactory
                .fromPrivateKeyForJwt(privateKey, "PS256");
        final byte[] data = "dados-teste".getBytes(StandardCharsets.UTF_8);
        final byte[] signature = strategy.sign(data);

        final Signature verifier = Signature.getInstance("RSASSA-PSS");
        verifier.setParameter(SigningStrategyFactory.pssParameterSpecFor("PS256"));
        verifier.initVerify(publicKey);
        verifier.update(data);
        assertThat(verifier.verify(signature)).isTrue();
    }

    private static java.security.cert.X509Certificate generateSelfSignedCert(
            final PrivateKey privKey, final PublicKey pubKey) throws Exception {
        final long now = System.currentTimeMillis();
        final java.util.Date notBefore = new java.util.Date(now);
        final java.util.Date notAfter = new java.util.Date(now + 365L * 24 * 60 * 60 * 1000);

        final org.bouncycastle.asn1.x500.X500Name issuer = new org.bouncycastle.asn1.x500.X500Name(
                "C=BR, O=Test, CN=test-client");

        final java.math.BigInteger serial = java.math.BigInteger.valueOf(now);
        final org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder certBuilder =
                new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                        issuer, serial, notBefore, notAfter, issuer, pubKey);

        final org.bouncycastle.operator.ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(
                "SHA256withRSA").build(privKey);

        final org.bouncycastle.cert.X509CertificateHolder holder = certBuilder.build(signer);
        return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(holder);
    }

    private static String toPkcs8Pem(final byte[] privateKeyBytes) {
        final StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN PRIVATE KEY-----\n");
        final String encoded = java.util.Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                .encodeToString(privateKeyBytes);
        sb.append(encoded);
        sb.append("\n-----END PRIVATE KEY-----\n");
        return sb.toString();
    }
}
