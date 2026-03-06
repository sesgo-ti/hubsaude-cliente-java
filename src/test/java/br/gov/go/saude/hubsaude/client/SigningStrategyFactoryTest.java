/*
 * Copyright (c) 2026 SES-GO / UFG
 * Todos os direitos reservados.
 */

package br.gov.go.saude.hubsaude.client;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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

        assertThat(assinatura).isNotNull();
        assertThat(assinatura).hasSizeGreaterThan(0);

        // Verificar assinatura
        final Signature verifier = Signature.getInstance("SHA384withRSA");
        verifier.initVerify(publicKey);
        verifier.update(dados);
        assertThat(verifier.verify(assinatura)).isTrue();
    }

    @Test
    void deveAssinarComArquivoPemSemSenha() throws Exception {
        final SigningStrategy strategy = SigningStrategyFactory.fromPemFile(keyFile, null);
        final byte[] dados = "mensagem de teste".getBytes(StandardCharsets.UTF_8);

        final byte[] assinatura = strategy.sign(dados);

        assertThat(assinatura).isNotNull();

        // Verificar assinatura
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

        // Verificar assinatura
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
    void estrategiasDevemSerIdempotentes() throws Exception {
        final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(privateKey);
        final byte[] dados = "dados idempotentes".getBytes(StandardCharsets.UTF_8);

        final byte[] assinatura1 = strategy.sign(dados);
        final byte[] assinatura2 = strategy.sign(dados);

        // Ambas devem ser válidas (RSA é determinístico para mesmo input)
        assertThat(assinatura1).isEqualTo(assinatura2);
    }

    @Test
    void deveUsarAlgoritmoRS384() throws Exception {
        final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(privateKey);
        final byte[] dados = "teste RS384".getBytes(StandardCharsets.UTF_8);

        final byte[] assinatura = strategy.sign(dados);

        // Verificar com SHA384withRSA - deve funcionar
        final Signature sha384Verifier = Signature.getInstance("SHA384withRSA");
        sha384Verifier.initVerify(publicKey);
        sha384Verifier.update(dados);
        assertThat(sha384Verifier.verify(assinatura)).isTrue();

        // Verificar com SHA256withRSA - deve falhar (lança exceção por mismatch de OID)
        final Signature sha256Verifier = Signature.getInstance("SHA256withRSA");
        sha256Verifier.initVerify(publicKey);
        sha256Verifier.update(dados);
        assertThatThrownBy(() -> sha256Verifier.verify(assinatura))
                .isInstanceOf(java.security.SignatureException.class);
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

        // Verificar
        final Signature verifier = Signature.getInstance("SHA384withRSA");
        verifier.initVerify(publicKey);
        verifier.update(dados);
        assertThat(verifier.verify(assinatura)).isTrue();
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
        assertThatThrownBy(() -> SigningStrategyFactory.fromPkcs11(null, "alias", "pin".toCharArray()))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void deveFalharComPkcs11AliasNulo() {
        // Usar provider fictício apenas para teste de validação
        final java.security.Provider provider = java.security.Security.getProvider("SunJCE");
        
        assertThatThrownBy(() -> SigningStrategyFactory.fromPkcs11(provider, null, "pin".toCharArray()))
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
        final String encoded = java.util.Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(privateKeyBytes);
        sb.append(encoded);
        sb.append("\n-----END PRIVATE KEY-----\n");
        return sb.toString();
    }
}
