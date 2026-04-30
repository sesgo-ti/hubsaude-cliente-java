/*
 * Copyright (c) 2026 SES-GO / UFG
 * Todos os direitos reservados.
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
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Testes unitários para {@link PemLoader}.
 */
class PemLoaderTest {

    private static Path keyFile;
    private static Path certFile;
    private static PrivateKey privateKey;

    @BeforeAll
    static void gerarParChaves(@TempDir final Path tempDir) throws Exception {
        final KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        final KeyPair pair = gen.generateKeyPair();
        privateKey = pair.getPrivate();

        // Escrever chave privada PEM (PKCS#8)
        keyFile = tempDir.resolve("test-key.pem");
        final String pkcs8Pem = toPkcs8Pem(pair.getPrivate().getEncoded());
        Files.writeString(keyFile, pkcs8Pem, StandardCharsets.UTF_8);

        // Escrever certificado auto-assinado PEM
        certFile = tempDir.resolve("test-cert.pem");
        final String certPem = generateSelfSignedCertPem(pair);
        Files.writeString(certFile, certPem, StandardCharsets.UTF_8);
    }

    @Test
    void deveCarregarChavePrivadaPkcs8() throws IOException {
        final PrivateKey loaded = PemLoader.loadPrivateKey(keyFile);

        assertThat(loaded).isNotNull();
        assertThat(loaded.getAlgorithm()).isEqualTo("RSA");
        assertThat(loaded.getEncoded()).isEqualTo(privateKey.getEncoded());
    }

    @Test
    void deveCarregarChavePrivadaSemSenha() throws IOException {
        final PrivateKey loaded = PemLoader.loadPrivateKey(keyFile, null);

        assertThat(loaded).isNotNull();
        assertThat(loaded.getAlgorithm()).isEqualTo("RSA");
    }

    @Test
    void deveCarregarCertificado() throws IOException {
        final X509Certificate cert = PemLoader.loadCertificate(certFile);

        assertThat(cert).isNotNull();
        assertThat(cert.getPublicKey()).isNotNull();
    }

    @Test
    void deveFalharComChaveInexistente(@TempDir final Path tempDir) {
        final Path naoExiste = tempDir.resolve("nao-existe.pem");
        
        assertThatThrownBy(() -> PemLoader.loadPrivateKey(naoExiste))
                .isInstanceOf(IOException.class);
    }

    @Test
    void deveFalharComCertificadoInexistente(@TempDir final Path tempDir) {
        final Path naoExiste = tempDir.resolve("nao-existe.pem");
        
        assertThatThrownBy(() -> PemLoader.loadCertificate(naoExiste))
                .isInstanceOf(IOException.class);
    }

    @Test
    void deveFalharComArquivoPemVazio(@TempDir final Path tempDir) throws IOException {
        final Path vazio = tempDir.resolve("vazio.pem");
        Files.writeString(vazio, "", StandardCharsets.UTF_8);
        
        assertThatThrownBy(() -> PemLoader.loadPrivateKey(vazio))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("vazio ou inválido");
    }

    @Test
    void deveFalharComArquivoPemInvalido(@TempDir final Path tempDir) throws IOException {
        final Path invalido = tempDir.resolve("invalido.pem");
        Files.writeString(invalido, "conteudo invalido que nao eh PEM", StandardCharsets.UTF_8);
        
        assertThatThrownBy(() -> PemLoader.loadPrivateKey(invalido))
                .isInstanceOf(SmartTokenException.class);
    }

    @Test
    void deveFalharQuandoArquivoNaoContemChave(@TempDir final Path tempDir) throws IOException {
        // Usa o certificado como se fosse chave
        assertThatThrownBy(() -> PemLoader.loadPrivateKey(certFile))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("não suportado");
    }

    @Test
    void deveFalharQuandoArquivoNaoContemCertificado(@TempDir final Path tempDir) throws IOException {
        // Usa a chave como se fosse certificado
        assertThatThrownBy(() -> PemLoader.loadCertificate(keyFile))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("não contém certificado");
    }

    @Test
    void deveCarregarChavePrivadaDeString() throws IOException {
        final String pem = Files.readString(keyFile, StandardCharsets.UTF_8);
        
        final PrivateKey loaded = PemLoader.loadPrivateKeyFromString(pem, null, "test");
        
        assertThat(loaded).isNotNull();
        assertThat(loaded.getAlgorithm()).isEqualTo("RSA");
    }

    @Test
    void deveCarregarCertificadoDeString() throws IOException {
        final String pem = Files.readString(certFile, StandardCharsets.UTF_8);
        
        final X509Certificate cert = PemLoader.loadCertificateFromString(pem, "test");
        
        assertThat(cert).isNotNull();
    }

    @Test
    void deveLancarNullPointerExceptionParaPathNull() {
        assertThatThrownBy(() -> PemLoader.loadPrivateKey(null))
                .isInstanceOf(NullPointerException.class);
        
        assertThatThrownBy(() -> PemLoader.loadCertificate(null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void deveLancarNullPointerExceptionParaPemStringNull() {
        assertThatThrownBy(() -> PemLoader.loadPrivateKeyFromString(null, null, "test"))
                .isInstanceOf(NullPointerException.class);
        
        assertThatThrownBy(() -> PemLoader.loadCertificateFromString(null, "test"))
                .isInstanceOf(NullPointerException.class);
    }

    // ---------- Testes de clearPassword ----------

    @Test
    void deveLimparSenhaAposUso() {
        final char[] senha = "minha-senha-secreta".toCharArray();
        final char[] original = java.util.Arrays.copyOf(senha, senha.length);
        
        PemLoader.clearPassword(senha);
        
        // Verifica que todos os caracteres foram zerados
        for (char c : senha) {
            assertThat(c).isEqualTo('\0');
        }
        // Confirma que era diferente antes
        assertThat(original[0]).isNotEqualTo('\0');
    }

    @Test
    void deveTratarSenhaNullSemFalha() {
        // Não deve lançar exceção
        PemLoader.clearPassword(null);
    }

    @Test
    void deveTratarSenhaVaziaSemFalha() {
        final char[] senhaVazia = new char[0];
        // Não deve lançar exceção
        PemLoader.clearPassword(senhaVazia);
    }

    @Test
    void deveCarregarChavePKCS1RsaNaoCriptografada(@TempDir final Path tempDir) throws Exception {
        // Gerar chave PKCS#1 RSA (formato OpenSSL tradicional)
        final KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        final KeyPair pair = gen.generateKeyPair();

        // Escrever no formato PKCS#1 (BEGIN RSA PRIVATE KEY)
        final Path pkcs1File = tempDir.resolve("pkcs1-key.pem");
        final String pkcs1Pem = toPkcs1Pem(pair.getPrivate());
        Files.writeString(pkcs1File, pkcs1Pem, StandardCharsets.UTF_8);

        final PrivateKey loaded = PemLoader.loadPrivateKey(pkcs1File);

        assertThat(loaded).isNotNull();
        assertThat(loaded.getAlgorithm()).isEqualTo("RSA");
    }

    @Test
    void deveFalharQuandoChavePkcs8EncriptadaSemSenha(@TempDir final Path tempDir) throws Exception {
        // Criar chave PKCS#8 criptografada manualmente
        final Path encryptedFile = tempDir.resolve("encrypted-key.pem");
        final String encryptedPem = createEncryptedPkcs8Pem();
        Files.writeString(encryptedFile, encryptedPem, StandardCharsets.UTF_8);

        assertThatThrownBy(() -> PemLoader.loadPrivateKey(encryptedFile))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("requer senha");
    }

    @Test
    void deveCarregarChavePkcs8EncriptadaComSenhaCorreta(@TempDir final Path tempDir) throws Exception {
        final Path encryptedFile = tempDir.resolve("encrypted-key.pem");
        final String encryptedPem = createEncryptedPkcs8Pem();
        Files.writeString(encryptedFile, encryptedPem, StandardCharsets.UTF_8);

        final PrivateKey loaded = PemLoader.loadPrivateKey(encryptedFile, "senha123".toCharArray());

        assertThat(loaded).isNotNull();
        assertThat(loaded.getAlgorithm()).isEqualTo("RSA");
    }

    @Test
    void deveFalharComSenhaIncorretaEmChavePkcs8Encriptada(@TempDir final Path tempDir) throws Exception {
        final Path encryptedFile = tempDir.resolve("encrypted-key.pem");
        final String encryptedPem = createEncryptedPkcs8Pem();
        Files.writeString(encryptedFile, encryptedPem, StandardCharsets.UTF_8);

        assertThatThrownBy(() -> PemLoader.loadPrivateKey(encryptedFile, "senha-errada".toCharArray()))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("senha incorreta");
    }

    // ---------- Testes para PEMEncryptedKeyPair (OpenSSL tradicional criptografado) ----------

    @Test
    void deveFalharQuandoChaveOpenSslEncriptadaSemSenha(@TempDir final Path tempDir) throws Exception {
        final Path encryptedFile = tempDir.resolve("openssl-encrypted-key.pem");
        final String encryptedPem = createOpenSslEncryptedPem();
        Files.writeString(encryptedFile, encryptedPem, StandardCharsets.UTF_8);

        assertThatThrownBy(() -> PemLoader.loadPrivateKey(encryptedFile))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("requer senha");
    }

    @Test
    void deveCarregarChaveOpenSslEncriptadaComSenhaCorreta(@TempDir final Path tempDir) throws Exception {
        final Path encryptedFile = tempDir.resolve("openssl-encrypted-key.pem");
        final String encryptedPem = createOpenSslEncryptedPem();
        Files.writeString(encryptedFile, encryptedPem, StandardCharsets.UTF_8);

        final PrivateKey loaded = PemLoader.loadPrivateKey(encryptedFile, "openssl123".toCharArray());

        assertThat(loaded).isNotNull();
        assertThat(loaded.getAlgorithm()).isEqualTo("RSA");
    }

    @Test
    void deveFalharComSenhaIncorretaEmChaveOpenSslEncriptada(@TempDir final Path tempDir) throws Exception {
        final Path encryptedFile = tempDir.resolve("openssl-encrypted-key.pem");
        final String encryptedPem = createOpenSslEncryptedPem();
        Files.writeString(encryptedFile, encryptedPem, StandardCharsets.UTF_8);

        assertThatThrownBy(() -> PemLoader.loadPrivateKey(encryptedFile, "senha-errada".toCharArray()))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("senha incorreta");
    }

    @Test
    void deveFalharComSenhaVaziaEmChaveOpenSslEncriptada(@TempDir final Path tempDir) throws Exception {
        final Path encryptedFile = tempDir.resolve("openssl-encrypted-key.pem");
        final String encryptedPem = createOpenSslEncryptedPem();
        Files.writeString(encryptedFile, encryptedPem, StandardCharsets.UTF_8);

        assertThatThrownBy(() -> PemLoader.loadPrivateKey(encryptedFile, new char[0]))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("requer senha");
    }

    /**
     * Cria uma chave RSA criptografada no formato OpenSSL tradicional.
     * Este formato usa "BEGIN RSA PRIVATE KEY" com headers Proc-Type e DEK-Info.
     */
    private static String createOpenSslEncryptedPem() throws Exception {
        // Adicionar BouncyCastle provider se não existir
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }

        // Gerar par de chaves
        final KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        final KeyPair pair = gen.generateKeyPair();

        // Criar PEM criptografado no formato OpenSSL tradicional (PEMEncryptedKeyPair)
        java.io.StringWriter sw = new java.io.StringWriter();
        try (org.bouncycastle.openssl.jcajce.JcaPEMWriter pemWriter =
                new org.bouncycastle.openssl.jcajce.JcaPEMWriter(sw)) {

            // Usar encryptor no formato OpenSSL tradicional (DES-EDE3-CBC)
            org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder encryptorBuilder =
                    new org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder("DES-EDE3-CBC")
                            .setProvider("BC");

            pemWriter.writeObject(pair.getPrivate(), encryptorBuilder.build("openssl123".toCharArray()));
        }
        return sw.toString();
    }

    private static String toPkcs1Pem(final PrivateKey privateKey) throws Exception {
        // Converter para PKCS#1 (RSAPrivateKey)
        org.bouncycastle.asn1.pkcs.RSAPrivateKey rsaKey =
                org.bouncycastle.asn1.pkcs.RSAPrivateKey.getInstance(
                        org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getInstance(privateKey.getEncoded())
                                .parsePrivateKey());

        final StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN RSA PRIVATE KEY-----\n");
        final String encoded = java.util.Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(rsaKey.getEncoded());
        sb.append(encoded);
        sb.append("\n-----END RSA PRIVATE KEY-----\n");
        return sb.toString();
    }

    private static String createEncryptedPkcs8Pem() throws Exception {
        // Adicionar BouncyCastle provider se não existir
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }

        // Gerar par de chaves
        final KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        final KeyPair pair = gen.generateKeyPair();

        // Criptografar usando AES-256-CBC com provider BC
        org.bouncycastle.openssl.jcajce.JcaPKCS8Generator pkcs8Gen =
                new org.bouncycastle.openssl.jcajce.JcaPKCS8Generator(
                        pair.getPrivate(),
                        new org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder(
                                org.bouncycastle.openssl.PKCS8Generator.AES_256_CBC)
                                .setProvider("BC")
                                .setPassword("senha123".toCharArray())
                                .build());

        org.bouncycastle.util.io.pem.PemObject pemObj = pkcs8Gen.generate();
        java.io.StringWriter sw = new java.io.StringWriter();
        try (org.bouncycastle.util.io.pem.PemWriter pw = new org.bouncycastle.util.io.pem.PemWriter(sw)) {
            pw.writeObject(pemObj);
        }
        return sw.toString();
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

    private static String generateSelfSignedCertPem(final KeyPair keyPair) throws Exception {
        final long now = System.currentTimeMillis();
        final java.util.Date notBefore = new java.util.Date(now);
        final java.util.Date notAfter = new java.util.Date(now + 365L * 24 * 60 * 60 * 1000);

        final org.bouncycastle.asn1.x500.X500Name issuer = new org.bouncycastle.asn1.x500.X500Name(
                "C=BR, O=Test, CN=test-client");

        final java.math.BigInteger serial = java.math.BigInteger.valueOf(now);
        final org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder certBuilder =
                new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                        issuer, serial, notBefore, notAfter, issuer, keyPair.getPublic());

        final org.bouncycastle.operator.ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(
                "SHA256withRSA").build(keyPair.getPrivate());

        final org.bouncycastle.cert.X509CertificateHolder holder = certBuilder.build(signer);
        final java.security.cert.X509Certificate cert = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                .getCertificate(holder);

        final StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN CERTIFICATE-----\n");
        sb.append(java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(cert.getEncoded()));
        sb.append("\n-----END CERTIFICATE-----\n");
        return sb.toString();
    }
}
