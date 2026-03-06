/*
 * Copyright (c) 2026 SES-GO / UFG
 * Todos os direitos reservados.
 */

package br.gov.go.saude.hubsaude.client;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import javax.net.ssl.SSLContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Testes unitários para {@link SslContextFactory}.
 *
 * <p>
 * Cobre validações de certificados X.509 (válido, expirado, futuro),
 * construção de SSLContext e cenários de erro.
 * </p>
 */
@DisplayName("SslContextFactory")
class SslContextFactoryTest {

    @TempDir
    private Path tempDir;

    private static KeyPair keyPair;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        final KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        keyPair = gen.generateKeyPair();
    }

    // ==================== validateCertificate(Path) ====================

    @Test
    @DisplayName("validateCertificate(Path): Deve validar certificado válido")
    void deveValidarCertificadoValido() throws Exception {
        final Path certFile = createCertFile(
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(365, ChronoUnit.DAYS));

        final X509Certificate cert = SslContextFactory.validateCertificate(certFile);

        assertThat(cert).isNotNull();
        assertThat(cert.getSubjectX500Principal().getName()).contains("SslContextFactoryTest");
    }

    @Test
    @DisplayName("validateCertificate(Path): Deve lançar exceção para certificado expirado")
    void deveLancarExcecaoParaCertificadoExpirado() throws Exception {
        final Path certFile = createCertFile(
                Instant.now().minus(365, ChronoUnit.DAYS),
                Instant.now().minus(1, ChronoUnit.DAYS));

        assertThatThrownBy(() -> SslContextFactory.validateCertificate(certFile))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("Certificado expirado");
    }

    @Test
    @DisplayName("validateCertificate(Path): Deve lançar exceção para certificado ainda não válido")
    void deveLancarExcecaoParaCertificadoFuturo() throws Exception {
        final Path certFile = createCertFile(
                Instant.now().plus(1, ChronoUnit.DAYS),
                Instant.now().plus(365, ChronoUnit.DAYS));

        assertThatThrownBy(() -> SslContextFactory.validateCertificate(certFile))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("Certificado ainda não é válido");
    }

    @Test
    @DisplayName("validateCertificate(Path): Deve lançar IOException para arquivo inexistente")
    void deveLancarIoExceptionParaArquivoInexistente() {
        final Path inexistente = tempDir.resolve("nao-existe.pem");

        assertThatThrownBy(() -> SslContextFactory.validateCertificate(inexistente))
                .isInstanceOf(IOException.class);
    }

    // ==================== validateCertificate(Path, String) ====================

    @Test
    @DisplayName("validateCertificate(Path, String): Deve validar PEM string válido")
    void deveValidarPemStringValido() throws Exception {
        final String pem = generateCertPem(
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(365, ChronoUnit.DAYS));
        final Path dummyPath = tempDir.resolve("dummy.pem");

        final X509Certificate cert = SslContextFactory.validateCertificate(dummyPath, pem);

        assertThat(cert).isNotNull();
    }

    @Test
    @DisplayName("validateCertificate(Path, String): Deve lançar exceção para PEM inválido")
    void deveLancarExcecaoParaPemInvalido() {
        final String pemInvalido = "-----BEGIN CERTIFICATE-----\nINVALIDO\n-----END CERTIFICATE-----";
        final Path dummyPath = tempDir.resolve("invalido.pem");

        assertThatThrownBy(() -> SslContextFactory.validateCertificate(dummyPath, pemInvalido))
                .isInstanceOf(Exception.class);
    }

    @Test
    @DisplayName("validateCertificate(Path, String): Deve lançar exceção para conteúdo não-certificado")
    void deveLancarExcecaoParaConteudoNaoCertificado() {
        // PEM de chave privada vazia/inválida para forçar cenário de não-certificado
        final String pemVazio = "";
        final Path dummyPath = tempDir.resolve("vazio-string.pem");

        assertThatThrownBy(() -> SslContextFactory.validateCertificate(dummyPath, pemVazio))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("não contém certificado X.509");
    }

    // ==================== validateCertificate(Path, PEMParser) ====================

    @Test
    @DisplayName("validateCertificate(Path, PEMParser): Deve validar parser com certificado válido")
    void deveValidarParserComCertificadoValido() throws Exception {
        final String pem = generateCertPem(
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(365, ChronoUnit.DAYS));
        final PEMParser parser = new PEMParser(new StringReader(pem));
        final Path dummyPath = tempDir.resolve("parser.pem");

        final X509Certificate cert = SslContextFactory.validateCertificate(dummyPath, parser);

        assertThat(cert).isNotNull();
    }

    @Test
    @DisplayName("validateCertificate(Path, PEMParser): Deve lançar exceção para parser vazio")
    void deveLancarExcecaoParaParserVazio() {
        final PEMParser parser = new PEMParser(new StringReader(""));
        final Path dummyPath = tempDir.resolve("vazio.pem");

        assertThatThrownBy(() -> SslContextFactory.validateCertificate(dummyPath, parser))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("não contém certificado X.509");
    }

    // ==================== validateCertificate(Path, Object) ====================

    @Test
    @DisplayName("validateCertificate(Path, Object): Deve validar X509CertificateHolder válido")
    void deveValidarX509CertificateHolderValido() throws Exception {
        final X509CertificateHolder holder = generateCertHolder(
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(365, ChronoUnit.DAYS));
        final Path dummyPath = tempDir.resolve("holder.pem");

        final X509Certificate cert = SslContextFactory.validateCertificate(dummyPath, holder);

        assertThat(cert).isNotNull();
    }

    @Test
    @DisplayName("validateCertificate(Path, Object): Deve lançar exceção para objeto não-certificado")
    void deveLancarExcecaoParaObjetoNaoCertificado() {
        final Object objetoInvalido = "não é um certificado";
        final Path dummyPath = tempDir.resolve("objeto.pem");

        assertThatThrownBy(() -> SslContextFactory.validateCertificate(dummyPath, objetoInvalido))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("não contém certificado X.509");
    }

    @Test
    @DisplayName("validateCertificate(Path, Object): Deve lançar exceção para objeto null")
    void deveLancarExcecaoParaObjetoNull() {
        final Path dummyPath = tempDir.resolve("null.pem");

        assertThatThrownBy(() -> SslContextFactory.validateCertificate(dummyPath, (Object) null))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("não contém certificado X.509");
    }

    // ==================== validateCertificate(Path, X509CertificateHolder) ====================

    @Test
    @DisplayName("validateCertificate(Path, X509CertificateHolder): Deve validar holder válido")
    void deveValidarHolderValido() throws Exception {
        final X509CertificateHolder holder = generateCertHolder(
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(365, ChronoUnit.DAYS));
        final Path dummyPath = tempDir.resolve("holder-valid.pem");

        final X509Certificate cert = SslContextFactory.validateCertificate(dummyPath, holder);

        assertThat(cert).isNotNull();
        assertThat(cert.getSubjectX500Principal().getName()).contains("SslContextFactoryTest");
    }

    @Test
    @DisplayName("validateCertificate(Path, X509CertificateHolder): Deve lançar exceção para holder expirado")
    void deveLancarExcecaoParaHolderExpirado() throws Exception {
        final X509CertificateHolder holder = generateCertHolder(
                Instant.now().minus(365, ChronoUnit.DAYS),
                Instant.now().minus(1, ChronoUnit.DAYS));
        final Path dummyPath = tempDir.resolve("holder-expirado.pem");

        assertThatThrownBy(() -> SslContextFactory.validateCertificate(dummyPath, holder))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("Certificado expirado");
    }

    // ==================== validateCertificate(Path, X509Certificate) ====================

    @Test
    @DisplayName("validateCertificate(Path, X509Certificate): Deve validar certificado dentro da validade")
    void deveValidarCertificadoDentroValidade() throws Exception {
        final X509Certificate cert = generateCert(
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(365, ChronoUnit.DAYS));
        final Path dummyPath = tempDir.resolve("cert-valid.pem");

        // Não deve lançar exceção
        SslContextFactory.validateCertificate(dummyPath, cert);
    }

    @Test
    @DisplayName("validateCertificate(Path, X509Certificate): Deve lançar exceção para certificado expirado")
    void deveDetectarCertificadoExpirado() throws Exception {
        final X509Certificate cert = generateCert(
                Instant.now().minus(365, ChronoUnit.DAYS),
                Instant.now().minus(1, ChronoUnit.DAYS));
        final Path dummyPath = tempDir.resolve("cert-expirado.pem");

        assertThatThrownBy(() -> SslContextFactory.validateCertificate(dummyPath, cert))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("Certificado expirado");
    }

    @Test
    @DisplayName("validateCertificate(Path, X509Certificate): Deve lançar exceção para certificado futuro")
    void deveDetectarCertificadoFuturo() throws Exception {
        final X509Certificate cert = generateCert(
                Instant.now().plus(1, ChronoUnit.DAYS),
                Instant.now().plus(365, ChronoUnit.DAYS));
        final Path dummyPath = tempDir.resolve("cert-futuro.pem");

        assertThatThrownBy(() -> SslContextFactory.validateCertificate(dummyPath, cert))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("Certificado ainda não é válido");
    }

    // ==================== buildSslContext ====================

    @Test
    @DisplayName("buildSslContext: Deve retornar SSLContext padrão quando serverTrustAnchor é null")
    void deveRetornarSslContextPadraoQuandoTrustAnchorNull() {
        final SSLContext ctx = SslContextFactory.buildSslContext(null, SslContextFactory.DEFAULT_TLS_PROTOCOL);

        assertThat(ctx).isNotNull();
        assertThat(ctx.getProtocol()).isEqualTo("Default");
    }

    @Test
    @DisplayName("buildSslContext: Deve construir SSLContext com certificado do servidor")
    void deveConstruirSslContextComCertificadoServidor() throws Exception {
        final Path certFile = createCertFile(
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(365, ChronoUnit.DAYS));

        final SSLContext ctx = SslContextFactory.buildSslContext(certFile, "TLSv1.3");

        assertThat(ctx).isNotNull();
        assertThat(ctx.getProtocol()).isEqualTo("TLSv1.3");
    }

    @Test
    @DisplayName("buildSslContext: Deve lançar exceção para certificado expirado")
    void deveLancarExcecaoParaCertificadoServidorExpirado() throws Exception {
        final Path certFile = createCertFile(
                Instant.now().minus(365, ChronoUnit.DAYS),
                Instant.now().minus(1, ChronoUnit.DAYS));

        assertThatThrownBy(() -> SslContextFactory.buildSslContext(certFile, "TLSv1.3"))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("Certificado expirado");
    }

    // ==================== buildTrustAllSslContext ====================

    @Test
    @DisplayName("buildTrustAllSslContext: Deve criar SSLContext trust-all")
    void deveCriarSslContextTrustAll() {
        final SSLContext ctx = SslContextFactory.buildTrustAllSslContext("TLSv1.3");

        assertThat(ctx).isNotNull();
        assertThat(ctx.getProtocol()).isEqualTo("TLSv1.3");
    }

    @Test
    @DisplayName("buildTrustAllSslContext: Deve lançar exceção para protocolo inválido")
    void deveLancarExcecaoParaProtocoloInvalido() {
        assertThatThrownBy(() -> SslContextFactory.buildTrustAllSslContext("TLSv99.9"))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("Falha ao criar SSLContext trust-all");
    }

    // ==================== Helpers ====================

    private Path createCertFile(Instant notBefore, Instant notAfter) throws Exception {
        final String pem = generateCertPem(notBefore, notAfter);
        final Path certFile = tempDir.resolve("cert-" + System.nanoTime() + ".pem");
        Files.writeString(certFile, pem, StandardCharsets.UTF_8);
        return certFile;
    }

    private String generateCertPem(Instant notBefore, Instant notAfter) throws Exception {
        final X509Certificate cert = generateCert(notBefore, notAfter);
        final StringWriter sw = new StringWriter();
        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(cert);
        }
        return sw.toString();
    }

    private X509Certificate generateCert(Instant notBefore, Instant notAfter) throws Exception {
        final X509CertificateHolder holder = generateCertHolder(notBefore, notAfter);
        return new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider())
                .getCertificate(holder);
    }

    private X509CertificateHolder generateCertHolder(Instant notBefore, Instant notAfter) throws Exception {
        final X500Name dn = new X500Name("CN=SslContextFactoryTest");
        final ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .build(keyPair.getPrivate());
        final X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                dn,
                BigInteger.valueOf(System.nanoTime()),
                Date.from(notBefore),
                Date.from(notAfter),
                dn,
                keyPair.getPublic());
        return builder.build(signer);
    }
}


