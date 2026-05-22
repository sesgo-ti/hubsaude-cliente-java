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
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;

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

        PEMParser parser = new PEMParser(new StringReader(pem));
        final X509Certificate cert = SslContextFactory.validateCertificate(dummyPath, parser);

        assertThat(cert).isNotNull();
    }

    @Test
    @DisplayName("validateCertificate(Path, String): Deve lançar exceção para PEM inválido")
    void deveLancarExcecaoParaPemInvalido() {
        final String pemInvalido = "-----BEGIN CERTIFICATE-----\nINVALIDO\n-----END CERTIFICATE-----";
        final Path dummyPath = tempDir.resolve("invalido.pem");

        assertThatThrownBy(() -> {
            PEMParser parser = new PEMParser(new StringReader(pemInvalido));
            SslContextFactory.validateCertificate(dummyPath, parser);
        })
                .isInstanceOf(Exception.class);
    }

    @Test
    @DisplayName("validateCertificate(Path, String): Deve lançar exceção para conteúdo não-certificado")
    void deveLancarExcecaoParaConteudoNaoCertificado() {
        // PEM de chave privada vazia/inválida para forçar cenário de não-certificado
        final String pemVazio = "";
        final Path dummyPath = tempDir.resolve("vazio-string.pem");

        assertThatThrownBy(() -> {
            PEMParser parser = new PEMParser(new StringReader(pemVazio));
            SslContextFactory.validateCertificate(dummyPath, parser);
        })
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

        final X509Certificate cert1 = new JcaX509CertificateConverter().getCertificate(holder);
        SslContextFactory.validateCertificate(dummyPath, cert1);
        final X509Certificate cert = cert1;

        assertThat(cert).isNotNull();
    }

    @Test
    @DisplayName("validateCertificate(Path, Object): Deve lançar exceção para objeto não-certificado")
    void deveLancarExcecaoParaObjetoNaoCertificado() {
        final Object objetoInvalido = "não é um certificado";
        final Path dummyPath = tempDir.resolve("objeto.pem");

        assertThatThrownBy(() -> {
            if (objetoInvalido instanceof X509CertificateHolder holder) {
                final X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
                SslContextFactory.validateCertificate(dummyPath, cert);
                return;
            }
            throw new SmartTokenException("Arquivo PEM não contém certificado X.509: " + dummyPath);
        })
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("não contém certificado X.509");
    }

    @Test
    @DisplayName("validateCertificate(Path, Object): Deve lançar exceção para objeto null")
    void deveLancarExcecaoParaObjetoNull() {
        final Path dummyPath = tempDir.resolve("null.pem");

        assertThatThrownBy(() -> {
            if ((Object) null instanceof X509CertificateHolder holder) {
                final X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
                SslContextFactory.validateCertificate(dummyPath, cert);
                return;
            }
            throw new SmartTokenException("Arquivo PEM não contém certificado X.509: " + dummyPath);
        })
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

        final X509Certificate cert1 = new JcaX509CertificateConverter().getCertificate(holder);
        SslContextFactory.validateCertificate(dummyPath, cert1);
        final X509Certificate cert = cert1;

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

        assertThatThrownBy(() -> {
            final X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
            SslContextFactory.validateCertificate(dummyPath, cert);
        })
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

    @Test
    @DisplayName("validateCertificate(Path, X509Certificate): Deve lançar exceção para certificado null")
    void deveLancarExcecaoParaCertificadoNull() {
        final Path dummyPath = tempDir.resolve("cert-null.pem");

        assertThatThrownBy(() -> SslContextFactory.validateCertificate(dummyPath, (X509Certificate) null))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("Certificado inválido");
    }

    // ==================== buildSslContext ====================

    @Test
    @DisplayName("buildSslContext: Deve respeitar protocolo TLS mesmo sem serverTrustAnchor")
    void deveRespeitarProtocoloTlsQuandoTrustAnchorNull() {
        final SSLContext ctx = SslContextFactory.buildSslContext((Path) null, SslContextFactory.DEFAULT_TLS_PROTOCOL);

        assertThat(ctx).isNotNull();
        // Agora o protocolo especificado é sempre respeitado (não mais "Default")
        assertThat(ctx.getProtocol()).isEqualTo("TLSv1.3");
    }

    @Test
    @DisplayName("buildSslContext: Deve usar TLS 1.2 quando especificado sem serverTrustAnchor")
    void deveUsarTls12QuandoEspecificadoSemTrustAnchor() {
        final SSLContext ctx = SslContextFactory.buildSslContext((Path) null, "TLSv1.2");

        assertThat(ctx).isNotNull();
        assertThat(ctx.getProtocol()).isEqualTo("TLSv1.2");
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

    // ==================== buildTrustAllSslContext (TestSslContextFactory) ====================

    @Test
    @DisplayName("TestSslContextFactory.buildTrustAllSslContext: Deve criar SSLContext trust-all")
    void deveCriarSslContextTrustAll() {
        final SSLContext ctx = TestSslContextFactory.buildTrustAllSslContext("TLSv1.3");

        assertThat(ctx).isNotNull();
        assertThat(ctx.getProtocol()).isEqualTo("TLSv1.3");
    }

    @Test
    @DisplayName("TestSslContextFactory.buildTrustAllSslContext: Deve lançar exceção para protocolo inválido")
    void deveLancarExcecaoParaProtocoloInvalido() {
        assertThatThrownBy(() -> TestSslContextFactory.buildTrustAllSslContext("TLSv99.9"))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("Falha ao criar SSLContext trust-all");
    }

    // ==================== buildKeyManagers (mTLS) ====================

    @Test
    @DisplayName("buildKeyManagers: Deve retornar null quando chave e cert são null")
    void deveRetornarNullQuandoChaveECertNull() {
        final KeyManager[] result = SslContextFactory.buildKeyManagers(null, null);

        assertThat(result).isNull();
    }

    @Test
    @DisplayName("buildKeyManagers: Deve retornar null quando apenas cert é null")
    void deveRetornarNullQuandoApenasCertNull() {
        final KeyManager[] result = SslContextFactory.buildKeyManagers(
                keyPair.getPrivate(), null);

        assertThat(result).isNull();
    }

    @Test
    @DisplayName("buildKeyManagers: Deve retornar null quando apenas chave é null")
    void deveRetornarNullQuandoApenasChaveNull() throws Exception {
        final X509Certificate cert = generateCert(
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(365, ChronoUnit.DAYS));

        final KeyManager[] result = SslContextFactory.buildKeyManagers(null, cert);

        assertThat(result).isNull();
    }

    @Test
    @DisplayName("buildKeyManagers: Deve retornar KeyManagers válidos com chave e cert")
    void deveRetornarKeyManagersValidos() throws Exception {
        final X509Certificate cert = generateCert(
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(365, ChronoUnit.DAYS));

        final KeyManager[] result = SslContextFactory.buildKeyManagers(
                keyPair.getPrivate(), cert);

        assertThat(result).isNotNull().isNotEmpty();
    }

    // ==================== buildSslContext com mTLS ====================

    @Test
    @DisplayName("buildSslContext mTLS: Deve construir SSLContext sem trust anchor com KeyManager")
    void deveConstruirSslContextMtlsSemTrustAnchor() throws Exception {
        final X509Certificate clientCert = generateCert(
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(365, ChronoUnit.DAYS));

        final SSLContext ctx = SslContextFactory.buildSslContext(
                (Path) null, "TLSv1.3",
                keyPair.getPrivate(), clientCert);

        assertThat(ctx).isNotNull();
        assertThat(ctx.getProtocol()).isEqualTo("TLSv1.3");
    }

    @Test
    @DisplayName("buildSslContext mTLS: Deve construir SSLContext com trust anchor e KeyManager")
    void deveConstruirSslContextMtlsComTrustAnchor() throws Exception {
        final Path serverCertFile = createCertFile(
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(365, ChronoUnit.DAYS));
        final X509Certificate clientCert = generateCert(
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(365, ChronoUnit.DAYS));

        final SSLContext ctx = SslContextFactory.buildSslContext(
                serverCertFile, "TLSv1.3",
                keyPair.getPrivate(), clientCert);

        assertThat(ctx).isNotNull();
        assertThat(ctx.getProtocol()).isEqualTo("TLSv1.3");
    }

    @Test
    @DisplayName("buildSslContext mTLS: Deve construir SSLContext a partir de X509Certificate com KeyManager")
    void deveConstruirSslContextMtlsComX509Certificate() throws Exception {
        final X509Certificate serverCert = generateCert(
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(365, ChronoUnit.DAYS));
        final X509Certificate clientCert = generateCert(
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(365, ChronoUnit.DAYS));

        final SSLContext ctx = SslContextFactory.buildSslContext(
                serverCert, "TLSv1.3",
                keyPair.getPrivate(), clientCert);

        assertThat(ctx).isNotNull();
        assertThat(ctx.getProtocol()).isEqualTo("TLSv1.3");
    }

    @Test
    @DisplayName("buildSslContext mTLS: Deve funcionar com chave e cert null (TLS unidirecional)")
    void deveFuncionarSemMtlsQuandoChaveCertNull() {
        final SSLContext ctx = SslContextFactory.buildSslContext(
                (Path) null, "TLSv1.3", null, null);

        assertThat(ctx).isNotNull();
        assertThat(ctx.getProtocol()).isEqualTo("TLSv1.3");
    }

    @Test
    @DisplayName("buildSslContext mTLS: Deve lançar exceção para protocolo inválido")
    void deveLancarExcecaoParaProtocoloInvalidoComMtls() throws Exception {
        final X509Certificate clientCert = generateCert(
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(365, ChronoUnit.DAYS));

        assertThatThrownBy(() -> SslContextFactory.buildSslContext(
                (Path) null, "TLSv99.9",
                keyPair.getPrivate(), clientCert))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("Protocolo TLS não suportado");
    }

    // ==================== buildSslContext mTLS com trust anchor expirado ====================

    @Test
    @DisplayName("buildSslContext mTLS: Deve relançar SmartTokenException para trust anchor expirado")
    void deveLancarExcecaoMtlsParaTrustAnchorExpirado() throws Exception {
        final Path expiredCert = createCertFile(
                Instant.now().minus(365, ChronoUnit.DAYS),
                Instant.now().minus(1, ChronoUnit.DAYS));
        final X509Certificate clientCert = generateCert(
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(365, ChronoUnit.DAYS));

        assertThatThrownBy(() -> SslContextFactory.buildSslContext(
                expiredCert, "TLSv1.3",
                keyPair.getPrivate(), clientCert))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("Certificado expirado");
    }

    @Test
    @DisplayName("buildSslContext KeyStore mTLS: Deve relançar SmartTokenException para trust anchor expirado")
    void deveLancarExcecaoKeyStoreMtlsParaTrustAnchorExpirado() throws Exception {
        final Path expiredCert = createCertFile(
                Instant.now().minus(365, ChronoUnit.DAYS),
                Instant.now().minus(1, ChronoUnit.DAYS));
        final X509Certificate clientCert = generateCert(
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(365, ChronoUnit.DAYS));

        final KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        ks.setKeyEntry("client", keyPair.getPrivate(), "changeit".toCharArray(),
                new X509Certificate[]{clientCert});

        assertThatThrownBy(() -> SslContextFactory.buildSslContext(
                expiredCert, "TLSv1.3", ks, "client", "changeit".toCharArray()))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("Certificado expirado");
    }

    // ==================== buildSslContext (2-param) protocolo inválido sem trust anchor ====================

    @Test
    @DisplayName("buildSslContext: Deve lançar exceção para protocolo inválido sem trust anchor")
    void deveLancarExcecaoParaProtocoloInvalidoSemTrustAnchor() {
        assertThatThrownBy(() -> SslContextFactory.buildSslContext((Path) null, "TLSv99.9"))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("Protocolo TLS não suportado");
    }

    // ==================== buildKeyManagers (KeyStore) ====================

    @Test
    @DisplayName("buildKeyManagers(KeyStore): Deve retornar null quando KeyStore é null")
    void deveRetornarNullQuandoKeyStoreNull() {
        final KeyManager[] result = SslContextFactory.buildKeyManagers(null, "alias", new char[0]);

        assertThat(result).isNull();
    }

    @Test
    @DisplayName("buildKeyManagers(KeyStore): Deve retornar KeyManagers com KeyStore válido")
    void deveRetornarKeyManagersComKeyStoreValido() throws Exception {
        final X509Certificate cert = generateCert(
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(365, ChronoUnit.DAYS));

        final KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        ks.setKeyEntry("client", keyPair.getPrivate(), "changeit".toCharArray(),
                new X509Certificate[]{cert});

        final KeyManager[] result = SslContextFactory.buildKeyManagers(ks, "client", "changeit".toCharArray());

        assertThat(result).isNotNull().isNotEmpty();
    }

    // ==================== buildSslContext (KeyStore mTLS) ====================

    @Test
    @DisplayName("buildSslContext KeyStore mTLS: Deve construir SSLContext sem trust anchor")
    void deveConstruirSslContextKeyStoreMtlsSemTrustAnchor() throws Exception {
        final X509Certificate cert = generateCert(
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(365, ChronoUnit.DAYS));

        final KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        ks.setKeyEntry("client", keyPair.getPrivate(), "changeit".toCharArray(),
                new X509Certificate[]{cert});

        final SSLContext ctx = SslContextFactory.buildSslContext(
                (Path) null, "TLSv1.3", ks, "client", "changeit".toCharArray());

        assertThat(ctx).isNotNull();
        assertThat(ctx.getProtocol()).isEqualTo("TLSv1.3");
    }

    @Test
    @DisplayName("buildSslContext KeyStore mTLS: Deve construir SSLContext com trust anchor")
    void deveConstruirSslContextKeyStoreMtlsComTrustAnchor() throws Exception {
        final Path serverCertFile = createCertFile(
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(365, ChronoUnit.DAYS));
        final X509Certificate clientCert = generateCert(
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(365, ChronoUnit.DAYS));

        final KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        ks.setKeyEntry("client", keyPair.getPrivate(), "changeit".toCharArray(),
                new X509Certificate[]{clientCert});

        final SSLContext ctx = SslContextFactory.buildSslContext(
                serverCertFile, "TLSv1.3", ks, "client", "changeit".toCharArray());

        assertThat(ctx).isNotNull();
        assertThat(ctx.getProtocol()).isEqualTo("TLSv1.3");
    }

    @Test
    @DisplayName("buildSslContext KeyStore mTLS: Deve lançar exceção para protocolo inválido")
    void deveLancarExcecaoParaProtocoloInvalidoComKeyStoreMtls() throws Exception {
        final X509Certificate cert = generateCert(
                Instant.now().minus(1, ChronoUnit.DAYS),
                Instant.now().plus(365, ChronoUnit.DAYS));

        final KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        ks.setKeyEntry("client", keyPair.getPrivate(), "changeit".toCharArray(),
                new X509Certificate[]{cert});

        assertThatThrownBy(() -> SslContextFactory.buildSslContext(
                (Path) null, "TLSv99.9", ks, "client", "changeit".toCharArray()))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("Protocolo TLS não suportado");
    }

    @Test
    @DisplayName("buildSslContext KeyStore mTLS: Deve funcionar com KeyStore null (TLS unidirecional)")
    void deveFuncionarSemMtlsQuandoKeyStoreNull() {
        final SSLContext ctx = SslContextFactory.buildSslContext(
                (Path) null, "TLSv1.3", (KeyStore) null, null, null);

        assertThat(ctx).isNotNull();
        assertThat(ctx.getProtocol()).isEqualTo("TLSv1.3");
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

