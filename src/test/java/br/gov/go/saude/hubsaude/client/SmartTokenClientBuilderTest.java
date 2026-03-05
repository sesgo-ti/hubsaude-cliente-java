/*
 * Copyright (c) 2026 SES-GO / UFG
 * Todos os direitos reservados.
 */

package br.gov.go.saude.hubsaude.client;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import javax.net.ssl.SSLContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Testes unitários para {@link SmartTokenClientBuilder}.
 *
 * <p>
 * Cobre validações do builder, fluxos de construção (PEM, SigningStrategy),
 * exclusividade mútua, valores padrão e parametrização completa.
 * </p>
 */
@DisplayName("SmartTokenClientBuilder")
class SmartTokenClientBuilderTest {

    private static final String TOKEN_ENDPOINT = "https://auth.example.com/token";
    private static final String CLIENT_ID = "builder-test-client";

    @TempDir
    private static Path tempDir;

    private static Path keyFile;
    private static Path certFile;
    private static KeyPair keyPair;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        final KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        keyPair = gen.generateKeyPair();

        // Chave privada
        keyFile = tempDir.resolve("test-key.pem");
        final String keyPem = toPkcs8Pem(keyPair.getPrivate().getEncoded());
        Files.writeString(keyFile, keyPem, StandardCharsets.UTF_8);

        // Certificado
        certFile = tempDir.resolve("test-cert.pem");
        final String certPem = generateSelfSignedCertPem(keyPair);
        Files.writeString(certFile, certPem, StandardCharsets.UTF_8);
    }

    // ==================== Validações obrigatórias ====================

    @Test
    @DisplayName("Deve exigir tokenEndpoint")
    void deveExigirTokenEndpoint() {
        assertThatThrownBy(() -> SmartTokenClient.builder()
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .build())
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("tokenEndpoint");
    }

    @Test
    @DisplayName("Deve exigir clientId")
    void deveExigirClientId() {
        assertThatThrownBy(() -> SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .privateKeyPem(keyFile)
                .build())
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("clientId");
    }

    @Test
    @DisplayName("Deve exigir signingStrategy ou privateKeyPem")
    void deveExigirAssinaturaOuChave() {
        assertThatThrownBy(() -> SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("signingStrategy ou privateKeyPem");
    }

    @Test
    @DisplayName("Deve rejeitar signingStrategy E privateKeyPem simultâneos")
    void deveRejeitarAmbosSigningStrategyEPrivateKeyPem() {
        final SigningStrategy mockStrategy = data -> new byte[0];

        assertThatThrownBy(() -> SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .signingStrategy(mockStrategy)
                .build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("signingStrategy OU privateKeyPem");
    }

    // ==================== Construção com privateKeyPem ====================

    @Test
    @DisplayName("Deve construir cliente com privateKeyPem e certificado")
    void deveConstruirComPrivateKeyPem() throws Exception {
        final SmartTokenClient client = SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .certificatePem(certFile)
                .build();

        assertThat(client).isNotNull();
        assertThat(client.buildClientAssertion()).isNotBlank();
    }

    @Test
    @DisplayName("Deve construir cliente com privateKeyPem sem certificado")
    void deveConstruirComPrivateKeyPemSemCertificado() throws Exception {
        final SmartTokenClient client = SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .build();

        assertThat(client).isNotNull();
        assertThat(client.buildClientAssertion()).isNotBlank();
    }

    // ==================== Construção com SigningStrategy ====================

    @Test
    @DisplayName("Deve construir cliente com SigningStrategy customizada")
    void deveConstruirComSigningStrategy() throws Exception {
        final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(keyPair.getPrivate());

        final SmartTokenClient client = SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .signingStrategy(strategy)
                .build();

        assertThat(client).isNotNull();
        assertThat(client.buildClientAssertion()).isNotBlank();
    }

    @Test
    @DisplayName("Deve construir cliente com SigningStrategy e certificado")
    void deveConstruirComSigningStrategyECertificado() throws Exception {
        final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(keyPair.getPrivate());

        final SmartTokenClient client = SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .signingStrategy(strategy)
                .certificatePem(certFile)
                .build();

        assertThat(client).isNotNull();
    }

    // ==================== Timeouts e parametrização ====================

    @Test
    @DisplayName("Deve aplicar timeout de conexão customizado")
    void deveAplicarConnectTimeout() throws Exception {
        final SmartTokenClient client = SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .connectTimeout(Duration.ofSeconds(15))
                .build();

        assertThat(client).isNotNull();
    }

    @Test
    @DisplayName("Deve aplicar timeout de requisição customizado")
    void deveAplicarRequestTimeout() throws Exception {
        final SmartTokenClient client = SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .requestTimeout(Duration.ofSeconds(60))
                .build();

        assertThat(client).isNotNull();
    }

    @Test
    @DisplayName("Deve aplicar TTL do assertion customizado")
    void deveAplicarAssertionTtl() throws Exception {
        final SmartTokenClient client = SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .assertionTtlSeconds(180)
                .build();

        assertThat(client).isNotNull();
    }

    @Test
    @DisplayName("Deve aplicar maxRetries customizado")
    void deveAplicarMaxRetries() throws Exception {
        final SmartTokenClient client = SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .maxRetries(5)
                .build();

        assertThat(client).isNotNull();
    }

    // ==================== Cache ====================

    @Test
    @DisplayName("Deve desabilitar cache de tokens")
    void deveDesabilitarCache() throws Exception {
        final SmartTokenClient client = SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .enableTokenCache(false)
                .build();

        assertThat(client).isNotNull();
    }

    @Test
    @DisplayName("Deve aplicar margem de cache customizada")
    void deveAplicarMargemDeCache() throws Exception {
        final SmartTokenClient client = SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .enableTokenCache(true)
                .tokenCacheMarginSeconds(60)
                .build();

        assertThat(client).isNotNull();
    }

    // ==================== SSL/TLS ====================

    @Test
    @DisplayName("Deve aplicar protocolo TLS customizado")
    void deveAplicarTlsProtocol() throws Exception {
        final SmartTokenClient client = SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .certificatePem(certFile)
                .tlsProtocol("TLSv1.2")
                .build();

        assertThat(client).isNotNull();
    }

    @Test
    @DisplayName("Deve aplicar SSLContext customizado via sslContext()")
    void deveAplicarSslContextCustomizado() throws Exception {
        final SSLContext trustAll = SslContextFactory.buildTrustAllSslContext(
                SslContextFactory.DEFAULT_TLS_PROTOCOL);

        final SmartTokenClient client = SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .sslContext(trustAll)
                .build();

        assertThat(client).isNotNull();
    }

    @Test
    @DisplayName("Deve aplicar serverTrustAnchor")
    void deveAplicarServerTrustAnchor() throws Exception {
        final SmartTokenClient client = SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .serverTrustAnchor(certFile)
                .build();

        assertThat(client).isNotNull();
    }

    // ==================== Construção completa ====================

    @Test
    @DisplayName("Deve construir cliente com todos os parâmetros")
    void deveConstruirComTodosOsParametros() throws Exception {
        final SmartTokenClient client = SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .certificatePem(certFile)
                .tlsProtocol("TLSv1.3")
                .connectTimeout(Duration.ofSeconds(10))
                .requestTimeout(Duration.ofSeconds(30))
                .assertionTtlSeconds(120)
                .enableTokenCache(true)
                .tokenCacheMarginSeconds(45)
                .maxRetries(4)
                .build();

        assertThat(client).isNotNull();
        assertThat(client.buildClientAssertion()).isNotBlank().contains(".");
    }

    // ==================== Fluidez da API ====================

    @Test
    @DisplayName("Deve retornar mesma instância do builder em cada setter")
    void deveRetornarMesmaInstancia() {
        final SmartTokenClientBuilder builder = SmartTokenClient.builder();
        assertThat(builder.tokenEndpoint(TOKEN_ENDPOINT)).isSameAs(builder);
        assertThat(builder.clientId(CLIENT_ID)).isSameAs(builder);
        assertThat(builder.privateKeyPem(keyFile)).isSameAs(builder);
        assertThat(builder.certificatePem(certFile)).isSameAs(builder);
        assertThat(builder.privateKeyPassword("test".toCharArray())).isSameAs(builder);
        assertThat(builder.tlsProtocol("TLSv1.3")).isSameAs(builder);
        assertThat(builder.connectTimeout(Duration.ofSeconds(5))).isSameAs(builder);
        assertThat(builder.requestTimeout(Duration.ofSeconds(10))).isSameAs(builder);
        assertThat(builder.assertionTtlSeconds(300)).isSameAs(builder);
        assertThat(builder.enableTokenCache(true)).isSameAs(builder);
        assertThat(builder.tokenCacheMarginSeconds(30)).isSameAs(builder);
        assertThat(builder.maxRetries(3)).isSameAs(builder);
        assertThat(builder.serverTrustAnchor(certFile)).isSameAs(builder);
    }

    // ==================== Erros de IO ====================

    @Test
    @DisplayName("Deve falhar com chave PEM inexistente")
    void deveFalharComChaveInexistente() {
        assertThatThrownBy(() -> SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(Path.of("/tmp/inexistente-key.pem"))
                .build())
                .isInstanceOf(IOException.class);
    }

    @Test
    @DisplayName("Deve falhar com certificado PEM inexistente")
    void deveFalharComCertificadoInexistente() {
        assertThatThrownBy(() -> SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .certificatePem(Path.of("/tmp/inexistente-cert.pem"))
                .build())
                .isInstanceOf(IOException.class);
    }

    @Test
    @DisplayName("Deve falhar com arquivo PEM inválido como chave")
    void deveFalharComChavePemInvalida(@TempDir final Path td) throws Exception {
        final Path badKey = td.resolve("bad-key.pem");
        Files.writeString(badKey, "conteudo invalido", StandardCharsets.UTF_8);

        assertThatThrownBy(() -> SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(badKey)
                .build())
                .isInstanceOf(Exception.class);
    }

    @Test
    @DisplayName("Deve falhar com arquivo PEM inválido como certificado")
    void deveFalharComCertificadoPemInvalido(@TempDir final Path td) throws Exception {
        final Path badCert = td.resolve("bad-cert.pem");
        Files.writeString(badCert, "-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----",
                StandardCharsets.UTF_8);

        assertThatThrownBy(() -> SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .certificatePem(badCert)
                .build())
                .isInstanceOf(Exception.class);
    }

    // ==================== Helpers ====================

    private static String toPkcs8Pem(final byte[] encoded) {
        return "-----BEGIN PRIVATE KEY-----\n"
                + java.util.Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                        .encodeToString(encoded)
                + "\n-----END PRIVATE KEY-----\n";
    }

    private static String generateSelfSignedCertPem(final KeyPair pair) throws Exception {
        final Instant now = Instant.now();
        final X500Name dn = new X500Name("CN=SmartTokenClientBuilder-Test");
        final ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate());
        final X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                dn,
                BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now),
                Date.from(now.plusSeconds(86400)),
                dn,
                pair.getPublic());

        final var cert = new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider())
                .getCertificate(certBuilder.build(signer));

        final StringWriter sw = new StringWriter();
        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(cert);
        }
        return sw.toString();
    }
}
