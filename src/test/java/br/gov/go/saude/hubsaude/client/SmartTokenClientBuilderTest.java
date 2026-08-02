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
import java.io.OutputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.sun.net.httpserver.HttpServer;

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

    /** Clientes criados pelo teste corrente, fechados no {@code @AfterEach} (#1810). */
    private final List<SmartTokenClient> clientesAbertos = new ArrayList<>();

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

    /**
     * Registra o cliente para fechamento automático ao fim do teste,
     * liberando o {@code HttpClient} interno (threads e conexões).
     *
     * @param client cliente recém-criado
     * @return o próprio cliente, para uso fluente
     */
    private SmartTokenClient registrar(final SmartTokenClient client) {
        clientesAbertos.add(client);
        return client;
    }

    @AfterEach
    void fecharClientes() {
        clientesAbertos.forEach(SmartTokenClient::close);
        clientesAbertos.clear();
    }

    // ==================== Validações obrigatórias ====================

    @Test
    @DisplayName("Deve exigir tokenEndpoint ou fhirBase")
    void deveExigirTokenEndpoint() {
        assertThatThrownBy(() -> SmartTokenClient.builder()
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("tokenEndpoint ou fhirBase");
    }

    @Test
    @DisplayName("Deve rejeitar tokenEndpoint e discoverTokenEndpointFrom simultâneos")
    void deveRejeitarAmbosTokenEndpoints() {
        assertThatThrownBy(() -> SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .fhirBase("https://fhir.example.com")
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Defina tokenEndpoint OU fhirBase");
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
        final SmartTokenClient client = registrar(SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .certificatePem(certFile)
                .build());

        assertThat(client).isNotNull();
        assertThat(client.buildClientAssertion()).isNotBlank();
    }

    @Test
    @DisplayName("Deve construir cliente com privateKeyPem sem certificado")
    void deveConstruirComPrivateKeyPemSemCertificado() throws Exception {
        final SmartTokenClient client = registrar(SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .build());

        assertThat(client).isNotNull();
        assertThat(client.buildClientAssertion()).isNotBlank();
    }

    // ==================== Construção com SigningStrategy ====================

    @Test
    @DisplayName("Deve construir cliente com SigningStrategy customizada")
    void deveConstruirComSigningStrategy() throws Exception {
        final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(keyPair.getPrivate());

        final SmartTokenClient client = registrar(SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .signingStrategy(strategy)
                .build());

        assertThat(client).isNotNull();
        assertThat(client.buildClientAssertion()).isNotBlank();
    }

    @Test
    @DisplayName("Deve construir cliente com SigningStrategy e certificado")
    void deveConstruirComSigningStrategyECertificado() throws Exception {
        final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(keyPair.getPrivate());

        final SmartTokenClient client = registrar(SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .signingStrategy(strategy)
                .certificatePem(certFile)
                .build());

        assertThat(client).isNotNull();
    }

    // ==================== Timeouts e parametrização ====================

    @Test
    @DisplayName("Deve aplicar timeout de conexão customizado")
    void deveAplicarConnectTimeout() throws Exception {
        final SmartTokenClient client = registrar(SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .connectTimeout(Duration.ofSeconds(15))
                .build());

        assertThat(client).isNotNull();
    }

    @Test
    @DisplayName("Deve aplicar timeout de requisição customizado")
    void deveAplicarRequestTimeout() throws Exception {
        final SmartTokenClient client = registrar(SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .requestTimeout(Duration.ofSeconds(60))
                .build());

        assertThat(client).isNotNull();
    }

    @Test
    @DisplayName("Deve aplicar TTL do assertion customizado")
    void deveAplicarAssertionTtl() throws Exception {
        final SmartTokenClient client = registrar(SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .assertionTtlSeconds(180)
                .build());

        assertThat(client).isNotNull();
    }

    @Test
    @DisplayName("Deve aplicar maxRetries customizado")
    void deveAplicarMaxRetries() throws Exception {
        final SmartTokenClient client = registrar(SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .maxRetries(5)
                .build());

        assertThat(client).isNotNull();
    }

    // ==================== Cache ====================

    @Test
    @DisplayName("Deve desabilitar cache de tokens")
    void deveDesabilitarCache() throws Exception {
        final SmartTokenClient client = registrar(SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .enableTokenCache(false)
                .build());

        assertThat(client).isNotNull();
    }

    @Test
    @DisplayName("Deve aplicar margem de cache customizada")
    void deveAplicarMargemDeCache() throws Exception {
        final SmartTokenClient client = registrar(SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .enableTokenCache(true)
                .tokenCacheMarginSeconds(60)
                .build());

        assertThat(client).isNotNull();
    }

    // ==================== SSL/TLS ====================

    @Test
    @DisplayName("Deve aplicar protocolo TLS customizado")
    void deveAplicarTlsProtocol() throws Exception {
        final SmartTokenClient client = registrar(SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .certificatePem(certFile)
                .tlsProtocol("TLSv1.2")
                .build());

        assertThat(client).isNotNull();
    }

    @Test
    @DisplayName("Deve aplicar SSLContext customizado via sslContext()")
    void deveAplicarSslContextCustomizado() throws Exception {
        final SSLContext trustAll = TestSslContextFactory.buildTrustAllSslContext(
                SslContextFactory.DEFAULT_TLS_PROTOCOL);

        final SmartTokenClient client = registrar(SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .sslContext(trustAll)
                .build());

        assertThat(client).isNotNull();
    }

    @Test
    @DisplayName("Deve aplicar serverTrustAnchor")
    void deveAplicarServerTrustAnchor() throws Exception {
        final SmartTokenClient client = registrar(SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .serverTrustAnchor(certFile)
                .build());

        assertThat(client).isNotNull();
    }

    // ==================== Construção completa ====================

    @Test
    @DisplayName("Deve construir cliente com todos os parâmetros")
    void deveConstruirComTodosOsParametros() throws Exception {
        final SmartTokenClient client = registrar(SmartTokenClient.builder()
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
                .build());

        assertThat(client).isNotNull();
        assertThat(client.buildClientAssertion()).isNotBlank().contains(".");
    }

    // ==================== Fluidez da API ====================

    @Test
    @DisplayName("Deve retornar mesma instância do builder em cada setter")
    void deveRetornarMesmaInstancia() {
        final SmartTokenClientBuilder builder = SmartTokenClient.builder();
        assertThat(builder.tokenEndpoint(TOKEN_ENDPOINT)).isSameAs(builder);
        assertThat(builder.fhirBase("http://fhir.local")).isSameAs(builder);
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
        assertThat(builder.tokenCacheMaxEntries(1_000)).isSameAs(builder);
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

    // ==================== Discovery ====================

    @Test
    @DisplayName("Deve obter tokenEndpoint via discovery (smart-configuration)")
    void deveObterTokenEndpointViaDiscovery() throws Exception {
        final String expectedEndpoint = "https://hub.saude.go.gov.br/auth/token";
        final String jsonResponse = "{\"token_endpoint\":\"" + expectedEndpoint + "\"}";

        final HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/.well-known/smart-configuration", exchange -> {
            final byte[] resp = jsonResponse.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, resp.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(resp);
            }
        });
        server.start();

        try {
            final String baseUrl = "http://localhost:" + server.getAddress().getPort();

            final SmartTokenClient client = registrar(SmartTokenClient.builder()
                    .fhirBase(baseUrl)
                    .clientId(CLIENT_ID)
                    .privateKeyPem(keyFile)
                    .build());

            assertThat(client).isNotNull();
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("Deve enviar traceparent W3C válido na requisição de discovery")
    void deveEnviarTraceparentValidoNoDiscovery() throws Exception {
        final String jsonResponse = "{\"token_endpoint\":\"https://hub.saude.go.gov.br/auth/token\"}";
        final AtomicReference<String> receivedTraceparent = new AtomicReference<>();

        final HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/.well-known/smart-configuration", exchange -> {
            receivedTraceparent.set(exchange.getRequestHeaders().getFirst("traceparent"));
            final byte[] resp = jsonResponse.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, resp.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(resp);
            }
        });
        server.start();

        try {
            final String baseUrl = "http://localhost:" + server.getAddress().getPort();

            SmartTokenClientBuilder.discoverTokenEndpoint(
                    baseUrl, SSLContext.getDefault(), Duration.ofSeconds(5), Duration.ofSeconds(5));

            assertThat(receivedTraceparent.get()).matches("^00-[0-9a-f]{32}-[0-9a-f]{16}-00$");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("Deve rejeitar token_endpoint descoberto com esquema http não-local")
    void deveRejeitarTokenEndpointDescobertoHttpNaoLocal() throws Exception {
        final String jsonResponse = "{\"token_endpoint\":\"http://exemplo.com/auth/token\"}";

        final HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/.well-known/smart-configuration", exchange -> {
            final byte[] resp = jsonResponse.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, resp.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(resp);
            }
        });
        server.start();

        try {
            final String baseUrl = "http://localhost:" + server.getAddress().getPort();

            assertThatThrownBy(() -> SmartTokenClientBuilder.discoverTokenEndpoint(
                    baseUrl, SSLContext.getDefault(), Duration.ofSeconds(5), Duration.ofSeconds(5)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("https");
        } finally {
            server.stop(0);
        }
    }

    // ==================== build com clientKeyStore (mTLS via KeyStore) ====================

    @Test
    @DisplayName("build: Deve construir SmartTokenClient com clientKeyStore (mTLS via KeyStore)")
    void deveConstruirComClientKeyStore() throws Exception {
        final X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider())
                .getCertificate(
                        new JcaX509v3CertificateBuilder(
                                new X500Name("CN=KeyStore-Test"),
                                BigInteger.valueOf(System.nanoTime()),
                                java.util.Date.from(Instant.now()),
                                java.util.Date.from(Instant.now().plusSeconds(86400)),
                                new X500Name("CN=KeyStore-Test"),
                                keyPair.getPublic())
                                .build(new JcaContentSignerBuilder("SHA256withRSA")
                                        .build(keyPair.getPrivate())));

        final KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        ks.setKeyEntry("client", keyPair.getPrivate(), "changeit".toCharArray(),
                new java.security.cert.Certificate[]{cert});

        final SmartTokenClient client = registrar(SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .certificatePem(certFile)
                .clientKeyStore(ks, "client", "changeit".toCharArray())
                .build());

        assertThat(client).isNotNull();
    }

    @Test
    @DisplayName("build: Deve consumir (zerar) as senhas fornecidas após a construção")
    void deveZerarSenhasAposBuild() throws Exception {
        final X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider())
                .getCertificate(
                        new JcaX509v3CertificateBuilder(
                                new X500Name("CN=KeyStore-Test"),
                                BigInteger.valueOf(System.nanoTime()),
                                java.util.Date.from(Instant.now()),
                                java.util.Date.from(Instant.now().plusSeconds(86400)),
                                new X500Name("CN=KeyStore-Test"),
                                keyPair.getPublic())
                                .build(new JcaContentSignerBuilder("SHA256withRSA")
                                        .build(keyPair.getPrivate())));

        final KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        ks.setKeyEntry("client", keyPair.getPrivate(), "changeit".toCharArray(),
                new java.security.cert.Certificate[]{cert});

        final char[] senhaChave = "senha-nao-usada".toCharArray();
        final char[] senhaKeyStore = "changeit".toCharArray();

        final SmartTokenClient client = registrar(SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .privateKeyPassword(senhaChave)
                .certificatePem(certFile)
                .clientKeyStore(ks, "client", senhaKeyStore)
                .build());

        assertThat(client).isNotNull();
        assertThat(senhaChave).containsOnly('\0');
        assertThat(senhaKeyStore).containsOnly('\0');
    }

    @Test
    @DisplayName("Deve permitir reutilizar o mesmo PIN entre fromKeyStore e clientKeyStore")
    void devePermitirReutilizarPinEntreFromKeyStoreEClientKeyStore() throws Exception {
        final X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider())
                .getCertificate(
                        new JcaX509v3CertificateBuilder(
                                new X500Name("CN=KeyStore-Test"),
                                BigInteger.valueOf(System.nanoTime()),
                                java.util.Date.from(Instant.now()),
                                java.util.Date.from(Instant.now().plusSeconds(86400)),
                                new X500Name("CN=KeyStore-Test"),
                                keyPair.getPublic())
                                .build(new JcaContentSignerBuilder("SHA256withRSA")
                                        .build(keyPair.getPrivate())));

        final KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        ks.setKeyEntry("client", keyPair.getPrivate(), "changeit".toCharArray(),
                new java.security.cert.Certificate[]{cert});

        final char[] pin = "changeit".toCharArray();

        // fromKeyStore faz cópia defensiva: o array do chamador fica intacto
        final SigningStrategy strategy = SigningStrategyFactory.fromKeyStore(ks, "client", pin);
        assertThat(pin).containsExactly("changeit".toCharArray());

        // O mesmo PIN pode ser reutilizado para mTLS via clientKeyStore
        final SmartTokenClient client = registrar(SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .signingStrategy(strategy)
                .clientKeyStore(ks, "client", pin)
                .build());

        assertThat(client).isNotNull();
        // build() consome (zera) o PIN ao final — semântica documentada
        assertThat(pin).containsOnly('\0');
    }

    @Test
    @DisplayName("static discoverTokenEndpoint: Deve lançar SmartTokenException quando backend falhar (HTTP != 200)")
    void deveFalharSeDiscoveryRetornarErroHttp() throws Exception {
        final HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/.well-known/smart-configuration", exchange -> {
            final byte[] error = "Not Found".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(404, error.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(error);
            }
        });
        server.start();

        try {
            final String baseUrl = "http://localhost:" + server.getAddress().getPort();

            assertThatThrownBy(() -> SmartTokenClientBuilder.discoverTokenEndpoint(
                    baseUrl, SSLContext.getDefault(), Duration.ofSeconds(5), Duration.ofSeconds(5)))
                    .isInstanceOf(SmartTokenException.class)
                    .hasMessageContaining("Falha ao obter smart-configuration (404")
                    .hasMessageContaining("traceId=");

        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("static discoverTokenEndpoint: Deve lançar SmartTokenException se faltar token_endpoint")
    void deveFalharSeNaoHouverTokenEndpointNoDiscovery() throws Exception {
        final HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/.well-known/smart-configuration", exchange -> {
            final String json = "{\"authorization_endpoint\":\"https://example.com/auth\"}";
            final byte[] resp = json.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, resp.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(resp);
            }
        });
        server.start();

        try {
            final String baseUrl = "http://localhost:" + server.getAddress().getPort();

            assertThatThrownBy(() -> SmartTokenClientBuilder.discoverTokenEndpoint(
                    baseUrl, SSLContext.getDefault(), Duration.ofSeconds(5), Duration.ofSeconds(5)))
                    .isInstanceOf(SmartTokenException.class)
                    .hasMessageContaining("não contém 'token_endpoint'");

        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("static discoverTokenEndpoint: Deve falhar se houver problema de I/O de rede")
    void deveOcorrerIoExceptionNoNetworkError() {
        assertThatThrownBy(() -> SmartTokenClientBuilder.discoverTokenEndpoint(
                "http://localhost:59999", SSLContext.getDefault(), Duration.ofSeconds(1), Duration.ofSeconds(1)))
                .isInstanceOf(IOException.class);
    }

    @Test
    @DisplayName("static discoverTokenEndpoint: Deve construir URL correta quando fhirBase termina com /")
    void deveDescobriTokenEndpointComBarraFinal() throws Exception {
        final HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        final String expectedTokenEndpoint = "https://auth.example.com/token";
        server.createContext("/.well-known/smart-configuration", exchange -> {
            final String json = "{\"token_endpoint\":\"" + expectedTokenEndpoint + "\"}";
            final byte[] resp = json.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, resp.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(resp);
            }
        });
        server.start();

        try {
            // URL com barra final
            final String baseUrl = "http://localhost:" + server.getAddress().getPort() + "/";

            final String tokenEndpoint = SmartTokenClientBuilder.discoverTokenEndpoint(
                    baseUrl, SSLContext.getDefault(), Duration.ofSeconds(5), Duration.ofSeconds(5));

            assertThat(tokenEndpoint).isEqualTo(expectedTokenEndpoint);
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("static discoverTokenEndpoint: Deve construir URL correta quando fhirBase NÃO termina com /")
    void deveDescobriTokenEndpointSemBarraFinal() throws Exception {
        final HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        final String expectedTokenEndpoint = "https://auth.example.com/token";
        server.createContext("/.well-known/smart-configuration", exchange -> {
            final String json = "{\"token_endpoint\":\"" + expectedTokenEndpoint + "\"}";
            final byte[] resp = json.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, resp.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(resp);
            }
        });
        server.start();

        try {
            // URL sem barra final
            final String baseUrl = "http://localhost:" + server.getAddress().getPort();

            final String tokenEndpoint = SmartTokenClientBuilder.discoverTokenEndpoint(
                    baseUrl, SSLContext.getDefault(), Duration.ofSeconds(5), Duration.ofSeconds(5));

            assertThat(tokenEndpoint).isEqualTo(expectedTokenEndpoint);
        } finally {
            server.stop(0);
        }
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
                java.util.Date.from(now),
                java.util.Date.from(now.plusSeconds(86400)),
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
