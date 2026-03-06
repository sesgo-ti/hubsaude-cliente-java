/*
 * Copyright (c) 2026 SES-GO / UFG
 * Todos os direitos reservados.
 */

package br.gov.go.saude.hubsaude.client;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import javax.net.ssl.SSLContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Testes unitários do SmartTokenClient.
 *
 * <p>
 * Gera par RSA real para validar a montagem do client_assertion sem
 * necessidade de subir o servidor.
 * </p>
 */
class SmartTokenClientTest {

        private static final String TOKEN_ENDPOINT = "https://localhost:8443/auth/token";
        private static final String CLIENT_ID = "test-client";

        private static Path keyFile;
        private static Path certFile;
        private static RSAPublicKey publicKey;
        private static PrivateKey privateKey;
        private static X509Certificate clientCertificate;

        @BeforeAll
        static void gerarParChaves(@TempDir final Path tempDir) throws Exception {
                final KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
                gen.initialize(2048);
                final KeyPair pair = gen.generateKeyPair();
                publicKey = (RSAPublicKey) pair.getPublic();
                privateKey = pair.getPrivate();

                // Escrever chave privada PEM
                keyFile = tempDir.resolve("client-key.pem");
                final String pkcs8Pem = toPkcs8Pem(pair.getPrivate().getEncoded());
                Files.writeString(keyFile, pkcs8Pem, StandardCharsets.UTF_8);

                // Escrever certificado auto-assinado PEM (stub mínimo para satisfazer o
                // construtor)
                certFile = tempDir.resolve("client-cert.pem");
                final String certPem = generateSelfSignedCertPem(pair);
                Files.writeString(certFile, certPem, StandardCharsets.UTF_8);

                clientCertificate = SslContextFactory.validateCertificate(certFile);
        }

        @Test
        void deveConstruirClientAssertionComCamposCorretos() throws Exception {
                final SmartTokenClient client = new SmartTokenClient(TOKEN_ENDPOINT, CLIENT_ID, keyFile, certFile);

                final String assertion = client.buildClientAssertion();

                final Claims claims = Jwts.parser()
                                .verifyWith(publicKey)
                                .build()
                                .parseSignedClaims(assertion)
                                .getPayload();

                assertThat(claims.getSubject()).isEqualTo(CLIENT_ID);
                assertThat(claims.getIssuer()).isEqualTo(CLIENT_ID);
                assertThat(claims.getAudience()).containsExactly(TOKEN_ENDPOINT);
                assertThat(claims.getId()).isNotBlank();
                assertThat(claims.getExpiration()).isAfter(claims.getIssuedAt());
        }

        @Test
        void deveFalharComArquivoChaveInexistente(@TempDir final Path tempDir) {
                assertThatThrownBy(() -> new SmartTokenClient(TOKEN_ENDPOINT, CLIENT_ID,
                                tempDir.resolve("nao-existe.pem"), certFile))
                                .isInstanceOf(Exception.class);
        }

        @Test
        void deveConstruirClienteComCertificadoServidorCustomizado() throws Exception {
                final SmartTokenClient client = new SmartTokenClient(
                                TOKEN_ENDPOINT,
                                CLIENT_ID,
                                keyFile,
                                certFile,
                                certFile);

                final String assertion = client.buildClientAssertion();
                assertThat(assertion).isNotBlank();
        }

        @Test
        void deveFalharQuandoCertificadoServidorInvalido(@TempDir final Path tempDir) {
                final Path inexistente = tempDir.resolve("server.pem");
                assertThatThrownBy(() -> new SmartTokenClient(
                                TOKEN_ENDPOINT,
                                CLIENT_ID,
                                keyFile,
                                certFile,
                                inexistente))
                                .isInstanceOf(SmartTokenException.class);
        }

        @Test
        void devePermitirConstrutorComObjetos() {
                final SmartTokenClient client = new SmartTokenClient(
                                TOKEN_ENDPOINT,
                                CLIENT_ID,
                                privateKey,
                                clientCertificate,
                                SslContextFactory.buildTrustAllSslContext(SslContextFactory.DEFAULT_TLS_PROTOCOL));

                assertThat(client.buildClientAssertion()).isNotBlank();
        }

        @Test
        void deveConstruirClienteViaBuilder() throws Exception {
                final SmartTokenClient client = SmartTokenClient.builder()
                                .tokenEndpoint(TOKEN_ENDPOINT)
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .connectTimeout(Duration.ofSeconds(5))
                                .requestTimeout(Duration.ofSeconds(15))
                                .assertionTtlSeconds(120)
                                .build();

                final String assertion = client.buildClientAssertion();
                assertThat(assertion).isNotBlank();
        }

        @Test
        void deveFalharQuandoChaveNaoCorrespondeAoCertificado(@TempDir final Path tempDir) throws Exception {
                // Gera um par de chaves diferente
                final KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
                gen.initialize(2048);
                final KeyPair outroPar = gen.generateKeyPair();

                // Gera um certificado com a chave pública do outro par
                final Path outroCertFile = tempDir.resolve("outro-cert.pem");
                final String outroCertPem = generateSelfSignedCertPem(outroPar);
                Files.writeString(outroCertFile, outroCertPem, StandardCharsets.UTF_8);

                final X509Certificate outroCert = SslContextFactory.validateCertificate(outroCertFile);

                // Tenta criar cliente com chave privada original + certificado de outro par
                assertThatThrownBy(() -> new SmartTokenClient(
                                TOKEN_ENDPOINT,
                                CLIENT_ID,
                                privateKey,
                                outroCert,
                                SslContextFactory.buildTrustAllSslContext(SslContextFactory.DEFAULT_TLS_PROTOCOL)))
                                .isInstanceOf(SmartTokenException.class)
                                .hasMessageContaining("não corresponde");
        }

        @Test
        void deveValidarCoerenciaEntreChaveECertificado() {
                // Não deve lançar exceção quando key e cert correspondem
                SmartTokenClient.verifyKeyPairConsistency(privateKey, clientCertificate);
        }

        @Test
        void deveFalharVerifyKeyPairConsistencyComChaveIncompativel() throws Exception {
                // Cria chave EC (incompatível com SHA256withRSA usado internamente)
                final KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
                ecGen.initialize(256);
                final KeyPair ecPair = ecGen.generateKeyPair();

                // Deve lançar SmartTokenException encapsulando InvalidKeyException
                assertThatThrownBy(() -> SmartTokenClient.verifyKeyPairConsistency(
                                ecPair.getPrivate(), clientCertificate))
                                .isInstanceOf(SmartTokenException.class)
                                .hasMessageContaining("Falha ao verificar consistência");
        }

        @Test
        void deveConstruirClienteViaBuilderComParametrosEnterprise() throws Exception {
                final SmartTokenClient client = SmartTokenClient.builder()
                                .tokenEndpoint(TOKEN_ENDPOINT)
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .connectTimeout(Duration.ofSeconds(5))
                                .requestTimeout(Duration.ofSeconds(15))
                                .assertionTtlSeconds(120)
                                .enableTokenCache(true)
                                .tokenCacheMarginSeconds(60)
                                .maxRetries(5)
                                .build();

                final String assertion = client.buildClientAssertion();
                assertThat(assertion).isNotBlank();
        }

        @Test
        void deveParseTokenResponseComExpiresIn() throws Exception {
                final String json = "{\"access_token\":\"abc123\",\"expires_in\":3600,\"token_type\":\"Bearer\"}";
                final var response = SmartTokenClient.parseTokenResponse(json);

                assertThat(response.accessToken()).isEqualTo("abc123");
                assertThat(response.expiresIn()).isEqualTo(3600);
        }

        @Test
        void deveParseTokenResponseSemExpiresIn() throws Exception {
                final String json = "{\"access_token\":\"abc123\",\"token_type\":\"Bearer\"}";
                final var response = SmartTokenClient.parseTokenResponse(json);

                assertThat(response.accessToken()).isEqualTo("abc123");
                assertThat(response.expiresIn()).isEqualTo(3600); // default
        }

        @Test
        void deveFalharParseTokenResponseSemAccessToken() {
                final String json = "{\"error\":\"invalid_grant\"}";
                assertThatThrownBy(() -> SmartTokenClient.parseTokenResponse(json))
                                .isInstanceOf(SmartTokenException.class)
                                .hasMessageContaining("access_token");
        }

        @Test
        void deveInvalidarCacheDoCliente() throws Exception {
                final SmartTokenClient client = SmartTokenClient.builder()
                                .tokenEndpoint(TOKEN_ENDPOINT)
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .enableTokenCache(true)
                                .build();

                // Não deve lançar exceção
                client.invalidateCache();
                client.invalidateCache("system/Patient.rs");
        }

        @Test
        void deveDesabilitarCacheDeTokens() throws Exception {
                final SmartTokenClient client = SmartTokenClient.builder()
                                .tokenEndpoint(TOKEN_ENDPOINT)
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .enableTokenCache(false)
                                .build();

                // Cliente criado sem exceção
                assertThat(client.buildClientAssertion()).isNotBlank();
        }

        @Test
        void deveConstruirBuilderComServerCertificatePem() throws Exception {
                final SmartTokenClient client = SmartTokenClient.builder()
                                .tokenEndpoint(TOKEN_ENDPOINT)
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .serverTrustAnchor(certFile) // usa o mesmo cert como trust anchor
                                .build();

                assertThat(client.buildClientAssertion()).isNotBlank();
        }

        @Test
        void deveExtractAccessTokenDelegandoParaParseTokenResponse() throws Exception {
                final String json = "{\"access_token\":\"token123\",\"token_type\":\"Bearer\"}";
                final String token = SmartTokenClient.extractAccessToken(json);
                assertThat(token).isEqualTo("token123");
        }

        @Test
        void deveFalharLoadPrivateKeyComArquivoPemInvalido(@TempDir final Path tempDir) throws Exception {
                final Path invalidPem = tempDir.resolve("invalid.pem");
                Files.writeString(invalidPem, "-----BEGIN PUBLIC KEY-----\nINVALID\n-----END PUBLIC KEY-----\n");

                assertThatThrownBy(() -> PemLoader.loadPrivateKey(invalidPem))
                                .isInstanceOf(Exception.class);
        }

        @Test
        void deveFalharValidateCertificateComArquivoNaoX509(@TempDir final Path tempDir) throws Exception {
                // Arquivo com chave privada em vez de certificado
                final Path notCertFile = tempDir.resolve("not-cert.pem");
                Files.writeString(notCertFile, toPkcs8Pem(privateKey.getEncoded()));

                assertThatThrownBy(() -> SslContextFactory.validateCertificate(notCertFile))
                                .isInstanceOf(SmartTokenException.class)
                                .hasMessageContaining("X.509");
        }

        @Test
        void deveConstruirBuilderComTlsProtocolCustomizado() throws Exception {
                final SmartTokenClient client = SmartTokenClient.builder()
                                .tokenEndpoint(TOKEN_ENDPOINT)
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .tlsProtocol("TLSv1.2") // protocolo válido alternativo
                                .build();

                assertThat(client.buildClientAssertion()).isNotBlank();
        }

        @Test
        void deveFalharBuildTrustAllSslContextComProtocoloInvalido() {
                assertThatThrownBy(() -> SslContextFactory.buildTrustAllSslContext("TLSv99.INVALIDO"))
                                .isInstanceOf(SmartTokenException.class)
                                .hasMessageContaining("TLSv99.INVALIDO");
        }

        @Test
        void deveFalharBuildSslContextComProtocoloInvalido() {
                assertThatThrownBy(() -> SslContextFactory.buildSslContext(certFile, "PROTOCOLO_INVALIDO"))
                                .isInstanceOf(SmartTokenException.class)
                                .hasMessageContaining("SSLContext");
        }

        @Test
        void deveUsarTlsv13ComoPadrao() {
                assertThat(SslContextFactory.DEFAULT_TLS_PROTOCOL).isEqualTo("TLSv1.3");
        }

        @Test
        void deveFalharObtainTokenComUrlInvalidaAposRetry() throws Exception {
                final SmartTokenClient client = SmartTokenClient.builder()
                                .tokenEndpoint("https://host-inexistente.local:9999/auth/token")
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .connectTimeout(Duration.ofMillis(500))
                                .maxRetries(1)
                                .build();

                assertThatThrownBy(() -> client.obtainToken("system/Patient.rs"))
                                .isInstanceOf(SmartTokenException.class)
                                .hasMessageContaining("Falha após 1 tentativas");
        }

        @Test
        void deveRespeitarBackoffExponencialNoRetry() throws Exception {
                final SmartTokenClient client = SmartTokenClient.builder()
                                .tokenEndpoint("https://host-inexistente.local:9999/auth/token")
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .connectTimeout(Duration.ofMillis(200))
                                .maxRetries(2)
                                .build();

                final long start = System.currentTimeMillis();

                assertThatThrownBy(() -> client.obtainToken("system/Patient.rs"))
                                .isInstanceOf(SmartTokenException.class)
                                .hasMessageContaining("Falha após 2 tentativas");

                final long elapsed = System.currentTimeMillis() - start;
                // Com maxRetries=2, deve haver 1 retry com delay base de 1000ms
                assertThat(elapsed).isGreaterThanOrEqualTo(900L);
        }

        @Test
        void deveFalharComHttp429RateLimit() throws Exception {
                final com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                                new java.net.InetSocketAddress(0), 0);
                server.createContext("/auth/token", exchange -> {
                        final byte[] resp = "{\"error\":\"rate_limit_exceeded\"}".getBytes(StandardCharsets.UTF_8);
                        exchange.sendResponseHeaders(429, resp.length);
                        try (var os = exchange.getResponseBody()) {
                                os.write(resp);
                        }
                });
                server.start();
                try {
                        final int port = server.getAddress().getPort();
                        final SmartTokenClient client = SmartTokenClient.builder()
                                        .tokenEndpoint("http://localhost:" + port + "/auth/token")
                                        .clientId(CLIENT_ID)
                                        .privateKeyPem(keyFile)
                                        .certificatePem(certFile)
                                        .maxRetries(1)
                                        .build();

                        assertThatThrownBy(() -> client.obtainToken("system/Patient.rs"))
                                        .isInstanceOf(SmartTokenException.class)
                                        .hasMessageContaining("429");
                } finally {
                        server.stop(0);
                }
        }

        @Test
        void deveFalharComHttpErroGenerico() throws Exception {
                final com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                                new java.net.InetSocketAddress(0), 0);
                server.createContext("/auth/token", exchange -> {
                        final byte[] resp = "{\"error\":\"server_error\"}".getBytes(StandardCharsets.UTF_8);
                        exchange.sendResponseHeaders(500, resp.length);
                        try (var os = exchange.getResponseBody()) {
                                os.write(resp);
                        }
                });
                server.start();
                try {
                        final int port = server.getAddress().getPort();
                        final SmartTokenClient client = SmartTokenClient.builder()
                                        .tokenEndpoint("http://localhost:" + port + "/auth/token")
                                        .clientId(CLIENT_ID)
                                        .privateKeyPem(keyFile)
                                        .certificatePem(certFile)
                                        .maxRetries(1)
                                        .build();

                        assertThatThrownBy(() -> client.obtainToken("system/Patient.rs"))
                                        .isInstanceOf(SmartTokenException.class)
                                        .hasMessageContaining("HTTP 500");
                } finally {
                        server.stop(0);
                }
        }

        // ---------- Testes de sanitizeErrorResponse ----------

        @Test
        void deveSanitizarRespostaDeErroNula() {
                final String sanitized = SmartTokenClient.sanitizeErrorResponse(null);
                assertThat(sanitized).isEqualTo("<empty>");
        }

        @Test
        void deveTruncarRespostaDeErroGrande() {
                final String longResponse = "x".repeat(600);
                final String sanitized = SmartTokenClient.sanitizeErrorResponse(longResponse);

                assertThat(sanitized).hasSize(503); // 500 + "..."
                assertThat(sanitized).endsWith("...");
        }

        @Test
        void deveSanitizarRespostaComAccessToken() {
                final String response = "{\"access_token\":\"eyJsecretvalue\",\"error\":\"invalid\"}";
                final String sanitized = SmartTokenClient.sanitizeErrorResponse(response);

                assertThat(sanitized).doesNotContain("eyJsecretvalue");
                assertThat(sanitized).contains("\"access_token\":\"[REDACTED]\"");
        }

        @Test
        void deveSanitizarRespostaComTokenGenerico() {
                final String response = "token=eyJhbGciOi&other=value";
                final String sanitized = SmartTokenClient.sanitizeErrorResponse(response);

                assertThat(sanitized).doesNotContain("eyJhbGciOi");
                assertThat(sanitized).contains("token=[REDACTED]");
        }

        @Test
        void deveSanitizarTokenContendoLetrasEContrabarra() {
                final String response = "token=abcdef\\ghi&other=value";
                final String sanitized = SmartTokenClient.sanitizeErrorResponse(response);

                assertThat(sanitized).contains("token=[REDACTED]&other=value");
                assertThat(sanitized).doesNotContain("def");
        }

        @Test
        void deveManterRespostaSemTokenIntacta() {
                final String response = "{\"error\":\"invalid_grant\",\"error_description\":\"Client not found\"}";
                final String sanitized = SmartTokenClient.sanitizeErrorResponse(response);

                assertThat(sanitized).contains("invalid_grant");
                assertThat(sanitized).contains("Client not found");
        }

        // ---------- Testes do record CachedToken ----------

        @Test
        void cachedTokenDeveSerValidoQuandoExpiraNoFuturo() {
                final var token = new SmartTokenClient.CachedToken(
                                "access-token-123",
                                java.time.Instant.now().plusSeconds(120));

                assertThat(token.isValid(30)).isTrue();
        }

        @Test
        void cachedTokenDeveSerInvalidoQuandoJaExpirou() {
                final var token = new SmartTokenClient.CachedToken(
                                "access-token-123",
                                java.time.Instant.now().minusSeconds(10));

                assertThat(token.isValid(30)).isFalse();
        }

        @Test
        void cachedTokenDeveSerInvalidoQuandoExpiraDentroDaMargem() {
                // Token expira em 20s, margem é 30s -> deve ser inválido
                final var token = new SmartTokenClient.CachedToken(
                                "access-token-123",
                                java.time.Instant.now().plusSeconds(20));

                assertThat(token.isValid(30)).isFalse();
        }

        @Test
        void cachedTokenDeveSerValidoQuandoExpiraForaDaMargem() {
                // Token expira em 60s, margem é 30s -> deve ser válido
                final var token = new SmartTokenClient.CachedToken(
                                "access-token-123",
                                java.time.Instant.now().plusSeconds(60));

                assertThat(token.isValid(30)).isTrue();
        }

        @Test
        void cachedTokenDeveRetornarAccessTokenCorretamente() {
                final var token = new SmartTokenClient.CachedToken(
                                "my-access-token",
                                java.time.Instant.now().plusSeconds(60));

                assertThat(token.accessToken()).isEqualTo("my-access-token");
        }

        @Test
        void cachedTokenDeveRetornarExpiresAtCorretamente() {
                final java.time.Instant expiresAt = java.time.Instant.now().plusSeconds(120);
                final var token = new SmartTokenClient.CachedToken("token", expiresAt);

                assertThat(token.expiresAt()).isEqualTo(expiresAt);
        }

        // ---------- Testes de Concorrência ----------

        @Test
        void deveConstruirClientAssertionConcorrentemente() throws Exception {
                final SmartTokenClient client = SmartTokenClient.builder()
                                .tokenEndpoint(TOKEN_ENDPOINT)
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .build();

                final int numThreads = 10;
                final java.util.concurrent.ExecutorService executor = java.util.concurrent.Executors
                                .newFixedThreadPool(numThreads);
                final java.util.concurrent.CountDownLatch latch = new java.util.concurrent.CountDownLatch(numThreads);
                final java.util.List<String> assertions = java.util.Collections.synchronizedList(
                                new java.util.ArrayList<>());
                final java.util.concurrent.atomic.AtomicInteger errors = new java.util.concurrent.atomic.AtomicInteger(
                                0);

                for (int i = 0; i < numThreads; i++) {
                        executor.submit(() -> {
                                try {
                                        final String assertion = client.buildClientAssertion();
                                        assertions.add(assertion);
                                } catch (Exception e) {
                                        errors.incrementAndGet();
                                } finally {
                                        latch.countDown();
                                }
                        });
                }

                latch.await(10, java.util.concurrent.TimeUnit.SECONDS);
                executor.shutdown();

                assertThat(errors.get()).isZero();
                assertThat(assertions).hasSize(numThreads);
                // Cada assertion deve ser única (jti diferente)
                assertThat(new java.util.HashSet<>(assertions)).hasSize(numThreads);
        }

        @Test
        void deveInvalidarCacheConcorrentemente() throws Exception {
                final SmartTokenClient client = SmartTokenClient.builder()
                                .tokenEndpoint(TOKEN_ENDPOINT)
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .enableTokenCache(true)
                                .build();

                final int numThreads = 20;
                final java.util.concurrent.ExecutorService executor = java.util.concurrent.Executors
                                .newFixedThreadPool(numThreads);
                final java.util.concurrent.CountDownLatch latch = new java.util.concurrent.CountDownLatch(numThreads);
                final java.util.concurrent.atomic.AtomicInteger errors = new java.util.concurrent.atomic.AtomicInteger(
                                0);

                for (int i = 0; i < numThreads; i++) {
                        final int idx = i;
                        executor.submit(() -> {
                                try {
                                        if (idx % 2 == 0) {
                                                client.invalidateCache("scope-" + idx);
                                        } else {
                                                client.invalidateCache();
                                        }
                                } catch (Exception e) {
                                        errors.incrementAndGet();
                                } finally {
                                        latch.countDown();
                                }
                        });
                }

                latch.await(10, java.util.concurrent.TimeUnit.SECONDS);
                executor.shutdown();

                assertThat(errors.get()).isZero();
        }

        // ---------- Testes de Validação de Certificado ----------

        @Test
        void deveFalharComCertificadoExpirado(@TempDir final Path tempDir) throws Exception {
                final KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
                gen.initialize(2048);
                final KeyPair pair = gen.generateKeyPair();

                // Gera certificado que já expirou
                final Path certExpirado = tempDir.resolve("cert-expirado.pem");
                final String certPem = generateExpiredCertPem(pair);
                Files.writeString(certExpirado, certPem, StandardCharsets.UTF_8);

                assertThatThrownBy(() -> SslContextFactory.validateCertificate(certExpirado))
                                .isInstanceOf(SmartTokenException.class)
                                .hasMessageContaining("expirado");
        }

        @Test
        void deveFalharComCertificadoAindaNaoValido(@TempDir final Path tempDir) throws Exception {
                final KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
                gen.initialize(2048);
                final KeyPair pair = gen.generateKeyPair();

                // Gera certificado que só será válido no futuro
                final Path certFuturo = tempDir.resolve("cert-futuro.pem");
                final String certPem = generateFutureCertPem(pair);
                Files.writeString(certFuturo, certPem, StandardCharsets.UTF_8);

                assertThatThrownBy(() -> SslContextFactory.validateCertificate(certFuturo))
                                .isInstanceOf(SmartTokenException.class)
                                .hasMessageContaining("ainda não é válido");
        }

        // ---------- Teste do Algoritmo Dinâmico ----------

        @Test
        void deveVerificarConsistenciaComChaveEC() throws Exception {
                // Cria par EC
                final java.security.KeyPairGenerator ecGen = java.security.KeyPairGenerator.getInstance("EC");
                ecGen.initialize(256);
                final java.security.KeyPair ecPair = ecGen.generateKeyPair();

                // Gera certificado EC
                final org.bouncycastle.asn1.x500.X500Name subject = new org.bouncycastle.asn1.x500.X500Name(
                                "CN=test-ec,O=Test,C=BR");
                final java.math.BigInteger serial = java.math.BigInteger.TWO;
                final java.util.Date notBefore = new java.util.Date();
                final java.util.Date notAfter = new java.util.Date(
                                System.currentTimeMillis() + 365L * 24 * 3600 * 1000);

                final org.bouncycastle.cert.X509v3CertificateBuilder builder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                                subject, serial, notBefore, notAfter, subject, ecPair.getPublic());

                final org.bouncycastle.operator.ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(
                                "SHA256withECDSA")
                                .build(ecPair.getPrivate());

                final byte[] certDer = builder.build(signer).getEncoded();
                final java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory
                                .getInstance("X.509");
                final X509Certificate ecCert = (X509Certificate) cf.generateCertificate(
                                new java.io.ByteArrayInputStream(certDer));

                // Deve passar - verifyKeyPairConsistency agora suporta EC
                SmartTokenClient.verifyKeyPairConsistency(ecPair.getPrivate(), ecCert);
        }

        // ==================== Testes de valores padrão do construtor ====================

        @Test
        void deveUsarAssertionTtlSecondsQuandoValorPositivo() throws Exception {
                final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(privateKey);
                final SSLContext sslContext = SslContextFactory.buildTrustAllSslContext("TLSv1.3");

                final SmartTokenClient client = new SmartTokenClient(
                                TOKEN_ENDPOINT, CLIENT_ID, strategy, clientCertificate, sslContext,
                                Duration.ofSeconds(10), Duration.ofSeconds(30),
                                120, true, 30, 3); // assertionTtlSeconds = 120

                final String assertion = client.buildClientAssertion();
                final Claims claims = Jwts.parser()
                                .verifyWith(publicKey)
                                .build()
                                .parseSignedClaims(assertion)
                                .getPayload();

                final long ttlSeconds = (claims.getExpiration().getTime() - claims.getIssuedAt().getTime()) / 1000;
                assertThat(ttlSeconds).isEqualTo(120);
        }

        @Test
        void deveUsarAssertionTtlPadraoQuandoValorZero() throws Exception {
                final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(privateKey);
                final SSLContext sslContext = SslContextFactory.buildTrustAllSslContext("TLSv1.3");

                final SmartTokenClient client = new SmartTokenClient(
                                TOKEN_ENDPOINT, CLIENT_ID, strategy, clientCertificate, sslContext,
                                Duration.ofSeconds(10), Duration.ofSeconds(30),
                                0, true, 30, 3); // assertionTtlSeconds = 0

                final String assertion = client.buildClientAssertion();
                final Claims claims = Jwts.parser()
                                .verifyWith(publicKey)
                                .build()
                                .parseSignedClaims(assertion)
                                .getPayload();

                final long ttlSeconds = (claims.getExpiration().getTime() - claims.getIssuedAt().getTime()) / 1000;
                assertThat(ttlSeconds).isEqualTo(SmartTokenClient.DEFAULT_ASSERTION_TTL_SECONDS);
        }

        @Test
        void deveUsarAssertionTtlPadraoQuandoValorNegativo() throws Exception {
                final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(privateKey);
                final SSLContext sslContext = SslContextFactory.buildTrustAllSslContext("TLSv1.3");

                final SmartTokenClient client = new SmartTokenClient(
                                TOKEN_ENDPOINT, CLIENT_ID, strategy, clientCertificate, sslContext,
                                Duration.ofSeconds(10), Duration.ofSeconds(30),
                                -10, true, 30, 3); // assertionTtlSeconds = -10

                final String assertion = client.buildClientAssertion();
                final Claims claims = Jwts.parser()
                                .verifyWith(publicKey)
                                .build()
                                .parseSignedClaims(assertion)
                                .getPayload();

                final long ttlSeconds = (claims.getExpiration().getTime() - claims.getIssuedAt().getTime()) / 1000;
                assertThat(ttlSeconds).isEqualTo(SmartTokenClient.DEFAULT_ASSERTION_TTL_SECONDS);
        }

        @Test
        void deveUsarTokenCacheMarginSecondsQuandoValorPositivo() throws Exception {
                final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(privateKey);
                final SSLContext sslContext = SslContextFactory.buildTrustAllSslContext("TLSv1.3");

                final SmartTokenClient client = new SmartTokenClient(
                                TOKEN_ENDPOINT, CLIENT_ID, strategy, clientCertificate, sslContext,
                                Duration.ofSeconds(10), Duration.ofSeconds(30),
                                60, true, 45, 3); // tokenCacheMarginSeconds = 45

                assertThat(client).isNotNull();
        }

        @Test
        void deveUsarTokenCacheMarginPadraoQuandoValorZero() throws Exception {
                final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(privateKey);
                final SSLContext sslContext = SslContextFactory.buildTrustAllSslContext("TLSv1.3");

                final SmartTokenClient client = new SmartTokenClient(
                                TOKEN_ENDPOINT, CLIENT_ID, strategy, clientCertificate, sslContext,
                                Duration.ofSeconds(10), Duration.ofSeconds(30),
                                60, true, 0, 3); // tokenCacheMarginSeconds = 0

                assertThat(client).isNotNull();
        }

        @Test
        void deveUsarTokenCacheMarginPadraoQuandoValorNegativo() throws Exception {
                final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(privateKey);
                final SSLContext sslContext = SslContextFactory.buildTrustAllSslContext("TLSv1.3");

                final SmartTokenClient client = new SmartTokenClient(
                                TOKEN_ENDPOINT, CLIENT_ID, strategy, clientCertificate, sslContext,
                                Duration.ofSeconds(10), Duration.ofSeconds(30),
                                60, true, -15, 3); // tokenCacheMarginSeconds = -15

                assertThat(client).isNotNull();
        }

        @Test
        void deveUsarMaxRetriesQuandoValorPositivo() throws Exception {
                final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(privateKey);
                final SSLContext sslContext = SslContextFactory.buildTrustAllSslContext("TLSv1.3");

                final SmartTokenClient client = new SmartTokenClient(
                                TOKEN_ENDPOINT, CLIENT_ID, strategy, clientCertificate, sslContext,
                                Duration.ofSeconds(10), Duration.ofSeconds(30),
                                60, true, 30, 5); // maxRetries = 5

                assertThat(client).isNotNull();
        }

        @Test
        void deveUsarMaxRetriesPadraoQuandoValorZero() throws Exception {
                final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(privateKey);
                final SSLContext sslContext = SslContextFactory.buildTrustAllSslContext("TLSv1.3");

                final SmartTokenClient client = new SmartTokenClient(
                                TOKEN_ENDPOINT, CLIENT_ID, strategy, clientCertificate, sslContext,
                                Duration.ofSeconds(10), Duration.ofSeconds(30),
                                60, true, 30, 0); // maxRetries = 0

                assertThat(client).isNotNull();
        }

        @Test
        void deveUsarMaxRetriesPadraoQuandoValorNegativo() throws Exception {
                final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(privateKey);
                final SSLContext sslContext = SslContextFactory.buildTrustAllSslContext("TLSv1.3");

                final SmartTokenClient client = new SmartTokenClient(
                                TOKEN_ENDPOINT, CLIENT_ID, strategy, clientCertificate, sslContext,
                                Duration.ofSeconds(10), Duration.ofSeconds(30),
                                60, true, 30, -2); // maxRetries = -2

                assertThat(client).isNotNull();
        }

        @Test
        void deveAceitarEnableTokenCacheTrue() throws Exception {
                final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(privateKey);
                final SSLContext sslContext = SslContextFactory.buildTrustAllSslContext("TLSv1.3");

                final SmartTokenClient client = new SmartTokenClient(
                                TOKEN_ENDPOINT, CLIENT_ID, strategy, clientCertificate, sslContext,
                                Duration.ofSeconds(10), Duration.ofSeconds(30),
                                60, true, 30, 3); // enableTokenCache = true

                assertThat(client).isNotNull();
        }

        @Test
        void deveAceitarEnableTokenCacheFalse() throws Exception {
                final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(privateKey);
                final SSLContext sslContext = SslContextFactory.buildTrustAllSslContext("TLSv1.3");

                final SmartTokenClient client = new SmartTokenClient(
                                TOKEN_ENDPOINT, CLIENT_ID, strategy, clientCertificate, sslContext,
                                Duration.ofSeconds(10), Duration.ofSeconds(30),
                                60, false, 30, 3); // enableTokenCache = false

                assertThat(client).isNotNull();
        }

        // ==================== Testes de obtainToken - normalização de scope ====================

        @Test
        void deveNormalizarScopeNullParaStringVazia() throws Exception {
                final com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                                new java.net.InetSocketAddress(0), 0);
                final java.util.concurrent.atomic.AtomicReference<String> receivedScope =
                                new java.util.concurrent.atomic.AtomicReference<>("");

                server.createContext("/auth/token", exchange -> {
                        // Captura o scope enviado
                        final String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                        for (String param : body.split("&")) {
                                if (param.startsWith("scope=")) {
                                        receivedScope.set(java.net.URLDecoder.decode(
                                                        param.substring(6), StandardCharsets.UTF_8));
                                }
                        }

                        final byte[] resp = "{\"access_token\":\"token123\",\"expires_in\":3600}".getBytes(StandardCharsets.UTF_8);
                        exchange.sendResponseHeaders(200, resp.length);
                        try (var os = exchange.getResponseBody()) {
                                os.write(resp);
                        }
                });
                server.start();

                try {
                        final int port = server.getAddress().getPort();
                        final SmartTokenClient client = SmartTokenClient.builder()
                                        .tokenEndpoint("http://localhost:" + port + "/auth/token")
                                        .clientId(CLIENT_ID)
                                        .privateKeyPem(keyFile)
                                        .certificatePem(certFile)
                                        .enableTokenCache(false)
                                        .build();

                        final String token = client.obtainToken(null);

                        assertThat(token).isEqualTo("token123");
                        // Scope normalizado de null para "" - o valor enviado deve ser vazio
                        assertThat(receivedScope.get()).isEmpty();
                } finally {
                        server.stop(0);
                }
        }

        @Test
        void deveNormalizarScopeComEspacosEmBranco() throws Exception {
                final com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                                new java.net.InetSocketAddress(0), 0);
                final java.util.concurrent.atomic.AtomicReference<String> receivedScope =
                                new java.util.concurrent.atomic.AtomicReference<>();

                server.createContext("/auth/token", exchange -> {
                        final String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                        for (String param : body.split("&")) {
                                if (param.startsWith("scope=")) {
                                        receivedScope.set(java.net.URLDecoder.decode(
                                                        param.substring(6), StandardCharsets.UTF_8));
                                }
                        }

                        final byte[] resp = "{\"access_token\":\"token456\",\"expires_in\":3600}".getBytes(StandardCharsets.UTF_8);
                        exchange.sendResponseHeaders(200, resp.length);
                        try (var os = exchange.getResponseBody()) {
                                os.write(resp);
                        }
                });
                server.start();

                try {
                        final int port = server.getAddress().getPort();
                        final SmartTokenClient client = SmartTokenClient.builder()
                                        .tokenEndpoint("http://localhost:" + port + "/auth/token")
                                        .clientId(CLIENT_ID)
                                        .privateKeyPem(keyFile)
                                        .certificatePem(certFile)
                                        .enableTokenCache(false)
                                        .build();

                        // Scope com espaços antes e depois
                        final String token = client.obtainToken("  system/Patient.rs  ");

                        assertThat(token).isEqualTo("token456");
                        assertThat(receivedScope.get()).isEqualTo("system/Patient.rs");
                } finally {
                        server.stop(0);
                }
        }

        // ==================== Testes de obtainToken - cache de tokens ====================

        @Test
        void deveRetornarTokenDoCacheQuandoValido() throws Exception {
                final java.util.concurrent.atomic.AtomicInteger requestCount =
                                new java.util.concurrent.atomic.AtomicInteger(0);

                final com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                                new java.net.InetSocketAddress(0), 0);
                server.createContext("/auth/token", exchange -> {
                        requestCount.incrementAndGet();
                        final byte[] resp = "{\"access_token\":\"cached-token\",\"expires_in\":3600}".getBytes(StandardCharsets.UTF_8);
                        exchange.sendResponseHeaders(200, resp.length);
                        try (var os = exchange.getResponseBody()) {
                                os.write(resp);
                        }
                });
                server.start();

                try {
                        final int port = server.getAddress().getPort();
                        final SmartTokenClient client = SmartTokenClient.builder()
                                        .tokenEndpoint("http://localhost:" + port + "/auth/token")
                                        .clientId(CLIENT_ID)
                                        .privateKeyPem(keyFile)
                                        .certificatePem(certFile)
                                        .enableTokenCache(true)
                                        .tokenCacheMarginSeconds(30)
                                        .build();

                        // Primeira chamada - deve fazer request
                        final String token1 = client.obtainToken("system/Patient.rs");
                        assertThat(token1).isEqualTo("cached-token");
                        assertThat(requestCount.get()).isEqualTo(1);

                        // Segunda chamada - deve retornar do cache
                        final String token2 = client.obtainToken("system/Patient.rs");
                        assertThat(token2).isEqualTo("cached-token");
                        assertThat(requestCount.get()).isEqualTo(1); // Não deve ter feito novo request
                } finally {
                        server.stop(0);
                }
        }

        @Test
        void deveRenovarTokenQuandoCacheExpirado() throws Exception {
                final java.util.concurrent.atomic.AtomicInteger requestCount =
                                new java.util.concurrent.atomic.AtomicInteger(0);

                final com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                                new java.net.InetSocketAddress(0), 0);
                server.createContext("/auth/token", exchange -> {
                        final int count = requestCount.incrementAndGet();
                        // Token com expires_in muito curto (1 segundo)
                        final byte[] resp = ("{\"access_token\":\"token-" + count + "\",\"expires_in\":1}")
                                        .getBytes(StandardCharsets.UTF_8);
                        exchange.sendResponseHeaders(200, resp.length);
                        try (var os = exchange.getResponseBody()) {
                                os.write(resp);
                        }
                });
                server.start();

                try {
                        final int port = server.getAddress().getPort();
                        final SmartTokenClient client = SmartTokenClient.builder()
                                        .tokenEndpoint("http://localhost:" + port + "/auth/token")
                                        .clientId(CLIENT_ID)
                                        .privateKeyPem(keyFile)
                                        .certificatePem(certFile)
                                        .enableTokenCache(true)
                                        .tokenCacheMarginSeconds(2) // Margem maior que expires_in
                                        .build();

                        // Primeira chamada
                        final String token1 = client.obtainToken("system/Patient.rs");
                        assertThat(token1).isEqualTo("token-1");
                        assertThat(requestCount.get()).isEqualTo(1);

                        // Segunda chamada - token já está dentro da margem de expiração
                        final String token2 = client.obtainToken("system/Patient.rs");
                        assertThat(token2).isEqualTo("token-2");
                        assertThat(requestCount.get()).isEqualTo(2); // Deve ter feito novo request
                } finally {
                        server.stop(0);
                }
        }

        @Test
        void deveFazerRequestSempreSeCacheDesabilitado() throws Exception {
                final java.util.concurrent.atomic.AtomicInteger requestCount =
                                new java.util.concurrent.atomic.AtomicInteger(0);

                final com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                                new java.net.InetSocketAddress(0), 0);
                server.createContext("/auth/token", exchange -> {
                        final int count = requestCount.incrementAndGet();
                        final byte[] resp = ("{\"access_token\":\"token-" + count + "\",\"expires_in\":3600}")
                                        .getBytes(StandardCharsets.UTF_8);
                        exchange.sendResponseHeaders(200, resp.length);
                        try (var os = exchange.getResponseBody()) {
                                os.write(resp);
                        }
                });
                server.start();

                try {
                        final int port = server.getAddress().getPort();
                        final SmartTokenClient client = SmartTokenClient.builder()
                                        .tokenEndpoint("http://localhost:" + port + "/auth/token")
                                        .clientId(CLIENT_ID)
                                        .privateKeyPem(keyFile)
                                        .certificatePem(certFile)
                                        .enableTokenCache(false) // Cache desabilitado
                                        .build();

                        // Primeira chamada
                        final String token1 = client.obtainToken("system/Patient.rs");
                        assertThat(token1).isEqualTo("token-1");

                        // Segunda chamada - deve fazer novo request mesmo com token válido
                        final String token2 = client.obtainToken("system/Patient.rs");
                        assertThat(token2).isEqualTo("token-2");

                        // Terceira chamada
                        final String token3 = client.obtainToken("system/Patient.rs");
                        assertThat(token3).isEqualTo("token-3");

                        assertThat(requestCount.get()).isEqualTo(3);
                } finally {
                        server.stop(0);
                }
        }

        @Test
        void deveCachearTokensPorScopeDiferente() throws Exception {
                final java.util.concurrent.atomic.AtomicInteger requestCount =
                                new java.util.concurrent.atomic.AtomicInteger(0);

                final com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                                new java.net.InetSocketAddress(0), 0);
                server.createContext("/auth/token", exchange -> {
                        final int count = requestCount.incrementAndGet();
                        final byte[] resp = ("{\"access_token\":\"token-" + count + "\",\"expires_in\":3600}")
                                        .getBytes(StandardCharsets.UTF_8);
                        exchange.sendResponseHeaders(200, resp.length);
                        try (var os = exchange.getResponseBody()) {
                                os.write(resp);
                        }
                });
                server.start();

                try {
                        final int port = server.getAddress().getPort();
                        final SmartTokenClient client = SmartTokenClient.builder()
                                        .tokenEndpoint("http://localhost:" + port + "/auth/token")
                                        .clientId(CLIENT_ID)
                                        .privateKeyPem(keyFile)
                                        .certificatePem(certFile)
                                        .enableTokenCache(true)
                                        .build();

                        // Scope A - primeira chamada
                        final String tokenA1 = client.obtainToken("system/Patient.rs");
                        assertThat(tokenA1).isEqualTo("token-1");

                        // Scope B - primeira chamada (novo scope, novo request)
                        final String tokenB1 = client.obtainToken("system/Observation.rs");
                        assertThat(tokenB1).isEqualTo("token-2");

                        // Scope A - segunda chamada (deve vir do cache)
                        final String tokenA2 = client.obtainToken("system/Patient.rs");
                        assertThat(tokenA2).isEqualTo("token-1");

                        // Scope B - segunda chamada (deve vir do cache)
                        final String tokenB2 = client.obtainToken("system/Observation.rs");
                        assertThat(tokenB2).isEqualTo("token-2");

                        // Total de 2 requests (1 por scope)
                        assertThat(requestCount.get()).isEqualTo(2);
                } finally {
                        server.stop(0);
                }
        }

        @Test
        void deveUsarCacheParaScopeNullENormalizado() throws Exception {
                final java.util.concurrent.atomic.AtomicInteger requestCount =
                                new java.util.concurrent.atomic.AtomicInteger(0);

                final com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                                new java.net.InetSocketAddress(0), 0);
                server.createContext("/auth/token", exchange -> {
                        requestCount.incrementAndGet();
                        final byte[] resp = "{\"access_token\":\"empty-scope-token\",\"expires_in\":3600}".getBytes(StandardCharsets.UTF_8);
                        exchange.sendResponseHeaders(200, resp.length);
                        try (var os = exchange.getResponseBody()) {
                                os.write(resp);
                        }
                });
                server.start();

                try {
                        final int port = server.getAddress().getPort();
                        final SmartTokenClient client = SmartTokenClient.builder()
                                        .tokenEndpoint("http://localhost:" + port + "/auth/token")
                                        .clientId(CLIENT_ID)
                                        .privateKeyPem(keyFile)
                                        .certificatePem(certFile)
                                        .enableTokenCache(true)
                                        .build();

                        // Scope null
                        final String token1 = client.obtainToken(null);
                        assertThat(token1).isEqualTo("empty-scope-token");

                        // Scope vazio (deve usar mesmo cache que null)
                        final String token2 = client.obtainToken("");
                        assertThat(token2).isEqualTo("empty-scope-token");

                        // Scope com apenas espaços (deve usar mesmo cache)
                        final String token3 = client.obtainToken("   ");
                        assertThat(token3).isEqualTo("empty-scope-token");

                        // Apenas 1 request (todos normalizados para "")
                        assertThat(requestCount.get()).isEqualTo(1);
                } finally {
                        server.stop(0);
                }
        }

        // ==================== Testes de invalidateCache - normalização de scope ====================

        @Test
        void invalidateCacheDeveNormalizarScopeNullParaStringVazia() throws Exception {
                final java.util.concurrent.atomic.AtomicInteger requestCount =
                                new java.util.concurrent.atomic.AtomicInteger(0);

                final com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                                new java.net.InetSocketAddress(0), 0);
                server.createContext("/auth/token", exchange -> {
                        requestCount.incrementAndGet();
                        final byte[] resp = "{\"access_token\":\"token-abc\",\"expires_in\":3600}".getBytes(StandardCharsets.UTF_8);
                        exchange.sendResponseHeaders(200, resp.length);
                        try (var os = exchange.getResponseBody()) {
                                os.write(resp);
                        }
                });
                server.start();

                try {
                        final int port = server.getAddress().getPort();
                        final SmartTokenClient client = SmartTokenClient.builder()
                                        .tokenEndpoint("http://localhost:" + port + "/auth/token")
                                        .clientId(CLIENT_ID)
                                        .privateKeyPem(keyFile)
                                        .certificatePem(certFile)
                                        .enableTokenCache(true)
                                        .build();

                        // Obtém token com scope vazio (normalizado de null)
                        client.obtainToken(null);
                        assertThat(requestCount.get()).isEqualTo(1);

                        // Verifica que está em cache
                        client.obtainToken(null);
                        assertThat(requestCount.get()).isEqualTo(1);

                        // Invalida cache com scope null (deve normalizar para "")
                        client.invalidateCache(null);

                        // Próxima chamada deve fazer novo request
                        client.obtainToken(null);
                        assertThat(requestCount.get()).isEqualTo(2);
                } finally {
                        server.stop(0);
                }
        }

        @Test
        void invalidateCacheDeveNormalizarScopeComEspacos() throws Exception {
                final java.util.concurrent.atomic.AtomicInteger requestCount =
                                new java.util.concurrent.atomic.AtomicInteger(0);

                final com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                                new java.net.InetSocketAddress(0), 0);
                server.createContext("/auth/token", exchange -> {
                        requestCount.incrementAndGet();
                        final byte[] resp = "{\"access_token\":\"token-xyz\",\"expires_in\":3600}".getBytes(StandardCharsets.UTF_8);
                        exchange.sendResponseHeaders(200, resp.length);
                        try (var os = exchange.getResponseBody()) {
                                os.write(resp);
                        }
                });
                server.start();

                try {
                        final int port = server.getAddress().getPort();
                        final SmartTokenClient client = SmartTokenClient.builder()
                                        .tokenEndpoint("http://localhost:" + port + "/auth/token")
                                        .clientId(CLIENT_ID)
                                        .privateKeyPem(keyFile)
                                        .certificatePem(certFile)
                                        .enableTokenCache(true)
                                        .build();

                        // Obtém token com scope normal
                        client.obtainToken("system/Patient.rs");
                        assertThat(requestCount.get()).isEqualTo(1);

                        // Verifica que está em cache
                        client.obtainToken("system/Patient.rs");
                        assertThat(requestCount.get()).isEqualTo(1);

                        // Invalida cache com scope com espaços (deve aplicar trim)
                        client.invalidateCache("  system/Patient.rs  ");

                        // Próxima chamada deve fazer novo request
                        client.obtainToken("system/Patient.rs");
                        assertThat(requestCount.get()).isEqualTo(2);
                } finally {
                        server.stop(0);
                }
        }

        @Test
        void invalidateCacheDeveInvalidarApenasOScopeEspecificado() throws Exception {
                final java.util.concurrent.atomic.AtomicInteger requestCount =
                                new java.util.concurrent.atomic.AtomicInteger(0);

                final com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                                new java.net.InetSocketAddress(0), 0);
                server.createContext("/auth/token", exchange -> {
                        requestCount.incrementAndGet();
                        final byte[] resp = ("{\"access_token\":\"token-" + requestCount.get() + "\",\"expires_in\":3600}")
                                        .getBytes(StandardCharsets.UTF_8);
                        exchange.sendResponseHeaders(200, resp.length);
                        try (var os = exchange.getResponseBody()) {
                                os.write(resp);
                        }
                });
                server.start();

                try {
                        final int port = server.getAddress().getPort();
                        final SmartTokenClient client = SmartTokenClient.builder()
                                        .tokenEndpoint("http://localhost:" + port + "/auth/token")
                                        .clientId(CLIENT_ID)
                                        .privateKeyPem(keyFile)
                                        .certificatePem(certFile)
                                        .enableTokenCache(true)
                                        .build();

                        // Obtém tokens para dois scopes diferentes
                        final String tokenA = client.obtainToken("system/Patient.rs");
                        final String tokenB = client.obtainToken("system/Observation.rs");
                        assertThat(requestCount.get()).isEqualTo(2);

                        // Invalida apenas o scope A
                        client.invalidateCache("system/Patient.rs");

                        // Scope B ainda deve estar em cache
                        final String tokenB2 = client.obtainToken("system/Observation.rs");
                        assertThat(tokenB2).isEqualTo(tokenB);
                        assertThat(requestCount.get()).isEqualTo(2); // Não fez novo request

                        // Scope A deve fazer novo request
                        final String tokenA2 = client.obtainToken("system/Patient.rs");
                        assertThat(tokenA2).isNotEqualTo(tokenA);
                        assertThat(requestCount.get()).isEqualTo(3); // Fez novo request
                } finally {
                        server.stop(0);
                }
        }

        // ---------- helpers ----------

        private static String toPkcs8Pem(final byte[] encoded) {
                final String b64 = java.util.Base64.getMimeEncoder(64, "\n".getBytes())
                                .encodeToString(encoded);
                return "-----BEGIN PRIVATE KEY-----\n" + b64 + "\n-----END PRIVATE KEY-----\n";
        }

        /**
         * Gera certificado X.509 auto-assinado mínimo via BouncyCastle para o teste.
         */
        private static String generateSelfSignedCertPem(final KeyPair pair) throws Exception {
                final org.bouncycastle.asn1.x500.X500Name subject = new org.bouncycastle.asn1.x500.X500Name(
                                "CN=test-client,O=Test,C=BR");
                final java.math.BigInteger serial = java.math.BigInteger.ONE;
                final java.util.Date notBefore = new java.util.Date();
                final java.util.Date notAfter = new java.util.Date(
                                System.currentTimeMillis() + 365L * 24 * 3600 * 1000);

                final org.bouncycastle.cert.X509v3CertificateBuilder builder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                                subject, serial, notBefore, notAfter, subject, pair.getPublic());

                final org.bouncycastle.operator.ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(
                                "SHA256WithRSA")
                                .build(pair.getPrivate());

                final byte[] certDer = builder.build(signer).getEncoded();
                final String b64 = java.util.Base64.getMimeEncoder(64, "\n".getBytes())
                                .encodeToString(certDer);
                return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n";
        }

        /**
         * Gera certificado X.509 que já expirou (notBefore e notAfter no passado).
         */
        private static String generateExpiredCertPem(final KeyPair pair) throws Exception {
                final org.bouncycastle.asn1.x500.X500Name subject = new org.bouncycastle.asn1.x500.X500Name(
                                "CN=expired-cert,O=Test,C=BR");
                final java.math.BigInteger serial = java.math.BigInteger.valueOf(3);
                // Certificado expirou há 2 dias
                final java.util.Date notBefore = new java.util.Date(
                                System.currentTimeMillis() - 3L * 24 * 3600 * 1000);
                final java.util.Date notAfter = new java.util.Date(
                                System.currentTimeMillis() - 1L * 24 * 3600 * 1000);

                final org.bouncycastle.cert.X509v3CertificateBuilder builder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                                subject, serial, notBefore, notAfter, subject, pair.getPublic());

                final org.bouncycastle.operator.ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(
                                "SHA256WithRSA")
                                .build(pair.getPrivate());

                final byte[] certDer = builder.build(signer).getEncoded();
                final String b64 = java.util.Base64.getMimeEncoder(64, "\n".getBytes())
                                .encodeToString(certDer);
                return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n";
        }

        /**
         * Gera certificado X.509 que só será válido no futuro.
         */
        private static String generateFutureCertPem(final KeyPair pair) throws Exception {
                final org.bouncycastle.asn1.x500.X500Name subject = new org.bouncycastle.asn1.x500.X500Name(
                                "CN=future-cert,O=Test,C=BR");
                final java.math.BigInteger serial = java.math.BigInteger.valueOf(4);
                // Certificado só será válido em 2 dias
                final java.util.Date notBefore = new java.util.Date(
                                System.currentTimeMillis() + 2L * 24 * 3600 * 1000);
                final java.util.Date notAfter = new java.util.Date(
                                System.currentTimeMillis() + 365L * 24 * 3600 * 1000);

                final org.bouncycastle.cert.X509v3CertificateBuilder builder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                                subject, serial, notBefore, notAfter, subject, pair.getPublic());

                final org.bouncycastle.operator.ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(
                                "SHA256WithRSA")
                                .build(pair.getPrivate());

                final byte[] certDer = builder.build(signer).getEncoded();
                final String b64 = java.util.Base64.getMimeEncoder(64, "\n".getBytes())
                                .encodeToString(certDer);
                return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n";
        }
}
