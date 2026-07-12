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
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;

import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import br.gov.go.saude.hubsaude.client.FaultToleranceConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

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
        void devePermitirConstrutorComObjetos() throws Exception {
                final SmartTokenClient client = new SmartTokenClient(
                                TOKEN_ENDPOINT,
                                CLIENT_ID,
                                privateKey,
                                clientCertificate,
                                SSLContext.getDefault());

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
                                SSLContext.getDefault()))
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
                // Cria chave EC (incompatível com SHA384withRSA usado internamente)
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

        // ==================== Testes de sanidade de expires_in (issue #730) ====================

        @Test
        void deveRejeitarExpiresInNegativo() {
                final String json = "{\"access_token\":\"abc123\",\"expires_in\":-300}";
                assertThatThrownBy(() -> SmartTokenClient.parseTokenResponse(json))
                                .isInstanceOf(SmartTokenException.class)
                                .hasMessageContaining("expires_in")
                                .hasMessageContaining("-300");
        }

        @Test
        void deveRejeitarExpiresInZero() {
                final String json = "{\"access_token\":\"abc123\",\"expires_in\":0}";
                assertThatThrownBy(() -> SmartTokenClient.parseTokenResponse(json))
                                .isInstanceOf(SmartTokenException.class)
                                .hasMessageContaining("expires_in");
        }

        @Test
        void deveRejeitarExpiresInNaoNumerico() {
                final String json = "{\"access_token\":\"abc123\",\"expires_in\":\"depois\"}";
                assertThatThrownBy(() -> SmartTokenClient.parseTokenResponse(json))
                                .isInstanceOf(SmartTokenException.class)
                                .hasMessageContaining("expires_in");
        }

        @Test
        void deveNormalizarExpiresInGiganteParaTetoDeSanidade() throws Exception {
                final String json = "{\"access_token\":\"abc123\",\"expires_in\":999999999}";
                final var response = SmartTokenClient.parseTokenResponse(json);

                assertThat(response.accessToken()).isEqualTo("abc123");
                assertThat(response.expiresIn()).isEqualTo(TokenResponseGuard.MAX_EXPIRES_IN_SECONDS);
        }

        @Test
        void deveAceitarExpiresInExatamenteNoTeto() throws Exception {
                final String json = "{\"access_token\":\"abc123\",\"expires_in\":86400}";
                final var response = SmartTokenClient.parseTokenResponse(json);

                assertThat(response.expiresIn()).isEqualTo(86400);
        }

        // ==================== Testes de limite do corpo da resposta (issue #730) ====================

        @Test
        void deveRejeitarRespostaComContentLengthAcimaDoLimite() throws Exception {
                final var handler = TokenResponseGuard.boundedStringBodyHandler(1024L);
                final var responseInfo = new java.net.http.HttpResponse.ResponseInfo() {
                        @Override
                        public int statusCode() {
                                return 200;
                        }

                        @Override
                        public java.net.http.HttpHeaders headers() {
                                return java.net.http.HttpHeaders.of(
                                                java.util.Map.of("Content-Length", java.util.List.of("2048")),
                                                (k, v) -> true);
                        }

                        @Override
                        public java.net.http.HttpClient.Version version() {
                                return java.net.http.HttpClient.Version.HTTP_1_1;
                        }
                };

                assertThatThrownBy(() -> handler.apply(responseInfo))
                                .isInstanceOf(SmartTokenException.class)
                                .hasMessageContaining("limite")
                                .hasMessageContaining("1024");
        }

        @Test
        void deveAbortarLeituraDeCorpoQueExcedeLimiteDuranteStreaming() throws Exception {
                final com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                                new java.net.InetSocketAddress(0), 0);

                // Corpo acima do teto de 1 MiB, enviado em modo chunked (length 0)
                // para exercitar o subscriber limitado, e não o atalho de
                // Content-Length.
                final byte[] chunk = new byte[64 * 1024];
                java.util.Arrays.fill(chunk, (byte) 'x');
                server.createContext("/auth/token", exchange -> {
                        exchange.sendResponseHeaders(200, 0);
                        try (var os = exchange.getResponseBody()) {
                                long sent = 0;
                                while (sent <= TokenResponseGuard.MAX_RESPONSE_BODY_BYTES) {
                                        os.write(chunk);
                                        sent += chunk.length;
                                }
                        } catch (IOException ignored) {
                                // Cliente aborta a conexão ao exceder o limite — esperado
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
                                        .maxRetries(1)
                                        .build();

                        assertThatThrownBy(() -> client.obtainToken("system/Patient.rs"))
                                        .isInstanceOf(SmartTokenException.class)
                                        .hasMessageContaining("limite");
                } finally {
                        server.stop(0);
                }
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
        void deveRetriarQuedaDeConexaoComBackoffExponencial() throws Exception {
                // Servidor TCP que aceita e fecha imediatamente: queda de conexão
                final java.net.ServerSocket server = new java.net.ServerSocket(0);
                final java.util.concurrent.atomic.AtomicInteger accepts =
                                new java.util.concurrent.atomic.AtomicInteger();
                final Thread acceptor = new Thread(() -> {
                        try {
                                while (!server.isClosed()) {
                                        final java.net.Socket socket = server.accept();
                                        accepts.incrementAndGet();
                                        socket.close();
                                }
                        } catch (IOException e) {
                                // servidor encerrado ao final do teste
                        }
                });
                acceptor.start();
                try {
                        final int port = server.getLocalPort();
                        final SmartTokenClient client = SmartTokenClient.builder()
                                        .tokenEndpoint("http://localhost:" + port + "/auth/token")
                                        .clientId(CLIENT_ID)
                                        .privateKeyPem(keyFile)
                                        .certificatePem(certFile)
                                        .maxRetries(3)
                                        .build();

                        // Captura os delays em vez de dormir de fato (teste determinístico)
                        final java.util.List<Long> delays = java.util.Collections.synchronizedList(
                                        new java.util.ArrayList<>());
                        client.setSleeper(delays::add);

                        assertThatThrownBy(() -> client.obtainToken("system/Patient.rs"))
                                        .isInstanceOf(SmartTokenException.class)
                                        .hasMessageContaining("Falha após 3 tentativas")
                                        .cause().isNotNull();

                        // Backoff exponencial sem jitter: 1000ms, 2000ms
                        assertThat(delays).containsExactly(1000L, 2000L);
                        assertThat(accepts.get()).isEqualTo(3);
                } finally {
                        server.close();
                        acceptor.join(5000);
                }
        }

        @Test
        void deveRetriarTimeoutETerSucessoNaSegundaTentativa() throws Exception {
                final java.util.concurrent.atomic.AtomicInteger calls =
                                new java.util.concurrent.atomic.AtomicInteger();
                final com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                                new java.net.InetSocketAddress(0), 0);
                final var executor = java.util.concurrent.Executors.newCachedThreadPool();
                server.setExecutor(executor);
                server.createContext("/auth/token", exchange -> {
                        if (calls.incrementAndGet() == 1) {
                                // Excede o requestTimeout do cliente: HttpTimeoutException
                                try {
                                        Thread.sleep(600);
                                } catch (InterruptedException e) {
                                        Thread.currentThread().interrupt();
                                }
                                exchange.sendResponseHeaders(503, -1);
                                exchange.close();
                        } else {
                                final byte[] resp = "{\"access_token\":\"tok-apos-timeout\",\"expires_in\":3600}"
                                                .getBytes(StandardCharsets.UTF_8);
                                exchange.sendResponseHeaders(200, resp.length);
                                try (var os = exchange.getResponseBody()) {
                                        os.write(resp);
                                }
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
                                        .requestTimeout(Duration.ofMillis(250))
                                        .maxRetries(2)
                                        .build();

                        final java.util.List<Long> delays = java.util.Collections.synchronizedList(
                                        new java.util.ArrayList<>());
                        client.setSleeper(delays::add);

                        final String token = client.obtainToken("system/Patient.rs");

                        assertThat(token).isEqualTo("tok-apos-timeout");
                        assertThat(delays).containsExactly(1000L);
                        assertThat(calls.get()).isEqualTo(2);
                } finally {
                        server.stop(0);
                        executor.shutdownNow();
                }
        }

        @Test
        void deveFalharImediatamenteEm503SemRetry() throws Exception {
                final java.util.concurrent.atomic.AtomicInteger calls =
                                new java.util.concurrent.atomic.AtomicInteger();
                final com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                                new java.net.InetSocketAddress(0), 0);
                server.createContext("/auth/token", exchange -> {
                        calls.incrementAndGet();
                        exchange.getResponseHeaders().add("Retry-After", "7");
                        final byte[] resp = "{\"error\":\"unavailable\"}".getBytes(StandardCharsets.UTF_8);
                        exchange.sendResponseHeaders(503, resp.length);
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
                                        .build();

                        final java.util.List<Long> delays = java.util.Collections.synchronizedList(
                                        new java.util.ArrayList<>());
                        client.setSleeper(delays::add);

                        // Resposta HTTP recebida: erro imediato, sem retry automático;
                        // Retry-After aparece apenas como diagnóstico na mensagem.
                        assertThatThrownBy(() -> client.obtainToken("system/Patient.rs"))
                                        .isInstanceOf(SmartTokenException.class)
                                        .hasMessageContaining("HTTP 503")
                                        .hasMessageContaining("Retry-After: 7");

                        assertThat(calls.get()).isEqualTo(1);
                        assertThat(delays).isEmpty();
                } finally {
                        server.stop(0);
                }
        }

        @Test
        void deveFalharComHttp429RateLimitSemRetry() throws Exception {
                final java.util.concurrent.atomic.AtomicInteger calls =
                                new java.util.concurrent.atomic.AtomicInteger();
                final com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                                new java.net.InetSocketAddress(0), 0);
                server.createContext("/auth/token", exchange -> {
                        calls.incrementAndGet();
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
                                        .build();

                        final java.util.List<Long> delays = java.util.Collections.synchronizedList(
                                        new java.util.ArrayList<>());
                        client.setSleeper(delays::add);

                        assertThatThrownBy(() -> client.obtainToken("system/Patient.rs"))
                                        .isInstanceOf(SmartTokenException.class)
                                        .hasMessageContaining("429")
                                        .hasMessageContaining("rate_limit_exceeded")
                                        .hasMessageContaining("decisão de aguardar e reenviar é do chamador");

                        assertThat(calls.get()).isEqualTo(1);
                        assertThat(delays).isEmpty();
                } finally {
                        server.stop(0);
                }
        }

        @Test
        void deveFalharComHttpErroGenericoSemRetry() throws Exception {
                final java.util.concurrent.atomic.AtomicInteger calls =
                                new java.util.concurrent.atomic.AtomicInteger();
                final com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                                new java.net.InetSocketAddress(0), 0);
                server.createContext("/auth/token", exchange -> {
                        calls.incrementAndGet();
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
                                        .build();

                        final java.util.List<Long> delays = java.util.Collections.synchronizedList(
                                        new java.util.ArrayList<>());
                        client.setSleeper(delays::add);

                        assertThatThrownBy(() -> client.obtainToken("system/Patient.rs"))
                                        .isInstanceOf(SmartTokenException.class)
                                        .hasMessageContaining("HTTP 500");

                        assertThat(calls.get()).isEqualTo(1);
                        assertThat(delays).isEmpty();
                } finally {
                        server.stop(0);
                }
        }

        @Test
        void deveFalharImediatamenteEm400SemRetry() throws Exception {
                final java.util.concurrent.atomic.AtomicInteger calls =
                                new java.util.concurrent.atomic.AtomicInteger();
                final com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                                new java.net.InetSocketAddress(0), 0);
                server.createContext("/auth/token", exchange -> {
                        calls.incrementAndGet();
                        final byte[] resp = "{\"error\":\"invalid_client\"}".getBytes(StandardCharsets.UTF_8);
                        exchange.sendResponseHeaders(400, resp.length);
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
                                        .maxRetries(3)
                                        .build();

                        final java.util.List<Long> delays = java.util.Collections.synchronizedList(
                                        new java.util.ArrayList<>());
                        client.setSleeper(delays::add);

                        assertThatThrownBy(() -> client.obtainToken("system/Patient.rs"))
                                        .isInstanceOf(SmartTokenException.class)
                                        .hasMessageContaining("HTTP 400")
                                        .hasMessageContaining("invalid_client");

                        assertThat(calls.get()).isEqualTo(1);
                        assertThat(delays).isEmpty();
                } finally {
                        server.stop(0);
                }
        }

        // ---------- Testes de isTransientNetworkFailure ----------

        @Test
        void deveClassificarFalhasDeRedeComoTransitorias() {
                assertThat(SmartTokenClient.isTransientNetworkFailure(
                                new java.net.http.HttpTimeoutException("timeout")))
                                .isTrue();
                assertThat(SmartTokenClient.isTransientNetworkFailure(
                                new java.net.SocketException("Connection reset")))
                                .isTrue();
                assertThat(SmartTokenClient.isTransientNetworkFailure(
                                new java.net.ConnectException("Connection refused")))
                                .isTrue();
                // HttpClient envolve a causa original em IOException genérica
                assertThat(SmartTokenClient.isTransientNetworkFailure(
                                new IOException("HTTP/1.1 header parser received no bytes",
                                                new java.io.EOFException("EOF reached while reading"))))
                                .isTrue();
                assertThat(SmartTokenClient.isTransientNetworkFailure(
                                new IOException("connection closed locally",
                                                new java.net.SocketException("Connection reset"))))
                                .isTrue();
                // O JDK por vezes lança esta IOException sem causa anexada
                assertThat(SmartTokenClient.isTransientNetworkFailure(
                                new IOException("HTTP/1.1 header parser received no bytes")))
                                .isTrue();
        }

        @Test
        void naoDeveClassificarFalhasTlsOuGenericasComoTransitorias() {
                assertThat(SmartTokenClient.isTransientNetworkFailure(
                                new IOException("erro generico de I/O")))
                                .isFalse();
                assertThat(SmartTokenClient.isTransientNetworkFailure(
                                new javax.net.ssl.SSLHandshakeException("handshake falhou")))
                                .isFalse();
                // SSLException prevalece mesmo com causa de rede na cadeia
                final javax.net.ssl.SSLException ssl = new javax.net.ssl.SSLException(
                                "TLS abortado", new java.net.SocketException("Connection reset"));
                assertThat(SmartTokenClient.isTransientNetworkFailure(new IOException(ssl)))
                                .isFalse();
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

        @Test
        void scopeLocksDevemSerLimitadosEDeterministicos() throws Exception {
                final SmartTokenClient client = SmartTokenClient.builder()
                                .tokenEndpoint(TOKEN_ENDPOINT)
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .build();

                // Simula scopes dinâmicos (ex.: por paciente): a quantidade de
                // locks distintos deve permanecer limitada (issue #731).
                final java.util.Set<Object> locks = java.util.Collections
                                .newSetFromMap(new java.util.IdentityHashMap<>());
                final int numScopes = 10_000;
                for (int i = 0; i < numScopes; i++) {
                        locks.add(client.scopeLockFor("patient/" + i + ".read"));
                }
                assertThat(locks).hasSizeLessThanOrEqualTo(32);

                // O mesmo scope deve sempre mapear para o mesmo lock
                // (preserva o single-flight por scope).
                assertThat(client.scopeLockFor("system/Patient.rs"))
                                .isSameAs(client.scopeLockFor("system/Patient.rs"));
        }

        @Test
        void scopeLockDeveGarantirSingleFlightPorScope() throws Exception {
                final SmartTokenClient client = SmartTokenClient.builder()
                                .tokenEndpoint(TOKEN_ENDPOINT)
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .build();

                final String scope = "system/Patient.rs";
                final int numThreads = 8;
                final java.util.concurrent.ExecutorService executor = java.util.concurrent.Executors
                                .newFixedThreadPool(numThreads);
                final java.util.concurrent.CountDownLatch latch = new java.util.concurrent.CountDownLatch(numThreads);
                final java.util.concurrent.atomic.AtomicInteger simultaneos = new java.util.concurrent.atomic.AtomicInteger(
                                0);
                final java.util.concurrent.atomic.AtomicInteger maxSimultaneos = new java.util.concurrent.atomic.AtomicInteger(
                                0);

                // Todas as threads disputam o lock do mesmo scope: dentro da
                // seção crítica, nunca deve haver mais de uma thread.
                for (int i = 0; i < numThreads; i++) {
                        executor.submit(() -> {
                                final java.util.concurrent.locks.ReentrantLock lock = client.scopeLockFor(scope);
                                lock.lock();
                                try {
                                        final int atual = simultaneos.incrementAndGet();
                                        maxSimultaneos.accumulateAndGet(atual, Math::max);
                                        Thread.sleep(10);
                                        simultaneos.decrementAndGet();
                                } catch (InterruptedException e) {
                                        Thread.currentThread().interrupt();
                                } finally {
                                        lock.unlock();
                                        latch.countDown();
                                }
                        });
                }

                assertThat(latch.await(10, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
                executor.shutdown();

                assertThat(maxSimultaneos.get()).isEqualTo(1);
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

        @Test
        void deveFalharConstrutorEmMemoriaComCertificadoExpirado() throws Exception {
                final KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
                gen.initialize(2048);
                final KeyPair pair = gen.generateKeyPair();

                final String certPem = generateExpiredCertPem(pair);
                final java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory
                                .getInstance("X.509");
                final X509Certificate certExpirado = (X509Certificate) cf.generateCertificate(
                                new java.io.ByteArrayInputStream(
                                                certPem.getBytes(StandardCharsets.UTF_8)));
                final SSLContext ssl = SslContextFactory.buildSslContext((Path) null, "TLSv1.3");

                // Certificado fornecido já em memória também é validado (fail-fast)
                assertThatThrownBy(() -> new SmartTokenClient(
                                "https://auth.example/token", CLIENT_ID,
                                pair.getPrivate(), certExpirado, ssl))
                                .isInstanceOf(SmartTokenException.class)
                                .hasMessageContaining("Certificado expirado");
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

        @Test
        void deveFalharVerifyKeyPairConsistencyComChaveDsa() throws Exception {
                final KeyPairGenerator dsaGen = KeyPairGenerator.getInstance("DSA");
                dsaGen.initialize(2048);
                final KeyPair dsaPair = dsaGen.generateKeyPair();

                assertThatThrownBy(() -> SmartTokenClient.verifyKeyPairConsistency(
                                dsaPair.getPrivate(), clientCertificate))
                                .isInstanceOf(SmartTokenException.class)
                                .hasMessageContaining("Tipo de chave não suportado");
        }

        // ==================== Testes de valores padrão do construtor ====================

        @Test
        void deveUsarAssertionTtlSecondsQuandoValorPositivo() throws Exception {
                final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(privateKey);

                final SmartTokenClient client = new SmartTokenClient(
                                TOKEN_ENDPOINT, CLIENT_ID, strategy, clientCertificate, SSLContext.getDefault(),
                                new FaultToleranceConfig(Duration.ofSeconds(10), Duration.ofSeconds(30), 120, 3),
                                true, 30);

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

                final SmartTokenClient client = new SmartTokenClient(
                                TOKEN_ENDPOINT, CLIENT_ID, strategy, clientCertificate, SSLContext.getDefault(),
                                new FaultToleranceConfig(Duration.ofSeconds(10), Duration.ofSeconds(30), 0, 3),
                                true, 30);

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

                final SmartTokenClient client = new SmartTokenClient(
                                TOKEN_ENDPOINT, CLIENT_ID, strategy, clientCertificate, SSLContext.getDefault(),
                                new FaultToleranceConfig(Duration.ofSeconds(10), Duration.ofSeconds(30), -10, 3),
                                true, 30);

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

                final SmartTokenClient client = new SmartTokenClient(
                                TOKEN_ENDPOINT, CLIENT_ID, strategy, clientCertificate, SSLContext.getDefault(),
                                new FaultToleranceConfig(Duration.ofSeconds(10), Duration.ofSeconds(30), 60, 3),
                                true, 45);

                assertThat(client).isNotNull();
        }

        @Test
        void deveUsarTokenCacheMarginPadraoQuandoValorZero() throws Exception {
                final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(privateKey);

                final SmartTokenClient client = new SmartTokenClient(
                                TOKEN_ENDPOINT, CLIENT_ID, strategy, clientCertificate, SSLContext.getDefault(),
                                new FaultToleranceConfig(Duration.ofSeconds(10), Duration.ofSeconds(30), 60, 3),
                                true, 0);

                assertThat(client).isNotNull();
        }

        @Test
        void deveUsarTokenCacheMarginPadraoQuandoValorNegativo() throws Exception {
                final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(privateKey);

                final SmartTokenClient client = new SmartTokenClient(
                                TOKEN_ENDPOINT, CLIENT_ID, strategy, clientCertificate, SSLContext.getDefault(),
                                new FaultToleranceConfig(Duration.ofSeconds(10), Duration.ofSeconds(30), 60, 3),
                                true, -15);

                assertThat(client).isNotNull();
        }

        @Test
        void deveUsarMaxRetriesQuandoValorPositivo() throws Exception {
                final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(privateKey);

                final SmartTokenClient client = new SmartTokenClient(
                                TOKEN_ENDPOINT, CLIENT_ID, strategy, clientCertificate, SSLContext.getDefault(),
                                new FaultToleranceConfig(Duration.ofSeconds(10), Duration.ofSeconds(30), 60, 5),
                                true, 30);

                assertThat(client).isNotNull();
        }

        @Test
        void deveUsarMaxRetriesPadraoQuandoValorZero() throws Exception {
                final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(privateKey);

                final SmartTokenClient client = new SmartTokenClient(
                                TOKEN_ENDPOINT, CLIENT_ID, strategy, clientCertificate, SSLContext.getDefault(),
                                new FaultToleranceConfig(Duration.ofSeconds(10), Duration.ofSeconds(30), 60, 0),
                                true, 30);

                assertThat(client).isNotNull();
        }

        @Test
        void deveUsarMaxRetriesPadraoQuandoValorNegativo() throws Exception {
                final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(privateKey);

                final SmartTokenClient client = new SmartTokenClient(
                                TOKEN_ENDPOINT, CLIENT_ID, strategy, clientCertificate, SSLContext.getDefault(),
                                new FaultToleranceConfig(Duration.ofSeconds(10), Duration.ofSeconds(30), 60, -2),
                                true, 30);

                assertThat(client).isNotNull();
        }

        @Test
        void deveAceitarEnableTokenCacheTrue() throws Exception {
                final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(privateKey);

                final SmartTokenClient client = new SmartTokenClient(
                                TOKEN_ENDPOINT, CLIENT_ID, strategy, clientCertificate, SSLContext.getDefault(),
                                new FaultToleranceConfig(Duration.ofSeconds(10), Duration.ofSeconds(30), 60, 3),
                                true, 30);

                assertThat(client).isNotNull();
        }

        @Test
        void deveAceitarEnableTokenCacheFalse() throws Exception {
                final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(privateKey);

                final SmartTokenClient client = new SmartTokenClient(
                                TOKEN_ENDPOINT, CLIENT_ID, strategy, clientCertificate, SSLContext.getDefault(),
                                new FaultToleranceConfig(Duration.ofSeconds(10), Duration.ofSeconds(30), 60, 3),
                                false, 30);

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

        // ==================== Testes de conformidade com a especificação (§11) ====================

        @Test
        void deveColapsarRequisicoesConcorrentesDoMesmoScope() throws Exception {
                final java.util.concurrent.atomic.AtomicInteger requestCount =
                                new java.util.concurrent.atomic.AtomicInteger(0);

                final com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                                new java.net.InetSocketAddress(0), 0);
                server.createContext("/auth/token", exchange -> {
                        requestCount.incrementAndGet();
                        try {
                                Thread.sleep(300); // amplia a janela de corrida
                        } catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                        }
                        final byte[] resp = "{\"access_token\":\"single-flight\",\"expires_in\":3600}"
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

                        final int numThreads = 8;
                        final var executor = java.util.concurrent.Executors.newFixedThreadPool(numThreads);
                        final var start = new java.util.concurrent.CountDownLatch(1);
                        final var done = new java.util.concurrent.CountDownLatch(numThreads);
                        final var tokens = java.util.Collections.synchronizedSet(new java.util.HashSet<String>());
                        final var errors = new java.util.concurrent.atomic.AtomicInteger(0);

                        for (int i = 0; i < numThreads; i++) {
                                executor.submit(() -> {
                                        try {
                                                start.await();
                                                tokens.add(client.obtainToken("system/Patient.rs"));
                                        } catch (Exception e) {
                                                errors.incrementAndGet();
                                        } finally {
                                                done.countDown();
                                        }
                                });
                        }
                        start.countDown();
                        assertThat(done.await(15, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
                        executor.shutdown();

                        assertThat(errors.get()).isZero();
                        assertThat(tokens).containsExactly("single-flight");
                        // Single-flight: N threads simultâneas geram apenas 1 requisição HTTP
                        assertThat(requestCount.get()).isEqualTo(1);
                } finally {
                        server.stop(0);
                }
        }

        @Test
        void deveRetornarTokenResponseCompletoComRawJson() throws Exception {
                final String json = "{\"access_token\":\"resp-token\",\"expires_in\":1800,"
                                + "\"token_type\":\"Bearer\",\"scope\":\"system/Patient.rs\"}";

                final com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                                new java.net.InetSocketAddress(0), 0);
                server.createContext("/auth/token", exchange -> {
                        final byte[] resp = json.getBytes(StandardCharsets.UTF_8);
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
                                        .build();

                        final SmartTokenClient.TokenResponse response =
                                        client.obtainTokenResponse("system/Patient.rs");

                        assertThat(response.accessToken()).isEqualTo("resp-token");
                        assertThat(response.expiresIn()).isEqualTo(1800);
                        // rawJson preserva o corpo integral para campos extras
                        assertThat(response.rawJson()).isEqualTo(json);
                        // toString não deve vazar o token
                        assertThat(response.toString()).doesNotContain("resp-token");
                } finally {
                        server.stop(0);
                }
        }

        @Test
        void deveEnviarFormBodyCorretoComPercentEncoding() throws Exception {
                final java.util.concurrent.atomic.AtomicReference<String> bodyRef =
                                new java.util.concurrent.atomic.AtomicReference<>();
                final java.util.concurrent.atomic.AtomicReference<String> contentTypeRef =
                                new java.util.concurrent.atomic.AtomicReference<>();

                final com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                                new java.net.InetSocketAddress(0), 0);
                server.createContext("/auth/token", exchange -> {
                        contentTypeRef.set(exchange.getRequestHeaders().getFirst("Content-Type"));
                        bodyRef.set(new String(exchange.getRequestBody().readAllBytes(),
                                        StandardCharsets.UTF_8));
                        final byte[] resp = "{\"access_token\":\"t\",\"expires_in\":60}"
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
                                        .build();

                        client.obtainToken("system/Patient.rs");

                        assertThat(contentTypeRef.get()).isEqualTo("application/x-www-form-urlencoded");
                        final String body = bodyRef.get();
                        assertThat(body).contains("grant_type=client_credentials");
                        assertThat(body).contains("client_assertion_type="
                                        + "urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer");
                        assertThat(body).contains("&client_assertion=ey");
                        // Percent-encoding: "/" do scope vira %2F
                        assertThat(body).contains("&scope=system%2FPatient.rs");
                } finally {
                        server.stop(0);
                }
        }

        @Test
        void deveGerarJtiUnicoPorClientAssertion() throws Exception {
                final SmartTokenClient client = SmartTokenClient.builder()
                                .tokenEndpoint(TOKEN_ENDPOINT)
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .build();

                final Claims claims1 = Jwts.parser().verifyWith(publicKey).build()
                                .parseSignedClaims(client.buildClientAssertion()).getPayload();
                final Claims claims2 = Jwts.parser().verifyWith(publicKey).build()
                                .parseSignedClaims(client.buildClientAssertion()).getPayload();

                assertThat(claims1.getId()).isNotBlank();
                assertThat(claims2.getId()).isNotBlank();
                assertThat(claims1.getId()).isNotEqualTo(claims2.getId());
        }

        @Test
        void deveInvalidarTodoOCacheComInvalidateCacheGlobal() throws Exception {
                final java.util.concurrent.atomic.AtomicInteger requestCount =
                                new java.util.concurrent.atomic.AtomicInteger(0);

                final com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                                new java.net.InetSocketAddress(0), 0);
                server.createContext("/auth/token", exchange -> {
                        requestCount.incrementAndGet();
                        final byte[] resp = "{\"access_token\":\"tok\",\"expires_in\":3600}"
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

                        client.obtainToken("system/Patient.rs");
                        client.obtainToken("system/Observation.rs");
                        assertThat(requestCount.get()).isEqualTo(2);

                        // RF-06.1: invalidação global remove TODOS os scopes
                        client.invalidateCache();

                        client.obtainToken("system/Patient.rs");
                        client.obtainToken("system/Observation.rs");
                        assertThat(requestCount.get()).isEqualTo(4);
                } finally {
                        server.stop(0);
                }
        }

        @Test
        void deveAplicarMargemPadraoQuandoMargemConfiguradaNegativa() throws Exception {
                final java.util.concurrent.atomic.AtomicInteger requestCount =
                                new java.util.concurrent.atomic.AtomicInteger(0);

                final com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                                new java.net.InetSocketAddress(0), 0);
                server.createContext("/auth/token", exchange -> {
                        requestCount.incrementAndGet();
                        // expires_in=20s: menor que a margem padrão (30s), maior que -5s
                        final byte[] resp = "{\"access_token\":\"curto\",\"expires_in\":20}"
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
                                        .tokenCacheMarginSeconds(-5)
                                        .build();

                        client.obtainToken("system/Patient.rs");
                        client.obtainToken("system/Patient.rs");

                        // RF-18.4b: margem negativa é substituída pela padrão (30s);
                        // token com 20s de vida está dentro da margem -> novo request.
                        // Se a margem -5 tivesse sido aceita, haveria apenas 1 request.
                        assertThat(requestCount.get()).isEqualTo(2);
                } finally {
                        server.stop(0);
                }
        }

        @Test
        void deveExporJwtAlgorithmConfigurado() throws Exception {
                final SmartTokenClient padrao = SmartTokenClient.builder()
                                .tokenEndpoint(TOKEN_ENDPOINT)
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .build();
                assertThat(padrao.getJwtAlgorithm()).isEqualTo("RS384");

                final SmartTokenClient ps256 = SmartTokenClient.builder()
                                .tokenEndpoint(TOKEN_ENDPOINT)
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .jwtAlgorithm("PS256")
                                .build();
                assertThat(ps256.getJwtAlgorithm()).isEqualTo("PS256");
        }

        @Test
        void deveResolverTokenEndpointViaDiscoveryEExporGetter() throws Exception {
                final com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                                new java.net.InetSocketAddress(0), 0);
                server.start();
                final int port = server.getAddress().getPort();
                final String tokenEndpoint = "http://localhost:" + port + "/auth/token";
                server.createContext("/.well-known/smart-configuration", exchange -> {
                        final byte[] resp = ("{\"token_endpoint\":\"" + tokenEndpoint + "\"}")
                                        .getBytes(StandardCharsets.UTF_8);
                        exchange.sendResponseHeaders(200, resp.length);
                        try (var os = exchange.getResponseBody()) {
                                os.write(resp);
                        }
                });

                try {
                        final SmartTokenClient client = SmartTokenClient.builder()
                                        .fhirBase("http://localhost:" + port)
                                        .clientId(CLIENT_ID)
                                        .privateKeyPem(keyFile)
                                        .certificatePem(certFile)
                                        .build();

                        // RF-09.5: getter expõe o endpoint resolvido via discovery
                        assertThat(client.getTokenEndpoint()).isEqualTo(tokenEndpoint);
                } finally {
                        server.stop(0);
                }
        }

        @Test
        void deveEscaparCaracteresEspeciaisDoClientIdNoAssertion() throws Exception {
                final String clientIdEspecial = "cli\"ent\\com aspas";
                final SmartTokenClient client = SmartTokenClient.builder()
                                .tokenEndpoint(TOKEN_ENDPOINT)
                                .clientId(clientIdEspecial)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .build();

                // Se o escaping JSON estiver incorreto, o parse da assertion falha
                final Claims claims = Jwts.parser().verifyWith(publicKey).build()
                                .parseSignedClaims(client.buildClientAssertion()).getPayload();

                assertThat(claims.getIssuer()).isEqualTo(clientIdEspecial);
                assertThat(claims.getSubject()).isEqualTo(clientIdEspecial);
        }

        @Test
        void naoDeveRetriarFalhaDeConfiancaTlsEmHttps() throws Exception {
                // Servidor HTTPS com certificado self-signed NÃO confiado pelo cliente
                final java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
                ks.load(null, null);
                ks.setKeyEntry("server", privateKey, "changeit".toCharArray(),
                                new java.security.cert.Certificate[]{clientCertificate});
                final javax.net.ssl.KeyManagerFactory kmf = javax.net.ssl.KeyManagerFactory
                                .getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(ks, "changeit".toCharArray());
                final SSLContext serverCtx = SSLContext.getInstance("TLS");
                serverCtx.init(kmf.getKeyManagers(), null, null);

                final com.sun.net.httpserver.HttpsServer server = com.sun.net.httpserver.HttpsServer
                                .create(new java.net.InetSocketAddress(0), 0);
                server.setHttpsConfigurator(new com.sun.net.httpserver.HttpsConfigurator(serverCtx));
                server.createContext("/auth/token", exchange -> exchange.sendResponseHeaders(200, -1));
                server.start();

                try {
                        final int port = server.getAddress().getPort();
                        final java.util.List<Long> delays = new java.util.ArrayList<>();
                        final SmartTokenClient client = SmartTokenClient.builder()
                                        .tokenEndpoint("https://localhost:" + port + "/auth/token")
                                        .clientId(CLIENT_ID)
                                        .privateKeyPem(keyFile)
                                        .certificatePem(certFile)
                                        .maxRetries(3)
                                        .build();
                        client.setSleeper(delays::add);

                        // RF-08: falha de confiança TLS não é transitória -> sem retry
                        assertThatThrownBy(() -> client.obtainToken("system/Patient.rs"))
                                        .isInstanceOfAny(IOException.class, SmartTokenException.class);
                        assertThat(delays).isEmpty();
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

        // ---------- Testes issue #725 ----------

        @Test
        void deveRedigirTokenAntesDeTruncarRespostaGrande() {
                // Corpo > 500 chars com o token após a posição de truncamento
                final String token = "eyJtokenSuperSecretoQueNaoPodeVazar12345";
                final String response = "{\"error\":\"invalid\",\"padding\":\""
                                + "x".repeat(600)
                                + "\",\"access_token\":\"" + token + "\"}";
                final String sanitized = SmartTokenClient.sanitizeErrorResponse(response);

                assertThat(sanitized).doesNotContain(token);
                assertThat(sanitized).endsWith("...");
                assertThat(sanitized.length()).isLessThanOrEqualTo(503);

                // Corpo > 500 chars com o token ANTES do ponto de truncamento:
                // a redação deve ocorrer antes do truncamento
                final String response2 = "{\"access_token\":\"" + token + "\",\"padding\":\""
                                + "y".repeat(600) + "\"}";
                final String sanitized2 = SmartTokenClient.sanitizeErrorResponse(response2);

                assertThat(sanitized2).doesNotContain(token);
                assertThat(sanitized2).contains("[REDACTED]");
                assertThat(sanitized2).endsWith("...");
        }

        @Test
        void deveAssinarClientAssertionComEs256EmFormatoP1363() throws Exception {
                final KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
                ecGen.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
                final KeyPair ecPair = ecGen.generateKeyPair();

                final SigningStrategy strategy = SigningStrategyFactory
                                .fromPrivateKeyForJwt(ecPair.getPrivate(), "ES256");
                final SmartTokenClient client = new SmartTokenClient(
                                TOKEN_ENDPOINT, CLIENT_ID, strategy, null, SSLContext.getDefault(),
                                new FaultToleranceConfig(Duration.ofSeconds(10), Duration.ofSeconds(30), 60, 3),
                                true, 30, "ES256");

                final String assertion = client.buildClientAssertion();

                // jjwt valida assinaturas ES256 em formato R||S (RFC 7518 §3.4);
                // uma assinatura DER seria rejeitada aqui
                final Claims claims = Jwts.parser()
                                .verifyWith(ecPair.getPublic())
                                .build()
                                .parseSignedClaims(assertion)
                                .getPayload();

                assertThat(claims.getSubject()).isEqualTo(CLIENT_ID);
        }

        @Test
        void deveAssinarClientAssertionComPs256ValidadoPorJjwt() throws Exception {
                final SigningStrategy strategy = SigningStrategyFactory
                                .fromPrivateKeyForJwt(privateKey, "PS256");
                final SmartTokenClient client = new SmartTokenClient(
                                TOKEN_ENDPOINT, CLIENT_ID, strategy, clientCertificate, SSLContext.getDefault(),
                                new FaultToleranceConfig(Duration.ofSeconds(10), Duration.ofSeconds(30), 60, 3),
                                true, 30, "PS256");

                final String assertion = client.buildClientAssertion();

                final Claims claims = Jwts.parser()
                                .verifyWith(publicKey)
                                .build()
                                .parseSignedClaims(assertion)
                                .getPayload();

                assertThat(claims.getSubject()).isEqualTo(CLIENT_ID);

                // Header deve declarar PS256
                final String headerJson = new String(
                                java.util.Base64.getUrlDecoder().decode(assertion.split("\\.")[0]),
                                StandardCharsets.UTF_8);
                assertThat(headerJson).contains("\"alg\":\"PS256\"");
        }

        @Test
        void deveIncluirKidNoHeaderQuandoConfigurado() throws Exception {
                final SmartTokenClient client = SmartTokenClient.builder()
                                .tokenEndpoint(TOKEN_ENDPOINT)
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .keyId("minha-chave-1")
                                .build();

                final String assertion = client.buildClientAssertion();
                final String headerJson = new String(
                                java.util.Base64.getUrlDecoder().decode(assertion.split("\\.")[0]),
                                StandardCharsets.UTF_8);

                assertThat(headerJson).contains("\"kid\":\"minha-chave-1\"");
                assertThat(client.getKeyId()).isEqualTo("minha-chave-1");

                // Assinatura continua válida
                final Claims claims = Jwts.parser()
                                .verifyWith(publicKey)
                                .build()
                                .parseSignedClaims(assertion)
                                .getPayload();
                assertThat(claims.getSubject()).isEqualTo(CLIENT_ID);
        }

        @Test
        void naoDeveIncluirKidNoHeaderPorPadrao() throws Exception {
                final SmartTokenClient client = SmartTokenClient.builder()
                                .tokenEndpoint(TOKEN_ENDPOINT)
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .build();

                final String assertion = client.buildClientAssertion();
                final String headerJson = new String(
                                java.util.Base64.getUrlDecoder().decode(assertion.split("\\.")[0]),
                                StandardCharsets.UTF_8);

                assertThat(headerJson).doesNotContain("\"kid\"");
                assertThat(headerJson).contains("\"alg\":\"RS384\"");
                assertThat(headerJson).contains("\"typ\":\"JWT\"");
        }

        @Test
        void deveUsarRs384ComoAlgoritmoPadrao() throws Exception {
                // Concern client-assertion-contexto-ig.md §3.2: alg DEVE ser
                // RS384 ou ES384; o padrão do SDK é RS384 (issue #361).
                final SmartTokenClient client = SmartTokenClient.builder()
                                .tokenEndpoint(TOKEN_ENDPOINT)
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .build();

                assertThat(client.getJwtAlgorithm()).isEqualTo("RS384");

                final String assertion = client.buildClientAssertion();
                final String headerJson = new String(
                                java.util.Base64.getUrlDecoder().decode(assertion.split("\\.")[0]),
                                StandardCharsets.UTF_8);
                assertThat(headerJson).contains("\"alg\":\"RS384\"");

                // jjwt verifica a assinatura conforme o alg do header: se a
                // estratégia assinasse com SHA-256, o parse falharia aqui.
                final Claims claims = Jwts.parser()
                                .verifyWith(publicKey)
                                .build()
                                .parseSignedClaims(assertion)
                                .getPayload();
                assertThat(claims.getSubject()).isEqualTo(CLIENT_ID);
        }

        @Test
        void deveIncluirHubCtxQuandoConfigurado() throws Exception {
                // Concern client-assertion-contexto-ig.md §3.4: o claim
                // hub_ctx declara o IG e a versão pretendidos.
                final SmartTokenClient client = SmartTokenClient.builder()
                                .tokenEndpoint(TOKEN_ENDPOINT)
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .hubContext("hemograma", "0.0.1")
                                .build();

                final String assertion = client.buildClientAssertion();
                final String payloadJson = new String(
                                java.util.Base64.getUrlDecoder().decode(assertion.split("\\.")[1]),
                                StandardCharsets.UTF_8);
                assertThat(payloadJson)
                                .contains("\"hub_ctx\":{\"ig\":\"hemograma\",\"versao\":\"0.0.1\"}");

                // Assinatura continua válida com o claim adicional
                final Claims claims = Jwts.parser()
                                .verifyWith(publicKey)
                                .build()
                                .parseSignedClaims(assertion)
                                .getPayload();
                assertThat(claims.getSubject()).isEqualTo(CLIENT_ID);
        }

        @Test
        void naoDeveIncluirHubCtxPorPadrao() throws Exception {
                final SmartTokenClient client = SmartTokenClient.builder()
                                .tokenEndpoint(TOKEN_ENDPOINT)
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .build();

                final String assertion = client.buildClientAssertion();
                final String payloadJson = new String(
                                java.util.Base64.getUrlDecoder().decode(assertion.split("\\.")[1]),
                                StandardCharsets.UTF_8);
                assertThat(payloadJson).doesNotContain("\"hub_ctx\"");
        }

        @Test
        void deveRejeitarHubContextComFormatoInvalido() {
                // Concern §3.4: ig segue [a-z][a-z0-9-]{1,30} e versao é
                // SemVer completo MAJOR.MINOR.PATCH (sem pre-release/build).
                final var builder = SmartTokenClient.builder()
                                .tokenEndpoint(TOKEN_ENDPOINT)
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile);

                assertThatThrownBy(() -> builder.hubContext("Hemograma", "0.0.1"))
                                .isInstanceOf(IllegalArgumentException.class)
                                .hasMessageContaining("ig");
                assertThatThrownBy(() -> builder.hubContext("a", "0.0.1"))
                                .isInstanceOf(IllegalArgumentException.class)
                                .hasMessageContaining("ig");
                assertThatThrownBy(() -> builder.hubContext("hemograma", "1.2"))
                                .isInstanceOf(IllegalArgumentException.class)
                                .hasMessageContaining("versao");
                assertThatThrownBy(() -> builder.hubContext("hemograma", "1.2.3-rc.1"))
                                .isInstanceOf(IllegalArgumentException.class)
                                .hasMessageContaining("versao");
                assertThatThrownBy(() -> builder.hubContext(null, "1.2.3"))
                                .isInstanceOf(IllegalArgumentException.class);
                assertThatThrownBy(() -> builder.hubContext("hemograma", null))
                                .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void deveFalharConstrutorComChaveECertificadoIncompativeis() throws Exception {
                // Chave recém-gerada, diferente da chave do clientCertificate
                final KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
                gen.initialize(2048);
                final KeyPair outroPar = gen.generateKeyPair();
                final SigningStrategy strategy = SigningStrategyFactory
                                .fromPrivateKey(outroPar.getPrivate());

                assertThatThrownBy(() -> new SmartTokenClient(
                                TOKEN_ENDPOINT, CLIENT_ID, strategy, clientCertificate, SSLContext.getDefault(),
                                new FaultToleranceConfig(Duration.ofSeconds(10), Duration.ofSeconds(30), 60, 3),
                                true, 30, "RS256"))
                                .isInstanceOf(SmartTokenException.class)
                                .hasMessageContaining("não corresponde");
        }

        @Test
        void deveFalharConstrutorComAlgoritmoNone() throws Exception {
                final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(privateKey);

                assertThatThrownBy(() -> new SmartTokenClient(
                                TOKEN_ENDPOINT, CLIENT_ID, strategy, clientCertificate, SSLContext.getDefault(),
                                new FaultToleranceConfig(Duration.ofSeconds(10), Duration.ofSeconds(30), 60, 3),
                                true, 30, "none"))
                                .isInstanceOf(SmartTokenException.class)
                                .hasMessageContaining("não suportado");
        }

        @Test
        void deveFalharConstrutorComAlgoritmoHs256() throws Exception {
                final SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(privateKey);

                assertThatThrownBy(() -> new SmartTokenClient(
                                TOKEN_ENDPOINT, CLIENT_ID, strategy, clientCertificate, SSLContext.getDefault(),
                                new FaultToleranceConfig(Duration.ofSeconds(10), Duration.ofSeconds(30), 60, 3),
                                true, 30, "HS256"))
                                .isInstanceOf(SmartTokenException.class)
                                .hasMessageContaining("não suportado");
        }

        @Test
        void toStringDeTokenResponseNaoDeveExporToken() {
                final var response = new SmartTokenClient.TokenResponse(
                                "token-super-secreto", 3600,
                                "{\"access_token\":\"token-super-secreto\"}");

                assertThat(response.toString()).doesNotContain("token-super-secreto");
                assertThat(response.toString()).contains("[REDACTED]");
                // Acesso direto continua funcionando
                assertThat(response.accessToken()).isEqualTo("token-super-secreto");
        }

        @Test
        void toStringDeCachedTokenNaoDeveExporToken() {
                final var cached = new SmartTokenClient.CachedToken(
                                "token-super-secreto", java.time.Instant.now().plusSeconds(60));

                assertThat(cached.toString()).doesNotContain("token-super-secreto");
                assertThat(cached.toString()).contains("[REDACTED]");
                assertThat(cached.accessToken()).isEqualTo("token-super-secreto");
        }

        @Test
        void deveRejeitarTokenEndpointHttpNaoLocal() {
                assertThatThrownBy(() -> SmartTokenClient.builder()
                                .tokenEndpoint("http://exemplo.com/auth/token")
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .build())
                                .isInstanceOf(IllegalArgumentException.class)
                                .hasMessageContaining("https");
        }

        @Test
        void deveRejeitarFhirBaseHttpNaoLocal() {
                assertThatThrownBy(() -> SmartTokenClient.builder()
                                .fhirBase("http://exemplo.com/fhir")
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .build())
                                .isInstanceOf(IllegalArgumentException.class)
                                .hasMessageContaining("https");
        }

        @Test
        void devePermitirHttpParaLocalhost() throws Exception {
                final SmartTokenClient client = SmartTokenClient.builder()
                                .tokenEndpoint("http://localhost:8080/auth/token")
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .build();

                assertThat(client.getTokenEndpoint()).isEqualTo("http://localhost:8080/auth/token");
        }

        @Test
        void closeDeveSerIdempotente() throws Exception {
                final SmartTokenClient client = SmartTokenClient.builder()
                                .tokenEndpoint(TOKEN_ENDPOINT)
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .build();

                client.close();
                client.close(); // segunda chamada não deve lançar exceção
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
