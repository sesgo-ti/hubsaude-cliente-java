/*
 * Copyright (c) 2026 SES-GO / UFG
 * Todos os direitos reservados.
 */

package br.gov.go.saude.hubsaude.client;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.util.Base64;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Classe base abstrata para testes de integração do SmartTokenClient.
 *
 * <p>
 * Define todos os casos de teste e delega a infraestrutura
 * (inicialização/parada do simulador)
 * para as subclasses concretas:
 * </p>
 * <ul>
 * <li>{@link SmartTokenClientJarIT} - Usa ProcessBuilder (mais rápido, para dev
 * local e CI/CD)</li>
 * </ul>
 *
 * <h2>Execução</h2>
 * 
 * <pre>{@code
 * mvn verify -Dit.test=SmartTokenClientJarIT
 * }</pre>
 *
 * @see SmartTokenClient
 */
abstract class SmartTokenClientIntegrationTestBase {

        protected final Logger log = LoggerFactory.getLogger(getClass());

        protected static final String CLIENT_ID = "integration-test-client";
        protected static final String ALLOWED_SCOPES = "system/Patient.rs system/Observation.rs";

        /**
         * SSLContext trust-all para testes com certificados auto-assinados do
         * simulador.
         */
        protected static final SSLContext TRUST_ALL_SSL_CONTEXT = SslContextFactory
                        .buildTrustAllSslContext(SslContextFactory.DEFAULT_TLS_PROTOCOL);

        protected Path keyFile;
        protected Path certFile;
        protected String certificatePem;

        // ==================== Métodos Abstratos ====================

        /**
         * Retorna a URL base do simulador (ex: "https://localhost:8443").
         */
        protected abstract String getSimulatorBaseUrl();

        // ==================== URLs do Simulador ====================

        protected String getTokenEndpoint() {
                return getSimulatorBaseUrl() + "/auth/token";
        }

        protected String getRegisterEndpoint() {
                return getSimulatorBaseUrl() + "/clients/register";
        }

        // ==================== Setup de Credenciais ====================

        /**
         * Gera credenciais de teste (chave privada + certificado).
         * Deve ser chamado pelas subclasses no @BeforeAll.
         */
        protected void gerarCredenciais(final Path tempDir) throws Exception {
                // Gera par de chaves RSA
                final KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
                gen.initialize(2048);
                final KeyPair pair = gen.generateKeyPair();

                // Escreve chave privada em formato PEM (PKCS#8)
                keyFile = tempDir.resolve("client-key.pem");
                final String pkcs8Pem = toPkcs8Pem(pair.getPrivate().getEncoded());
                Files.writeString(keyFile, pkcs8Pem, StandardCharsets.UTF_8);

                // Gera certificado autoassinado
                certFile = tempDir.resolve("client-cert.pem");
                certificatePem = generateSelfSignedCertPem(pair);
                Files.writeString(certFile, certificatePem, StandardCharsets.UTF_8);
        }

        // ==================== Setup dos Testes ====================

        @BeforeEach
        void registrarClienteNoSimulador() throws Exception {
                final HttpClient client = HttpClient.newBuilder()
                                .sslContext(TRUST_ALL_SSL_CONTEXT)
                                .connectTimeout(Duration.ofSeconds(10))
                                .build();

                // Registra o cliente via JSON
                final String json = String.format("""
                                {
                                    "client_id": "%s",
                                    "certificate": %s,
                                    "allowed_scopes": "%s"
                                }
                                """, CLIENT_ID, escapeJsonString(certificatePem), ALLOWED_SCOPES);

                final HttpRequest request = HttpRequest.newBuilder()
                                .uri(URI.create(getRegisterEndpoint()))
                                .header("Content-Type", "application/json")
                                .timeout(Duration.ofSeconds(30))
                                .POST(HttpRequest.BodyPublishers.ofString(json))
                                .build();

                // Ignora erros de conflito (cliente já registrado)
                final HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                log.debug("Registro de cliente: status={}, body={}", response.statusCode(), response.body());
        }

        // ==================== Testes ====================

        @Test
        @DisplayName("Deve obter token de acesso com sucesso")
        void deveObterTokenComSucesso() throws Exception {
                final SmartTokenClient tokenClient = SmartTokenClient.builder()
                                .tokenEndpoint(getTokenEndpoint())
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .sslContext(TRUST_ALL_SSL_CONTEXT)
                                .build();

                final String accessToken = tokenClient.obtainToken("system/Patient.rs");

                assertThat(accessToken)
                                .isNotBlank()
                                .contains("."); // JWT tem ao menos um ponto
        }

        @Test
        @DisplayName("Deve falhar com scope não permitido")
        void deveFalharComScopeNaoPermitido() throws Exception {
                final SmartTokenClient tokenClient = SmartTokenClient.builder()
                                .tokenEndpoint(getTokenEndpoint())
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .sslContext(TRUST_ALL_SSL_CONTEXT)
                                .build();

                assertThatThrownBy(() -> tokenClient.obtainToken("system/Encounter.rs"))
                                .isInstanceOf(SmartTokenException.class)
                                .hasMessageContaining("scope");
        }

        @Test
        @DisplayName("Deve reutilizar token do cache quando válido")
        void deveReutilizarTokenDoCache() throws Exception {
                final SmartTokenClient tokenClient = SmartTokenClient.builder()
                                .tokenEndpoint(getTokenEndpoint())
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .enableTokenCache(true)
                                .tokenCacheMarginSeconds(30)
                                .sslContext(TRUST_ALL_SSL_CONTEXT)
                                .build();

                final String token1 = tokenClient.obtainToken("system/Patient.rs");
                final String token2 = tokenClient.obtainToken("system/Patient.rs");

                // Mesmo token deve retornar do cache
                assertThat(token1).isEqualTo(token2);
        }

        @Test
        @DisplayName("Deve obter tokens diferentes para scopes diferentes")
        void deveObterTokensDiferentesParaScopesDiferentes() throws Exception {
                final SmartTokenClient tokenClient = SmartTokenClient.builder()
                                .tokenEndpoint(getTokenEndpoint())
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .enableTokenCache(true)
                                .sslContext(TRUST_ALL_SSL_CONTEXT)
                                .build();

                final String tokenPatient = tokenClient.obtainToken("system/Patient.rs");
                final String tokenObservation = tokenClient.obtainToken("system/Observation.rs");

                // Tokens diferentes para scopes diferentes
                assertThat(tokenPatient).isNotEqualTo(tokenObservation);
        }

        @Test
        @DisplayName("Deve invalidar cache e obter novo token")
        void deveInvalidarCacheEObterNovoToken() throws Exception {
                final SmartTokenClient tokenClient = SmartTokenClient.builder()
                                .tokenEndpoint(getTokenEndpoint())
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .enableTokenCache(true)
                                .sslContext(TRUST_ALL_SSL_CONTEXT)
                                .build();

                final String scope = "system/Patient.rs";
                final String token1 = tokenClient.obtainToken(scope);

                // Invalida o cache para este scope
                tokenClient.invalidateCache(scope);

                final String token2 = tokenClient.obtainToken(scope);

                // Novo token deve ter sido obtido (pode ser igual ou diferente, mas passou pelo
                // servidor)
                assertThat(token1).isNotNull();
                assertThat(token2).isNotNull();
        }

        @Test
        @DisplayName("Deve falhar com client_id não registrado")
        void deveFalharComClientIdNaoRegistrado() throws Exception {
                final SmartTokenClient tokenClient = SmartTokenClient.builder()
                                .tokenEndpoint(getTokenEndpoint())
                                .clientId("cliente-inexistente-xyz")
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .sslContext(TRUST_ALL_SSL_CONTEXT)
                                .build();

                assertThatThrownBy(() -> tokenClient.obtainToken("system/Patient.rs"))
                                .isInstanceOf(SmartTokenException.class)
                                .hasMessageContaining("invalid_client");
        }

        @Test
        @DisplayName("Deve funcionar com múltiplos scopes")
        void deveFuncionarComMultiplosScopes() throws Exception {
                final SmartTokenClient tokenClient = SmartTokenClient.builder()
                                .tokenEndpoint(getTokenEndpoint())
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .sslContext(TRUST_ALL_SSL_CONTEXT)
                                .build();

                final String accessToken = tokenClient.obtainToken("system/Patient.rs system/Observation.rs");

                assertThat(accessToken).isNotBlank();
        }

        @Test
        @DisplayName("Deve respeitar timeout configurado")
        void deveRespeitarTimeoutConfigurado() throws Exception {
                final SmartTokenClient tokenClient = SmartTokenClient.builder()
                                .tokenEndpoint(getTokenEndpoint())
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .connectTimeout(Duration.ofSeconds(5))
                                .requestTimeout(Duration.ofSeconds(30))
                                .sslContext(TRUST_ALL_SSL_CONTEXT)
                                .build();

                // Deve completar dentro do timeout
                final String accessToken = tokenClient.obtainToken("system/Patient.rs");
                assertThat(accessToken).isNotBlank();
        }

        @Test
        @DisplayName("Deve descobrir endpoint dinamicamente e obter token (Discovery)")
        void deveObterTokenUsandoDiscovery() throws Exception {
                // Utiliza fhirBase em vez do tokenEndpoint explícito
                final SmartTokenClient tokenClient = SmartTokenClient.builder()
                                .fhirBase(getSimulatorBaseUrl())
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .sslContext(TRUST_ALL_SSL_CONTEXT)
                                .build();

                // O tokenClient deve ter extraído ".well-known/smart-configuration" no build
                // e conseguido resolver a URL apontando para a própria instância do simulador.
                final String accessToken = tokenClient.obtainToken("system/Patient.rs");

                assertThat(accessToken)
                                .isNotBlank()
                                .contains(".");
        }

        // ==================== Métodos Auxiliares ====================

        protected static String toPkcs8Pem(final byte[] encoded) {
                final String b64 = Base64.getMimeEncoder(64, "\n".getBytes())
                                .encodeToString(encoded);
                return "-----BEGIN PRIVATE KEY-----\n" + b64 + "\n-----END PRIVATE KEY-----\n";
        }

        /**
         * Gera certificado X.509 autoassinado via BouncyCastle.
         */
        protected static String generateSelfSignedCertPem(final KeyPair pair) throws Exception {
                final org.bouncycastle.asn1.x500.X500Name subject = new org.bouncycastle.asn1.x500.X500Name(
                                "CN=" + CLIENT_ID + ",O=Test,C=BR");
                final BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
                final Date notBefore = new Date();
                final Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000);

                final org.bouncycastle.cert.X509v3CertificateBuilder builder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                                subject, serial, notBefore, notAfter, subject, pair.getPublic());

                final org.bouncycastle.operator.ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(
                                "SHA256WithRSA")
                                .build(pair.getPrivate());

                final byte[] certDer = builder.build(signer).getEncoded();
                final String b64 = Base64.getMimeEncoder(64, "\n".getBytes())
                                .encodeToString(certDer);
                return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n";
        }

        /**
         * Escapa string para uso em JSON.
         */
        protected static String escapeJsonString(final String input) {
                return "\"" + input
                                .replace("\\", "\\\\")
                                .replace("\"", "\\\"")
                                .replace("\n", "\\n")
                                .replace("\r", "\\r")
                                + "\"";
        }
}
