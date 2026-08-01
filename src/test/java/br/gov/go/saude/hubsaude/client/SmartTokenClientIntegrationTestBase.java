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

import java.math.BigInteger;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

import javax.net.ssl.SSLContext;

import io.jsonwebtoken.Jwts;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

        protected final String CLIENT_ID =
                        "integration-test-client-" + UUID.randomUUID();
        protected static final String ALLOWED_SCOPES = "system/Patient.rs system/Observation.rs";

        /**
         * Certificado X.509 do simulador para validação TLS.
         * Deve ser inicializado pela subclasse no @BeforeAll após extrair
         * o certificado do servidor.
         */
        protected X509Certificate simulatorCert;

        /**
         * SSLContext configurado com o certificado do simulador.
         * Usado apenas para o registro do cliente (sem mTLS).
         * Deve ser inicializado pela subclasse no @BeforeAll.
         */
        protected SSLContext simulatorSslContext;

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
                certificatePem = generateSelfSignedCertPem(pair, CLIENT_ID);
                Files.writeString(certFile, certificatePem, StandardCharsets.UTF_8);
        }

        // ==================== Setup dos Testes ====================

        @BeforeEach
        void registrarClienteNoSimulador() throws Exception {
                final HttpClient client = HttpClient.newBuilder()
                                .sslContext(simulatorSslContext)
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

                final HttpResponse<String> response = client.send(
                                request, HttpResponse.BodyHandlers.ofString());
                final int status = response.statusCode();
                log.debug("Registro de cliente: status={}, body={}",
                                status, response.body());
                if (status != 200 && status != 201 && status != 409) {
                        throw new IllegalStateException(
                                        "Falha ao registrar cliente no simulador: status="
                                                        + status + " body=" + response.body());
                }
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
                                .serverTrustAnchor(simulatorCert)
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
                                .serverTrustAnchor(simulatorCert)
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
                                .serverTrustAnchor(simulatorCert)
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
                                .serverTrustAnchor(simulatorCert)
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
                                .serverTrustAnchor(simulatorCert)
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
                                .serverTrustAnchor(simulatorCert)
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
                                .serverTrustAnchor(simulatorCert)
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
                                .serverTrustAnchor(simulatorCert)
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
                                .serverTrustAnchor(simulatorCert)
                                .build();

                // O tokenClient deve ter extraído ".well-known/smart-configuration" no build
                // e conseguido resolver a URL apontando para a própria instância do simulador.
                final String accessToken = tokenClient.obtainToken("system/Patient.rs");

                assertThat(accessToken)
                                .isNotBlank()
                                .contains(".");
        }

        // ==================== Testes do elemento kid (issue #408) ==========
        //
        // Testes de caracterização do comportamento do Servidor de
        // Autorização (SA) do HubSaúde (hubsaude-smart-iam, embutido no
        // hubsaude-simulador) em relação ao elemento "kid" (JOSE header).
        //
        // Referência normativa: docs/design/concerns/
        // client-assertion-contexto-ig.md (§3.2 e §5.1) — "kid" é
        // obrigatório quando o cliente possui múltiplas chaves registradas
        // e "kid" desconhecido deve resultar em 401 invalid_client.
        //
        // Se algum destes testes falhar após atualização do simulador,
        // o comportamento do SA quanto ao "kid" mudou — revisar a
        // documentação e a issue #408.

        @Test
        @DisplayName("SA emite access token com kid no header JOSE")
        void saEmiteAccessTokenComKidNoHeader() throws Exception {
                final SmartTokenClient tokenClient = SmartTokenClient.builder()
                                .tokenEndpoint(getTokenEndpoint())
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .serverTrustAnchor(simulatorCert)
                                .build();

                final String accessToken = tokenClient.obtainToken("system/Patient.rs");
                final String kid = extrairKidDoHeaderJwt(accessToken);

                assertThat(kid)
                                .as("SA deve incluir 'kid' no header do access token emitido")
                                .isNotBlank();
        }

        @Test
        @DisplayName("kid do access token corresponde ao kid publicado no JWKS do SA")
        void kidDoAccessTokenCorrespondeAoJwks() throws Exception {
                final SmartTokenClient tokenClient = SmartTokenClient.builder()
                                .tokenEndpoint(getTokenEndpoint())
                                .clientId(CLIENT_ID)
                                .privateKeyPem(keyFile)
                                .certificatePem(certFile)
                                .serverTrustAnchor(simulatorCert)
                                .build();

                final String accessToken = tokenClient.obtainToken("system/Patient.rs");
                final String kidDoToken = extrairKidDoHeaderJwt(accessToken);
                final String kidDoJwks = extrairKidDoJwks();

                assertThat(kidDoToken)
                                .as("kid do access token deve permitir localizar a chave no JWKS")
                                .isEqualTo(kidDoJwks);
        }

        @Test
        @DisplayName("SA aceita client_assertion sem kid (chave única registrada)")
        void saAceitaClientAssertionSemKid() throws Exception {
                final String assertion = construirClientAssertion(null);

                final HttpResponse<String> response = solicitarTokenDireto(assertion);

                assertThat(response.statusCode())
                                .as("Com uma única chave registrada, kid é dispensável (concern §5.1)")
                                .isEqualTo(200);
                assertThat(response.body()).contains("access_token");
        }

        @Test
        @DisplayName("SA atual ignora kid do client_assertion (não valida kid desconhecido)")
        void saIgnoraKidDesconhecidoNoClientAssertion() throws Exception {
                // Caracterização: o SA atual NÃO lê o kid do client_assertion —
                // valida a assinatura com a única chave registrada do cliente.
                // O concern normativo (§5.1) prevê 401 invalid_client
                // ("kid desconhecido") quando houver suporte a múltiplas chaves.
                final String assertion =
                                construirClientAssertion("kid-desconhecido-" + UUID.randomUUID());

                final HttpResponse<String> response = solicitarTokenDireto(assertion);

                assertThat(response.statusCode())
                                .as("SA atual ignora o kid do client_assertion; se este teste "
                                                + "falhar, o SA passou a validar kid (ver issue #408)")
                                .isEqualTo(200);
                assertThat(response.body()).contains("access_token");
        }

        @Test
        @DisplayName("JWKS do SA publica kid para cada chave")
        void jwksDoSaPublicaKid() throws Exception {
                final String kid = extrairKidDoJwks();

                assertThat(kid)
                                .as("Toda chave publicada no JWKS do SA deve ter kid")
                                .isNotBlank();
        }

        // ==================== Auxiliares do kid ====================

        private String getCertsEndpoint() {
                return getSimulatorBaseUrl() + "/certs";
        }

        /**
         * Constrói um {@code client_assertion} JWT assinado com a chave do
         * cliente de teste, opcionalmente com o elemento {@code kid} no
         * header JOSE.
         *
         * @param kid identificador de chave; {@code null} omite o elemento
         * @return JWT compacto pronto para envio ao token endpoint
         */
        private String construirClientAssertion(final String kid) throws Exception {
                final var privateKey = PemLoader.loadPrivateKey(keyFile);
                final Instant now = Instant.now();
                final var builder = Jwts.builder()
                                .issuer(CLIENT_ID)
                                .subject(CLIENT_ID)
                                .audience().add(getTokenEndpoint()).and()
                                .issuedAt(java.util.Date.from(now))
                                .expiration(java.util.Date.from(now.plusSeconds(60)))
                                .id(UUID.randomUUID().toString());
                if (kid != null) {
                        builder.header().add("kid", kid).and();
                }
                return builder.signWith(privateKey, Jwts.SIG.RS384).compact();
        }

        /**
         * Envia o {@code client_assertion} diretamente ao token endpoint do
         * SA (POST form-urlencoded), com mTLS usando as credenciais do
         * cliente de teste.
         */
        private HttpResponse<String> solicitarTokenDireto(final String assertion)
                        throws Exception {
                final SSLContext mtlsContext = SslContextFactory.buildSslContext(
                                simulatorCert,
                                SslContextFactory.DEFAULT_TLS_PROTOCOL,
                                PemLoader.loadPrivateKey(keyFile),
                                PemLoader.loadCertificate(certFile));

                final HttpClient client = HttpClient.newBuilder()
                                .sslContext(mtlsContext)
                                .connectTimeout(Duration.ofSeconds(10))
                                .build();

                final String body = "grant_type=client_credentials"
                                + "&client_assertion_type=" + URLEncoder.encode(
                                                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                                                StandardCharsets.UTF_8)
                                + "&client_assertion=" + URLEncoder.encode(
                                                assertion, StandardCharsets.UTF_8)
                                + "&scope=" + URLEncoder.encode(
                                                "system/Patient.rs", StandardCharsets.UTF_8);

                final HttpRequest request = HttpRequest.newBuilder()
                                .uri(URI.create(getTokenEndpoint()))
                                .header("Content-Type", "application/x-www-form-urlencoded")
                                .timeout(Duration.ofSeconds(30))
                                .POST(HttpRequest.BodyPublishers.ofString(body))
                                .build();

                final HttpResponse<String> response = client.send(
                                request, HttpResponse.BodyHandlers.ofString());
                log.debug("Token endpoint (direto): status={} body={}",
                                response.statusCode(), response.body());
                return response;
        }

        /** Decodifica o header JOSE do JWT e retorna o valor de {@code kid}. */
        private static String extrairKidDoHeaderJwt(final String jwt) {
                final String headerJson = new String(
                                Base64.getUrlDecoder().decode(jwt.split("\\.")[0]),
                                StandardCharsets.UTF_8);
                final JsonNode node = new ObjectMapper().readTree(headerJson);
                return node.has("kid") ? node.get("kid").asString() : null;
        }

        /** Obtém o {@code kid} da primeira chave publicada no JWKS do SA. */
        private String extrairKidDoJwks() throws Exception {
                final HttpClient client = HttpClient.newBuilder()
                                .sslContext(simulatorSslContext)
                                .connectTimeout(Duration.ofSeconds(10))
                                .build();

                final HttpRequest request = HttpRequest.newBuilder()
                                .uri(URI.create(getCertsEndpoint()))
                                .timeout(Duration.ofSeconds(30))
                                .GET()
                                .build();

                final HttpResponse<String> response = client.send(
                                request, HttpResponse.BodyHandlers.ofString());
                assertThat(response.statusCode())
                                .as("JWKS deve estar disponível em " + getCertsEndpoint())
                                .isEqualTo(200);

                final JsonNode keys = new ObjectMapper()
                                .readTree(response.body()).get("keys");
                assertThat(keys)
                                .as("JWKS deve conter ao menos uma chave")
                                .isNotNull();
                assertThat(keys.size()).isPositive();

                final JsonNode kid = keys.get(0).get("kid");
                return kid != null ? kid.asString() : null;
        }

        // ==================== Métodos Auxiliares ====================

        protected static String toPkcs8Pem(final byte[] encoded) {
                final String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                                .encodeToString(encoded);
                return "-----BEGIN PRIVATE KEY-----\n" + b64 + "\n-----END PRIVATE KEY-----\n";
        }

        /**
         * Gera certificado X.509 autoassinado via BouncyCastle.
         */
        protected static String generateSelfSignedCertPem(final KeyPair pair, final String cn) throws Exception {
                final org.bouncycastle.asn1.x500.X500Name subject = new org.bouncycastle.asn1.x500.X500Name(
                                "CN=" + cn + ",O=Test,C=BR");
                final BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
                final java.util.Date notBefore = new java.util.Date();
                final java.util.Date notAfter = new java.util.Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000);

                final org.bouncycastle.cert.X509v3CertificateBuilder builder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                                subject, serial, notBefore, notAfter, subject, pair.getPublic());

                final org.bouncycastle.operator.ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(
                                "SHA256WithRSA")
                                .build(pair.getPrivate());

                final byte[] certDer = builder.build(signer).getEncoded();
                final String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
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
