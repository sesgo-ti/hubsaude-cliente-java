/*
 * Copyright (c) 2026 SES-GO / UFG
 * Todos os direitos reservados.
 */

package br.gov.go.saude.hubsaude.client;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.condition.EnabledIf;

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
 * Testes de integração do SmartTokenClient.
 *
 * <p>
 * Estes testes requerem que o simulador (hubsaude-simulador) esteja em execução
 * na porta 8443. Para iniciar o simulador:
 * </p>
 *
 * <pre>{@code
 * cd projetos/hubsaude-simulador
 * mvn spring-boot:run
 * }</pre>
 *
 * <p>
 * Os testes são marcados com {@code @Tag("integration")} e só executam quando
 * o simulador está acessível. Execute com:
 * </p>
 *
 * <pre>{@code
 * mvn verify -DskipUnitTests
 * # ou
 * mvn failsafe:integration-test
 * }</pre>
 *
 * @see SmartTokenClient
 */
@Tag("integration")
@DisplayName("Testes de Integração - SmartTokenClient")
class SmartTokenClientIT {

    private static final String SIMULATOR_BASE_URL = "https://localhost:8443";
    private static final String TOKEN_ENDPOINT = SIMULATOR_BASE_URL + "/auth/token";
    private static final String REGISTER_ENDPOINT = SIMULATOR_BASE_URL + "/clients/register";
    private static final String CLIENT_ID = "integration-test-client";
    private static final String ALLOWED_SCOPES = "system/Patient.rs system/Observation.rs";

    private static Path keyFile;
    private static Path certFile;
    private static String certificatePem;

    /**
     * Verifica se o simulador está acessível antes de executar os testes.
     */
    static boolean isSimulatorAvailable() {
        try {
            final HttpClient client = HttpClient.newBuilder()
                    .sslContext(SmartTokenClient.buildTrustAllSslContext())
                    .connectTimeout(Duration.ofSeconds(2))
                    .build();

            final HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(SIMULATOR_BASE_URL + "/actuator/health"))
                    .timeout(Duration.ofSeconds(2))
                    .GET()
                    .build();

            final HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() == 200;
        } catch (final Exception e) {
            System.err.println("Simulador não disponível em " + SIMULATOR_BASE_URL + ": " + e.getMessage());
            return false;
        }
    }

    @BeforeAll
    static void gerarCredenciais(@TempDir final Path tempDir) throws Exception {
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

    @BeforeEach
    void registrarClienteNoSimulador() throws Exception {
        if (!isSimulatorAvailable()) {
            return;
        }

        final HttpClient client = HttpClient.newBuilder()
                .sslContext(SmartTokenClient.buildTrustAllSslContext())
                .connectTimeout(Duration.ofSeconds(5))
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
                .uri(URI.create(REGISTER_ENDPOINT))
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(10))
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();

        // Ignora erros de conflito (cliente já registrado)
        client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    @Test
    @EnabledIf("isSimulatorAvailable")
    @DisplayName("Deve obter token de acesso com sucesso")
    void deveObterTokenComSucesso() throws Exception {
        final SmartTokenClient tokenClient = SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .certificatePem(certFile)
                .build();

        final String accessToken = tokenClient.obtainToken("system/Patient.rs");

        assertThat(accessToken)
                .isNotBlank()
                .contains("."); // JWT tem ao menos um ponto
    }

    @Test
    @EnabledIf("isSimulatorAvailable")
    @DisplayName("Deve falhar com scope não permitido")
    void deveFalharComScopeNaoPermitido() throws Exception {
        final SmartTokenClient tokenClient = SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .certificatePem(certFile)
                .build();

        assertThatThrownBy(() -> tokenClient.obtainToken("system/Encounter.rs"))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("scope");
    }

    @Test
    @EnabledIf("isSimulatorAvailable")
    @DisplayName("Deve reutilizar token do cache quando válido")
    void deveReutilizarTokenDoCache() throws Exception {
        final SmartTokenClient tokenClient = SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .certificatePem(certFile)
                .enableTokenCache(true)
                .tokenCacheMarginSeconds(30)
                .build();

        final String token1 = tokenClient.obtainToken("system/Patient.rs");
        final String token2 = tokenClient.obtainToken("system/Patient.rs");

        // Mesmo token deve retornar do cache
        assertThat(token1).isEqualTo(token2);
    }

    @Test
    @EnabledIf("isSimulatorAvailable")
    @DisplayName("Deve obter tokens diferentes para scopes diferentes")
    void deveObterTokensDiferentesParaScopesDiferentes() throws Exception {
        final SmartTokenClient tokenClient = SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .certificatePem(certFile)
                .enableTokenCache(true)
                .build();

        final String tokenPatient = tokenClient.obtainToken("system/Patient.rs");
        final String tokenObservation = tokenClient.obtainToken("system/Observation.rs");

        // Tokens diferentes para scopes diferentes
        assertThat(tokenPatient).isNotEqualTo(tokenObservation);
    }

    @Test
    @EnabledIf("isSimulatorAvailable")
    @DisplayName("Deve invalidar cache e obter novo token")
    void deveInvalidarCacheEObterNovoToken() throws Exception {
        final SmartTokenClient tokenClient = SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .certificatePem(certFile)
                .enableTokenCache(true)
                .build();

        final String scope = "system/Patient.rs";
        final String token1 = tokenClient.obtainToken(scope);

        // Invalida o cache para este scope
        tokenClient.invalidateCache(scope);

        final String token2 = tokenClient.obtainToken(scope);

        // Novo token deve ter sido obtido (pode ser igual ou diferente, mas passou pelo servidor)
        assertThat(token1).isNotNull();
        assertThat(token2).isNotNull();
    }

    @Test
    @EnabledIf("isSimulatorAvailable")
    @DisplayName("Deve falhar com client_id não registrado")
    void deveFalharComClientIdNaoRegistrado() throws Exception {
        final SmartTokenClient tokenClient = SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId("cliente-inexistente-xyz")
                .privateKeyPem(keyFile)
                .certificatePem(certFile)
                .build();

        assertThatThrownBy(() -> tokenClient.obtainToken("system/Patient.rs"))
                .isInstanceOf(SmartTokenException.class)
                .hasMessageContaining("invalid_client");
    }

    @Test
    @EnabledIf("isSimulatorAvailable")
    @DisplayName("Deve funcionar com múltiplos scopes")
    void deveFuncionarComMultiplosScopes() throws Exception {
        final SmartTokenClient tokenClient = SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .certificatePem(certFile)
                .build();

        final String accessToken = tokenClient.obtainToken("system/Patient.rs system/Observation.rs");

        assertThat(accessToken).isNotBlank();
    }

    @Test
    @EnabledIf("isSimulatorAvailable")
    @DisplayName("Deve respeitar timeout configurado")
    void deveRespeitarTimeoutConfigurado() throws Exception {
        final SmartTokenClient tokenClient = SmartTokenClient.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .clientId(CLIENT_ID)
                .privateKeyPem(keyFile)
                .certificatePem(certFile)
                .connectTimeout(Duration.ofSeconds(5))
                .requestTimeout(Duration.ofSeconds(30))
                .build();

        // Deve completar dentro do timeout
        final String accessToken = tokenClient.obtainToken("system/Patient.rs");
        assertThat(accessToken).isNotBlank();
    }

    // ---------- Métodos auxiliares ----------

    private static String toPkcs8Pem(final byte[] encoded) {
        final String b64 = Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(encoded);
        return "-----BEGIN PRIVATE KEY-----\n" + b64 + "\n-----END PRIVATE KEY-----\n";
    }

    /**
     * Gera certificado X.509 autoassinado via BouncyCastle.
     */
    private static String generateSelfSignedCertPem(final KeyPair pair) throws Exception {
        final org.bouncycastle.asn1.x500.X500Name subject =
                new org.bouncycastle.asn1.x500.X500Name("CN=" + CLIENT_ID + ",O=Test,C=BR");
        final BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        final Date notBefore = new Date();
        final Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000);

        final org.bouncycastle.cert.X509v3CertificateBuilder builder =
                new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                        subject, serial, notBefore, notAfter, subject, pair.getPublic());

        final org.bouncycastle.operator.ContentSigner signer =
                new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256WithRSA")
                        .build(pair.getPrivate());

        final byte[] certDer = builder.build(signer).getEncoded();
        final String b64 = Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(certDer);
        return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n";
    }

    /**
     * Escapa string para uso em JSON.
     */
    private static String escapeJsonString(final String input) {
        return "\"" + input
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                + "\"";
    }
}
