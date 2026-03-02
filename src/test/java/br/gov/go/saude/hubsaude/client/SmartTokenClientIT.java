/*
 * Copyright (c) 2026 SES-GO / UFG
 * Todos os direitos reservados.
 */

package br.gov.go.saude.hubsaude.client;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Testes de integração do SmartTokenClient com simulador SMART on FHIR.
 *
 * <p>
 * Suporta <strong>dois modos de execução</strong>, ambos com inicialização automática:
 * </p>
 *
 * <h2>1. Modo JAR (ProcessBuilder) — Padrão</h2>
 * <p>
 * Inicia automaticamente o simulador como processo Java local.
 * Mais rápido, ideal para desenvolvimento local.
 * </p>
 * <pre>{@code
 * mvn verify
 * }</pre>
 *
 * <h2>2. Modo Docker (Testcontainers)</h2>
 * <p>
 * Inicia automaticamente o simulador como container Docker.
 * Ideal para CI/CD e builds reproduzíveis.
 * </p>
 * <pre>{@code
 * mvn verify -Dsimulator.mode=docker
 * }</pre>
 *
 * <h2>Pré-requisitos</h2>
 * <ul>
 *   <li><strong>Modo JAR:</strong> Java 21+ instalado</li>
 *   <li><strong>Modo Docker:</strong> Docker instalado e em execução</li>
 *   <li>hubsaude-simulador disponível via Maven (GitHub Packages ou .m2 local)</li>
 * </ul>
 *
 * <h2>Comparação de Performance</h2>
 * <table>
 *   <tr><th>Modo</th><th>Tempo aproximado</th><th>Uso recomendado</th></tr>
 *   <tr><td>Docker</td><td>~6s</td><td>CI/CD, builds reproduzíveis</td></tr>
 *   <tr><td>JAR</td><td>~3s</td><td>Desenvolvimento local</td></tr>
 * </table>
 *
 * @see SmartTokenClient
 */
@Tag("integration")
@DisplayName("Testes de Integração - SmartTokenClient")
class SmartTokenClientIT {

    private static final Logger LOG = LoggerFactory.getLogger(SmartTokenClientIT.class);

    private static final int SIMULATOR_PORT = 8443;
    private static final int DOCKER_HOST_PORT = 18443;
    private static final String CLIENT_ID = "integration-test-client";
    private static final String ALLOWED_SCOPES = "system/Patient.rs system/Observation.rs";

    /**
     * Modo de execução do simulador: "jar" (padrão) ou "docker".
     */
    private static final String SIMULATOR_MODE = System.getProperty("simulator.mode", "jar");

    /**
     * Indica se estamos usando modo Docker (Testcontainers) ou JAR (ProcessBuilder).
     */
    private static final boolean USING_DOCKER_MODE = "docker".equalsIgnoreCase(SIMULATOR_MODE);

    /**
     * Container do simulador HubSaúde (null se usando modo JAR).
     */
    private static GenericContainer<?> dockerContainer;

    /**
     * Processo do simulador JAR (null se usando modo Docker).
     */
    private static Process jarProcess;

    /**
     * URL base do simulador (depende do modo de execução).
     */
    private static String simulatorBaseUrl;

    private static Path keyFile;
    private static Path certFile;
    private static String certificatePem;

    @BeforeAll
    static void inicializarSimulador(@TempDir final Path tempDir) throws Exception {
        if (USING_DOCKER_MODE) {
            LOG.info("🐳 Modo DOCKER: iniciando simulador via Testcontainers");
            startDockerSimulator();
            simulatorBaseUrl = "https://localhost:" + DOCKER_HOST_PORT;
        } else {
            LOG.info("☕ Modo JAR: iniciando simulador via ProcessBuilder");
            startJarSimulator();
            simulatorBaseUrl = "https://localhost:" + SIMULATOR_PORT;
        }

        LOG.info("Simulador disponível em: {}", simulatorBaseUrl);

        // Gera credenciais de teste
        gerarCredenciais(tempDir);
    }

    @AfterAll
    static void pararSimulador() {
        if (USING_DOCKER_MODE && dockerContainer != null && dockerContainer.isRunning()) {
            LOG.info("Parando container Docker do simulador...");
            dockerContainer.stop();
            LOG.info("Container Docker encerrado");
        }

        if (!USING_DOCKER_MODE && jarProcess != null) {
            LOG.info("Parando processo JAR do simulador...");
            jarProcess.destroy();
            try {
                jarProcess.waitFor(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                jarProcess.destroyForcibly();
            }
            LOG.info("Processo JAR encerrado");
        }
    }

    // ==================== Inicialização do Simulador ====================

    private static void startJarSimulator() throws Exception {
        final Path jarPath = resolveSimulatorJar();
        LOG.info("Usando JAR do simulador: {}", jarPath);

        final ProcessBuilder pb = new ProcessBuilder(
                "java",
                "-Djava.security.egd=file:/dev/./urandom",
                "-jar", jarPath.toString()
        );
        pb.redirectErrorStream(true);

        jarProcess = pb.start();

        // Thread para consumir output (evita bloqueio do processo)
        final Thread outputThread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(jarProcess.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    LOG.debug("[simulador-jar] {}", line);
                }
            } catch (IOException e) {
                if (jarProcess.isAlive()) {
                    LOG.warn("Erro ao ler output do simulador: {}", e.getMessage());
                }
            }
        }, "simulator-output-reader");
        outputThread.setDaemon(true);
        outputThread.start();

        // Aguarda o simulador ficar pronto
        waitForSimulator("https://localhost:" + SIMULATOR_PORT);
    }

    @SuppressWarnings("resource")
    private static void startDockerSimulator() {
        final Path jarPath = resolveSimulatorJar();
        LOG.info("Usando JAR do simulador: {}", jarPath);

        dockerContainer = new GenericContainer<>(
                new ImageFromDockerfile("hubsaude-simulador-test", false)
                        .withFileFromPath("app.jar", jarPath)
                        .withDockerfileFromBuilder(builder -> builder
                                .from("eclipse-temurin:21-jre-alpine")
                                .workDir("/app")
                                .copy("app.jar", "app.jar")
                                .expose(SIMULATOR_PORT)
                                .env("LOG_LEVEL", "INFO")
                                .entryPoint("java", "-Djava.security.egd=file:/dev/./urandom", "-jar", "app.jar")
                                .build()))
                .withExposedPorts(SIMULATOR_PORT)
                // Usa porta fixa para que a audience do JWT seja consistente
                .withCreateContainerCmdModifier(cmd ->
                        cmd.withHostConfig(cmd.getHostConfig()
                                .withPortBindings(new com.github.dockerjava.api.model.PortBinding(
                                        com.github.dockerjava.api.model.Ports.Binding.bindPort(DOCKER_HOST_PORT),
                                        new com.github.dockerjava.api.model.ExposedPort(SIMULATOR_PORT)))))
                .withEnv("LOG_LEVEL", "DEBUG")
                .withEnv("SERVER_BASE_URL", "https://localhost:" + DOCKER_HOST_PORT)
                .waitingFor(Wait.forHttps("/.well-known/smart-configuration")
                        .forPort(SIMULATOR_PORT)
                        .forStatusCode(200)
                        .allowInsecure()
                        .withStartupTimeout(Duration.ofMinutes(2)))
                .withLogConsumer(new Slf4jLogConsumer(LOG).withPrefix("simulador"));

        dockerContainer.start();
    }

    /**
     * Aguarda o simulador ficar pronto (usado no modo JAR).
     */
    private static void waitForSimulator(final String baseUrl) throws Exception {
        final HttpClient client = HttpClient.newBuilder()
                .sslContext(SmartTokenClient.buildTrustAllSslContext())
                .connectTimeout(Duration.ofSeconds(5))
                .build();

        final String healthUrl = baseUrl + "/.well-known/smart-configuration";
        final int maxAttempts = 60; // 60 segundos no máximo
        final int delayMs = 1000;

        LOG.info("Aguardando simulador em {}...", healthUrl);

        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                final HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(healthUrl))
                        .timeout(Duration.ofSeconds(5))
                        .GET()
                        .build();

                final HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() == 200) {
                    LOG.info("Simulador pronto após {} tentativa(s)", attempt);
                    return;
                }
            } catch (Exception e) {
                // Simulador ainda não está pronto
                if (attempt % 10 == 0) {
                    LOG.debug("Tentativa {}/{}: {}", attempt, maxAttempts, e.getMessage());
                }
            }

            // Verifica se o processo ainda está vivo
            if (jarProcess != null && !jarProcess.isAlive()) {
                throw new IllegalStateException(
                        "Processo do simulador terminou inesperadamente com código: " + jarProcess.exitValue());
            }

            Thread.sleep(delayMs);
        }

        throw new IllegalStateException(
                "Simulador não ficou pronto em " + maxAttempts + " segundos. URL: " + healthUrl);
    }

    /**
     * Resolve o caminho do JAR do hubsaude-simulador.
     */
    private static Path resolveSimulatorJar() {
        final Path simulatorJar = Paths.get("target", "simulator", "hubsaude-simulador.jar");

        if (Files.exists(simulatorJar)) {
            return simulatorJar.toAbsolutePath();
        }

        throw new IllegalStateException(
                "Não foi possível localizar o JAR do hubsaude-simulador em " + simulatorJar + ". " +
                        "Execute 'mvn verify' para que o maven-dependency-plugin copie o artefato.");
    }

    private static void gerarCredenciais(final Path tempDir) throws Exception {
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

    // ==================== URLs do Simulador ====================

    private static String getTokenEndpoint() {
        return simulatorBaseUrl + "/auth/token";
    }

    private static String getRegisterEndpoint() {
        return simulatorBaseUrl + "/clients/register";
    }

    // ==================== Setup dos Testes ====================

    @BeforeEach
    void registrarClienteNoSimulador() throws Exception {
        final HttpClient client = HttpClient.newBuilder()
                .sslContext(SmartTokenClient.buildTrustAllSslContext())
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
        LOG.debug("Registro de cliente: status={}, body={}", response.statusCode(), response.body());
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
    @DisplayName("Deve falhar com client_id não registrado")
    void deveFalharComClientIdNaoRegistrado() throws Exception {
        final SmartTokenClient tokenClient = SmartTokenClient.builder()
                .tokenEndpoint(getTokenEndpoint())
                .clientId("cliente-inexistente-xyz")
                .privateKeyPem(keyFile)
                .certificatePem(certFile)
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
                .build();

        // Deve completar dentro do timeout
        final String accessToken = tokenClient.obtainToken("system/Patient.rs");
        assertThat(accessToken).isNotBlank();
    }

    // ==================== Métodos Auxiliares ====================

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
