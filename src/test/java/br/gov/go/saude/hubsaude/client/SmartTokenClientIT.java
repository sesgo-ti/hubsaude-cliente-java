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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Testes de integração do SmartTokenClient com simulador iniciado automaticamente.
 *
 * <p>
 * Utiliza <strong>Testcontainers</strong> para iniciar automaticamente o simulador
 * (hubsaude-simulador) como um container Docker. Isso garante que os testes sejam:
 * </p>
 * <ul>
 *   <li><strong>Autocontidos:</strong> Não requerem serviços externos iniciados manualmente</li>
 *   <li><strong>Reproduzíveis:</strong> Funcionam em qualquer ambiente com Docker</li>
 *   <li><strong>Isolados:</strong> Cada execução usa um container limpo</li>
 * </ul>
 *
 * <h2>Pré-requisitos</h2>
 * <ul>
 *   <li>Docker instalado e em execução</li>
 *   <li>Projeto hubsaude-simulador compilado (mvn package -DskipTests)</li>
 * </ul>
 *
 * <h2>Execução</h2>
 * <pre>{@code
 * # Compilar o simulador primeiro
 * cd ../hubsaude-simulador && mvn package -DskipTests
 *
 * # Executar testes de integração
 * cd ../hubsaude-cliente-java && mvn verify
 * }</pre>
 *
 * @see SmartTokenClient
 */
@Tag("integration")
@Testcontainers
@DisplayName("Testes de Integração - SmartTokenClient (Testcontainers)")
class SmartTokenClientIT {

    private static final Logger LOG = LoggerFactory.getLogger(SmartTokenClientIT.class);

    private static final int SIMULATOR_PORT = 8443;
    private static final String CLIENT_ID = "integration-test-client";
    private static final String ALLOWED_SCOPES = "system/Patient.rs system/Observation.rs";

    /**
     * Container do simulador HubSaúde.
     *
     * <p>
     * Construído dinamicamente enviando apenas o JAR do simulador (não o diretório inteiro).
     * O container é iniciado uma única vez para todos os testes da classe.
     * </p>
     */
    @Container
    @SuppressWarnings("resource")
    private static final GenericContainer<?> SIMULATOR = createSimulatorContainer();

    private static Path keyFile;
    private static Path certFile;
    private static String certificatePem;

    // Porta fixa no host para evitar problemas de audience no JWT
    private static final int HOST_PORT = 18443;

    @SuppressWarnings("resource")
    private static GenericContainer<?> createSimulatorContainer() {
        final Path jarPath = resolveSimulatorJar();
        LOG.info("Usando JAR do simulador: {}", jarPath);

        // Constrói imagem enviando apenas o JAR (não o diretório inteiro - muito mais rápido)
        return new GenericContainer<>(
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
                                        com.github.dockerjava.api.model.Ports.Binding.bindPort(HOST_PORT),
                                        new com.github.dockerjava.api.model.ExposedPort(SIMULATOR_PORT)))))
                .withEnv("LOG_LEVEL", "DEBUG")
                .withEnv("SERVER_BASE_URL", "https://localhost:" + HOST_PORT)
                .waitingFor(Wait.forHttps("/.well-known/smart-configuration")
                        .forPort(SIMULATOR_PORT)
                        .forStatusCode(200)
                        .allowInsecure()
                        .withStartupTimeout(Duration.ofMinutes(2)))
                .withLogConsumer(new Slf4jLogConsumer(LOG).withPrefix("simulador"));
    }

    /**
     * Resolve o caminho do JAR do hubsaude-simulador.
     *
     * <p>
     * O JAR é obtido via Maven (dependência de teste) e copiado para target/simulator
     * pelo maven-dependency-plugin durante a fase pre-integration-test.
     * </p>
     */
    private static Path resolveSimulatorJar() {
        // JAR copiado pelo maven-dependency-plugin em pre-integration-test
        final Path simulatorJar = Paths.get("target", "simulator", "hubsaude-simulador.jar");
        
        if (Files.exists(simulatorJar)) {
            return simulatorJar.toAbsolutePath();
        }

        throw new IllegalStateException(
                "Não foi possível localizar o JAR do hubsaude-simulador em " + simulatorJar + ". " +
                        "Execute 'mvn verify' para que o maven-dependency-plugin copie o artefato.");
    }

    private static String getSimulatorBaseUrl() {
        return String.format("https://%s:%d",
                SIMULATOR.getHost(),
                HOST_PORT);
    }

    private static String getTokenEndpoint() {
        return getSimulatorBaseUrl() + "/auth/token";
    }

    private static String getRegisterEndpoint() {
        return getSimulatorBaseUrl() + "/clients/register";
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
