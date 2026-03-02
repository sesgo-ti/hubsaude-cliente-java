/*
 * Copyright (c) 2026 SES-GO / UFG
 * Todos os direitos reservados.
 */

package br.gov.go.saude.hubsaude.client;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;

/**
 * Testes de integração do SmartTokenClient usando modo Docker (Testcontainers).
 *
 * <p>
 * Inicia automaticamente o simulador como container Docker.
 * Ideal para <strong>CI/CD</strong> e builds 100% reproduzíveis.
 * </p>
 *
 * <h2>Execução</h2>
 * <pre>{@code
 * mvn verify -Dit.test=SmartTokenClientDockerIT
 * }</pre>
 *
 * <h2>Pré-requisitos</h2>
 * <ul>
 *   <li>Docker instalado e em execução</li>
 *   <li>hubsaude-simulador disponível via Maven</li>
 * </ul>
 *
 * @see SmartTokenClientIntegrationTestBase
 * @see SmartTokenClientJarIT
 */
@DisplayName("Testes de Integração - SmartTokenClient (Docker)")
class SmartTokenClientDockerIT extends SmartTokenClientIntegrationTestBase {

    private static final Logger LOG = LoggerFactory.getLogger(SmartTokenClientDockerIT.class);

    private static final int CONTAINER_PORT = 8443;
    private static final int HOST_PORT = 18443;
    private static final String BASE_URL = "https://localhost:" + HOST_PORT;

    private static GenericContainer<?> simulatorContainer;

    @BeforeAll
    static void iniciarSimulador(@TempDir final Path tempDir) throws Exception {
        LOG.info("🐳 Iniciando simulador via Testcontainers...");
        startDockerSimulator();
        LOG.info("Simulador disponível em: {}", BASE_URL);

        // Gera credenciais de teste
        gerarCredenciais(tempDir);
    }

    @AfterAll
    static void pararSimulador() {
        if (simulatorContainer != null && simulatorContainer.isRunning()) {
            LOG.info("Parando container Docker do simulador...");
            simulatorContainer.stop();
            LOG.info("Container Docker encerrado");
        }
    }

    @Override
    protected String getSimulatorBaseUrl() {
        return BASE_URL;
    }

    // ==================== Inicialização ====================

    @SuppressWarnings("resource")
    private static void startDockerSimulator() {
        final Path jarPath = resolveSimulatorJar();
        LOG.info("Usando JAR do simulador: {}", jarPath);

        simulatorContainer = new GenericContainer<>(
                new ImageFromDockerfile("hubsaude-simulador-test", false)
                        .withFileFromPath("app.jar", jarPath)
                        .withDockerfileFromBuilder(builder -> builder
                                .from("eclipse-temurin:21-jre-alpine")
                                .workDir("/app")
                                .copy("app.jar", "app.jar")
                                .expose(CONTAINER_PORT)
                                .env("LOG_LEVEL", "INFO")
                                .entryPoint("java", "-Djava.security.egd=file:/dev/./urandom", "-jar", "app.jar")
                                .build()))
                .withExposedPorts(CONTAINER_PORT)
                // Usa porta fixa para que a audience do JWT seja consistente
                .withCreateContainerCmdModifier(cmd ->
                        cmd.withHostConfig(cmd.getHostConfig()
                                .withPortBindings(new com.github.dockerjava.api.model.PortBinding(
                                        com.github.dockerjava.api.model.Ports.Binding.bindPort(HOST_PORT),
                                        new com.github.dockerjava.api.model.ExposedPort(CONTAINER_PORT)))))
                .withEnv("LOG_LEVEL", "DEBUG")
                .withEnv("SERVER_BASE_URL", BASE_URL)
                .waitingFor(Wait.forHttps("/.well-known/smart-configuration")
                        .forPort(CONTAINER_PORT)
                        .forStatusCode(200)
                        .allowInsecure()
                        .withStartupTimeout(Duration.ofMinutes(2)))
                .withLogConsumer(new Slf4jLogConsumer(LOG).withPrefix("simulador"));

        simulatorContainer.start();
    }

    private static Path resolveSimulatorJar() {
        final Path simulatorJar = Paths.get("target", "simulator", "hubsaude-simulador.jar");

        if (Files.exists(simulatorJar)) {
            return simulatorJar.toAbsolutePath();
        }

        throw new IllegalStateException(
                "Não foi possível localizar o JAR do hubsaude-simulador em " + simulatorJar + ". " +
                        "Execute 'mvn verify' para que o maven-dependency-plugin copie o artefato.");
    }
}
