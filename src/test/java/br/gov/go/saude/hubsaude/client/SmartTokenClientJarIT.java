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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * Testes de integração do SmartTokenClient usando modo JAR (ProcessBuilder).
 *
 * <p>
 * Inicia automaticamente o simulador como processo Java local.
 * Mais rápido (~5s total), ideal para <strong>desenvolvimento local</strong>.
 * </p>
 *
 * <h2>Execução</h2>
 * 
 * <pre>{@code
 * mvn verify -Dit.test=SmartTokenClientJarIT
 * }</pre>
 *
 * <h2>Pré-requisitos</h2>
 * <ul>
 * <li>Java 21+ instalado</li>
 * <li>hubsaude-simulador disponível via Maven</li>
 * </ul>
 *
 * @see SmartTokenClientIntegrationTestBase
 * @see SmartTokenClientDockerIT
 */
@DisplayName("Testes de Integração - SmartTokenClient (JAR)")
class SmartTokenClientJarIT extends SmartTokenClientIntegrationTestBase {

    private static final Logger LOG = LoggerFactory.getLogger(SmartTokenClientJarIT.class);

    private static final int SIMULATOR_PORT = 8443;
    private static final String BASE_URL = "https://localhost:" + SIMULATOR_PORT;

    private static Process simulatorProcess;

    @BeforeAll
    static void iniciarSimulador(@TempDir final Path tempDir) throws Exception {
        LOG.info("☕ Iniciando simulador via ProcessBuilder...");
        startJarSimulator();
        LOG.info("Simulador disponível em: {}", BASE_URL);

        // Gera credenciais de teste
        gerarCredenciais(tempDir);
    }

    @AfterAll
    static void pararSimulador() {
        if (simulatorProcess != null) {
            LOG.info("Parando processo JAR do simulador...");
            simulatorProcess.destroy();
            try {
                simulatorProcess.waitFor(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                simulatorProcess.destroyForcibly();
            }
            LOG.info("Processo JAR encerrado");
        }
    }

    @Override
    protected String getSimulatorBaseUrl() {
        return BASE_URL;
    }

    // ==================== Inicialização ====================

    private static void startJarSimulator() throws Exception {
        final Path jarPath = resolveSimulatorJar();
        LOG.info("Usando JAR do simulador: {}", jarPath);

        final ProcessBuilder pb = new ProcessBuilder(
                "java",
                "-Djava.security.egd=file:/dev/./urandom",
                "-jar", jarPath.toString());
        pb.redirectErrorStream(true);

        simulatorProcess = pb.start();

        // Thread daemon para consumir output (evita bloqueio)
        final Thread outputThread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(simulatorProcess.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    LOG.debug("[simulador-jar] {}", line);
                }
            } catch (IOException e) {
                if (simulatorProcess.isAlive()) {
                    LOG.warn("Erro ao ler output do simulador: {}", e.getMessage());
                }
            }
        }, "simulator-output-reader");
        outputThread.setDaemon(true);
        outputThread.start();

        // Aguarda o simulador ficar pronto
        waitForSimulator();
    }

    private static void waitForSimulator() throws Exception {
        final HttpClient client = HttpClient.newBuilder()
                .sslContext(SslContextFactory.buildTrustAllSslContext(SslContextFactory.DEFAULT_TLS_PROTOCOL))
                .connectTimeout(Duration.ofSeconds(5))
                .build();

        final String healthUrl = BASE_URL + "/.well-known/smart-configuration";
        final int maxAttempts = 60;
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
                if (attempt % 10 == 0) {
                    LOG.debug("Tentativa {}/{}: {}", attempt, maxAttempts, e.getMessage());
                }
            }

            // Verifica se o processo ainda está vivo
            if (simulatorProcess != null && !simulatorProcess.isAlive()) {
                throw new IllegalStateException(
                        "Processo do simulador terminou inesperadamente com código: " + simulatorProcess.exitValue());
            }

            Thread.sleep(delayMs);
        }

        throw new IllegalStateException(
                "Simulador não ficou pronto em " + maxAttempts + " segundos. URL: " + healthUrl);
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
