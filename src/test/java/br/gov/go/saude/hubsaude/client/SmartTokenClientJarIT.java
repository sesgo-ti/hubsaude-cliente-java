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

import java.io.BufferedReader;
import java.io.File;
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
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
 */
@Tag("integration")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DisplayName("Testes de Integração - SmartTokenClient (JAR)")
@SuppressWarnings("PMD.TestClassWithoutTestCases") // casos @Test herdados de SmartTokenClientIntegrationTestBase
class SmartTokenClientJarIT extends SmartTokenClientIntegrationTestBase {

    private static final Logger LOG = LoggerFactory.getLogger(SmartTokenClientJarIT.class);

    /** Porta efêmera alocada dinamicamente para o simulador. */
    private int simulatorPort;

    /** URL base do simulador, derivada da porta efêmera. */
    private String baseUrl;

    private Process simulatorProcess;

    @BeforeAll
    void iniciarSimulador(@TempDir final Path tempDir) throws Exception {
        simulatorPort = allocateFreePort();
        baseUrl = "https://localhost:" + simulatorPort;
        LOG.info("Iniciando simulador via ProcessBuilder na porta {}...", simulatorPort);
        startJarSimulator();
        LOG.info("Simulador disponível em: {}", baseUrl);

        // Extrai o certificado do simulador e constrói SSLContext seguro
        simulatorCert = extractServerCertificate("localhost", simulatorPort);
        simulatorSslContext = SslContextFactory.buildSslContext(simulatorCert, SslContextFactory.DEFAULT_TLS_PROTOCOL);
        LOG.info("SSLContext construído com certificado do simulador: {}", simulatorCert.getSubjectX500Principal());

        // Gera credenciais de teste
        gerarCredenciais(tempDir);
    }

    /**
     * Aloca uma porta TCP livre no host, evitando conflito com outros
     * processos (elimina a dependência da porta fixa 8443).
     *
     * @return número de porta livre
     * @throws IOException se não for possível abrir socket local
     */
    private static int allocateFreePort() throws IOException {
        try (java.net.ServerSocket socket = new java.net.ServerSocket(0)) {
            socket.setReuseAddress(true);
            return socket.getLocalPort();
        }
    }

    @AfterAll
    void pararSimulador() {
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
        return baseUrl;
    }

    // ==================== Inicialização ====================

    private void startJarSimulator() throws Exception {
        final Path jarPath = resolveSimulatorJar();
        LOG.info("Usando JAR do simulador: {}", jarPath);

        final ProcessBuilder pb = new ProcessBuilder(
                "java",
                "-Djava.security.egd=file:/dev/./urandom",
                "-jar", jarPath.toString(),
                "--server.port=" + simulatorPort,
                "--server.base-url=" + baseUrl);
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

    private void waitForSimulator() throws Exception {
        // try-with-resources: libera o HttpClient usado no polling (#1810).
        try (HttpClient client = HttpClient.newBuilder()
                .sslContext(TestSslContextFactory.buildTrustAllSslContext(SslContextFactory.DEFAULT_TLS_PROTOCOL))
                .connectTimeout(Duration.ofSeconds(5))
                .build()) {
            waitForSimulator(client);
        }
    }

    private void waitForSimulator(final HttpClient client) throws Exception {
        final String healthUrl = baseUrl + "/.well-known/smart-configuration";
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

    private Path resolveSimulatorJar() {
        final Path simulatorJar = Paths.get("target", "simulator", "hubsaude-simulador.jar");

        if (Files.exists(simulatorJar)) {
            return simulatorJar.toAbsolutePath();
        }

        // Fallback: execução direta pela IDE (ex.: IntelliJ IDEA), sem a fase
        // Maven 'pre-integration-test' que dispara o maven-dependency-plugin
        // (copy-simulator). Como o hubsaude-simulador é dependência test-scope,
        // o JAR executável (Spring Boot) já está em ~/.m2 e no classpath de
        // teste montado pela IDE — basta localizá-lo ali.
        final Path fromClasspath = resolveSimulatorJarFromClasspath();
        if (fromClasspath != null) {
            LOG.info("JAR do simulador resolvido via classpath de teste: {}", fromClasspath);
            return fromClasspath;
        }

        throw new IllegalStateException(
                "Não foi possível localizar o JAR do hubsaude-simulador em " + simulatorJar
                        + " nem no classpath de teste. Rode 'mvn verify' (o maven-dependency-plugin "
                        + "copia o artefato) ou garanta que a dependência de teste "
                        + "br.gov.go.saude.hubsaude:hubsaude-simulador esteja resolvida em ~/.m2.");
    }

    /**
     * Localiza o JAR executável do simulador entre as entradas do classpath
     * de teste, ignorando os artefatos {@code -sources}/{@code -javadoc}.
     *
     * @return caminho absoluto do JAR, ou {@code null} se ausente do classpath
     */
    private Path resolveSimulatorJarFromClasspath() {
        final String classpath = System.getProperty("java.class.path", "");
        for (final String entry : classpath.split(File.pathSeparator)) {
            final Path candidate = Paths.get(entry);
            final Path fileName = candidate.getFileName();
            final String name = fileName != null ? fileName.toString() : "";
            if (name.startsWith("hubsaude-simulador")
                    && name.endsWith(".jar")
                    && !name.endsWith("-sources.jar")
                    && !name.endsWith("-javadoc.jar")
                    && Files.exists(candidate)) {
                return candidate.toAbsolutePath();
            }
        }
        return null;
    }

    /**
     * Extrai o certificado X.509 do servidor via conexão SSL.
     *
     * <p>
     * Conecta ao servidor usando trust-all temporário apenas para obter o certificado,
     * que será usado para construir um SSLContext seguro para os testes.
     * </p>
     *
     * @param host hostname do servidor
     * @param port porta HTTPS do servidor
     * @return certificado X.509 do servidor
     * @throws Exception se não conseguir extrair o certificado
     */
    private X509Certificate extractServerCertificate(final String host, final int port) throws Exception {
        // Usa trust-all temporário APENAS para extrair o certificado
        final SSLContext trustAllContext = TestSslContextFactory.buildTrustAllSslContext(SslContextFactory.DEFAULT_TLS_PROTOCOL);
        final SSLSocketFactory factory = trustAllContext.getSocketFactory();

        try (SSLSocket socket = (SSLSocket) factory.createSocket(host, port)) {
            socket.setSoTimeout(5000);
            socket.startHandshake();

            final SSLSession session = socket.getSession();
            final java.security.cert.Certificate[] certs = session.getPeerCertificates();

            if (certs.length == 0) {
                throw new IllegalStateException("Servidor não retornou certificados");
            }

            // O primeiro certificado é o do servidor
            if (certs[0] instanceof X509Certificate x509Cert) {
                LOG.debug("Certificado extraído: subject={}, issuer={}",
                        x509Cert.getSubjectX500Principal(),
                        x509Cert.getIssuerX500Principal());
                return x509Cert;
            }

            throw new IllegalStateException("Certificado do servidor não é X.509");
        }
    }
}
