/*
 * Copyright (c) 2026 SES-GO / UFG
 * Todos os direitos reservados.
 */

package br.gov.go.saude.hubsaude.client;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Objects;
import javax.net.ssl.SSLContext;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Builder fluente para construção de instâncias de {@link SmartTokenClient}.
 *
 * <p>
 * Permite configurar timeouts, TTL do assertion e demais parâmetros
 * de forma legível e segura.
 * </p>
 *
 * <h2>Exemplo com arquivo PEM</h2>
 *
 * <pre>{@code
 * var client = SmartTokenClient.builder()
 *         .tokenEndpoint("https://auth.example.com/token")
 *         .clientId("my-app")
 *         .privateKeyPem(Path.of("key.pem"))
 *         .certificatePem(Path.of("cert.pem"))
 *         .build();
 * }</pre>
 *
 * <h2>Exemplo com SigningStrategy (HSM, Vault, etc.)</h2>
 *
 * <pre>{@code
 * var client = SmartTokenClient.builder()
 *         .tokenEndpoint("https://auth.example.com/token")
 *         .clientId("my-app")
 *         .signingStrategy(SigningStrategyFactory.fromPkcs11(provider, "alias", pin))
 *         .certificatePem(Path.of("cert.pem"))
 *         .build();
 * }</pre>
 *
 * @see SmartTokenClient
 * @see SigningStrategy
 * @see SslContextFactory
 */
@SuppressWarnings({ "checkstyle:HiddenField", "PMD.TooManyFields" }) // Padrão Builder usa nomes iguais e tem muitos
                                                                     // campos
public final class SmartTokenClientBuilder {

    private String tokenEndpoint;
    private String discoveryBaseUrl;
    private String clientId;
    private Path privateKeyPem;
    private char[] privateKeyPassword;
    private SigningStrategy signingStrategy;
    private Path certificatePem;
    private Path serverTrustAnchor;
    private SSLContext customSslContext;
    private String tlsProtocol = SslContextFactory.DEFAULT_TLS_PROTOCOL;
    private FaultToleranceConfig faultToleranceConfig = new FaultToleranceConfig(
        SmartTokenClient.DEFAULT_CONNECT_TIMEOUT,
        SmartTokenClient.DEFAULT_REQUEST_TIMEOUT,
        SmartTokenClient.DEFAULT_ASSERTION_TTL_SECONDS,
        SmartTokenClient.DEFAULT_MAX_RETRIES
    );
    // Os campos enableTokenCache e tokenCacheMarginSeconds podem ser finais, mas são mutáveis via métodos do builder.
    // Para evitar warnings, suprimimos a sugestão de torná-los finais.
    @SuppressWarnings({"PMD.ImmutableField", "java:S1104"})
    private boolean enableTokenCache = true;
    @SuppressWarnings({"PMD.ImmutableField", "java:S1104"})
    private int tokenCacheMarginSeconds = SmartTokenClient.DEFAULT_TOKEN_CACHE_MARGIN_SECONDS;

    SmartTokenClientBuilder() {
    }

    /**
     * Define a URL do endpoint de token.
     *
     * @param tokenEndpoint URL completa (ex: https://host/auth/token)
     * @return este builder
     */
    public SmartTokenClientBuilder tokenEndpoint(final String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
        return this;
    }

    /**
     * Define a URL base do servidor FHIR para descobrir o token_endpoint
     * a partir de /.well-known/smart-configuration.
     *
     * <p>
     * Mutuamente exclusivo com {@link #tokenEndpoint(String)}.
     * </p>
     *
     * @param fhirBaseUrl URL base do servidor FHIR (ex:
     *                    https://hub.saude.go.gov.br)
     * @return este builder
     */
    public SmartTokenClientBuilder fhirBase(final String fhirBaseUrl) {
        this.discoveryBaseUrl = fhirBaseUrl;
        return this;
    }

    /**
     * Define o identificador do cliente.
     *
     * <p>
     * Este valor é fornecido pelo sistema Ganesha no momento do credenciamento
     * do sistema interlocutor junto ao HubSaúde.
     * </p>
     *
     * @param clientId identificador do cliente (ex: {@code hs-XXXXXXXX})
     * @return este builder
     */
    public SmartTokenClientBuilder clientId(final String clientId) {
        this.clientId = clientId;
        return this;
    }

    /**
     * Define o caminho para o arquivo PEM da chave privada.
     *
     * <p>
     * Mutuamente exclusivo com {@link #signingStrategy(SigningStrategy)}.
     * </p>
     *
     * @param privateKeyPem caminho absoluto
     * @return este builder
     */
    public SmartTokenClientBuilder privateKeyPem(final Path privateKeyPem) {
        this.privateKeyPem = privateKeyPem;
        return this;
    }

    /**
     * Define a senha para decriptar a chave privada PEM.
     *
     * <p>
     * Necessária apenas se a chave estiver criptografada (PKCS#8 encrypted
     * ou formato OpenSSL tradicional com DEK-Info).
     * </p>
     *
     * @param password senha da chave privada
     * @return este builder
     */
    @SuppressWarnings("PMD.UseVarargs") // char[] para senha é intencional - segurança
    @SuppressFBWarnings(value = "EI_EXPOSE_REP2", justification = "Não copiar char[] minimiza exposição de senha em memória")
    public SmartTokenClientBuilder privateKeyPassword(final char[] password) {
        this.privateKeyPassword = password;
        return this;
    }

    /**
     * Define a estratégia de assinatura diretamente.
     *
     * <p>
     * Use este método para cenários enterprise onde a chave não está
     * em arquivo (HSM via PKCS#11, HashiCorp Vault, etc.).
     * </p>
     *
     * <p>
     * Mutuamente exclusivo com {@link #privateKeyPem(Path)}.
     * </p>
     *
     * @param signingStrategy estratégia de assinatura configurada
     * @return este builder
     */
    public SmartTokenClientBuilder signingStrategy(final SigningStrategy signingStrategy) {
        this.signingStrategy = signingStrategy;
        return this;
    }

    /**
     * Define o caminho para o arquivo PEM do certificado do cliente.
     *
     * @param certificatePem caminho absoluto
     * @return este builder
     */
    public SmartTokenClientBuilder certificatePem(final Path certificatePem) {
        this.certificatePem = certificatePem;
        return this;
    }

    /**
     * Define o certificado do servidor para validação TLS customizada.
     *
     * @param serverTrustAnchor caminho absoluto; null usa trust store da JVM
     * @return este builder
     */
    public SmartTokenClientBuilder serverTrustAnchor(final Path serverTrustAnchor) {
        this.serverTrustAnchor = serverTrustAnchor;
        return this;
    }

    /**
     * Define o protocolo TLS a utilizar.
     *
     * <p>
     * Valores válidos incluem: "TLSv1.3" (padrão), "TLSv1.2", "TLS".
     * O uso de TLSv1.3 é recomendado por segurança.
     * </p>
     *
     * @param tlsProtocol protocolo TLS (padrão: TLSv1.3)
     * @return este builder
     */
    public SmartTokenClientBuilder tlsProtocol(final String tlsProtocol) {
        this.tlsProtocol = tlsProtocol;
        return this;
    }

    /**
     * Define um {@link SSLContext} customizado, substituindo o comportamento
     * padrão de {@link #serverTrustAnchor(Path)}.
     *
     * <p>
     * Visibilidade package-private — destinado exclusivamente para testes de
     * integração que necessitam de trust-all com certificados auto-assinados.
     * </p>
     *
     * @param sslContext contexto SSL a ser utilizado
     * @return este builder
     */
    SmartTokenClientBuilder sslContext(final SSLContext sslContext) {
        this.customSslContext = sslContext;
        return this;
    }

    /**
     * Define o timeout de conexão TCP.
     *
     * @param connectTimeout duração positiva
     * @return este builder
     */
    public SmartTokenClientBuilder connectTimeout(final Duration connectTimeout) {
        this.faultToleranceConfig = new FaultToleranceConfig(
            connectTimeout,
            faultToleranceConfig.getRequestTimeout(),
            faultToleranceConfig.getAssertionTtlSeconds(),
            faultToleranceConfig.getMaxRetries()
        );
        return this;
    }

    /**
     * Define o timeout máximo da requisição HTTP.
     *
     * @param requestTimeout duração positiva
     * @return este builder
     */
    public SmartTokenClientBuilder requestTimeout(final Duration requestTimeout) {
        this.faultToleranceConfig = new FaultToleranceConfig(
            faultToleranceConfig.getConnectTimeout(),
            requestTimeout,
            faultToleranceConfig.getAssertionTtlSeconds(),
            faultToleranceConfig.getMaxRetries()
        );
        return this;
    }

    /**
     * Define o TTL do client_assertion JWT em segundos.
     *
     * @param assertionTtlSeconds valor positivo
     * @return este builder
     */
    public SmartTokenClientBuilder assertionTtlSeconds(final int assertionTtlSeconds) {
        this.faultToleranceConfig = new FaultToleranceConfig(
            faultToleranceConfig.getConnectTimeout(),
            faultToleranceConfig.getRequestTimeout(),
            assertionTtlSeconds,
            faultToleranceConfig.getMaxRetries()
        );
        return this;
    }

    /**
     * Define o número máximo de tentativas em caso de falha transitória.
     *
     * <p>
     * Falhas transitórias incluem timeouts e erros de conexão.
     * O retry usa backoff exponencial (1s, 2s, 4s...).
     * </p>
     *
     * @param maxRetries número positivo (padrão: 3)
     * @return este builder
     */
    public SmartTokenClientBuilder maxRetries(final int maxRetries) {
        this.faultToleranceConfig = new FaultToleranceConfig(
            faultToleranceConfig.getConnectTimeout(),
            faultToleranceConfig.getRequestTimeout(),
            faultToleranceConfig.getAssertionTtlSeconds(),
            maxRetries
        );
        return this;
    }

    /**
     * Define se o cache de tokens está habilitado.
     *
     * @param enableTokenCache true para habilitar (padrão)
     * @return este builder
     */
    public SmartTokenClientBuilder enableTokenCache(final boolean enableTokenCache) {
        this.enableTokenCache = enableTokenCache;
        return this;
    }

    /**
     * Define a margem em segundos para renovar token antes de expirar.
     *
     * @param tokenCacheMarginSeconds margem positiva (padrão: 30s)
     * @return este builder
     */
    public SmartTokenClientBuilder tokenCacheMarginSeconds(final int tokenCacheMarginSeconds) {
        this.tokenCacheMarginSeconds = tokenCacheMarginSeconds;
        return this;
    }

    /**
     * Constrói a instância de {@link SmartTokenClient}.
     *
     * @return cliente configurado
     * @throws IOException           se os arquivos PEM não puderem ser lidos
     * @throws IllegalStateException se nem privateKeyPem nem signingStrategy forem
     *                               definidos
     */
    @SuppressWarnings({ "PMD.CyclomaticComplexity", "PMD.NPathComplexity" })
    public SmartTokenClient build() throws IOException {
        if (tokenEndpoint != null && discoveryBaseUrl != null) {
            throw new IllegalStateException("Defina tokenEndpoint OU fhirBase, não ambos");
        }
        if (tokenEndpoint == null && discoveryBaseUrl == null) {
            throw new IllegalStateException("É obrigatório definir tokenEndpoint ou fhirBase");
        }
        Objects.requireNonNull(clientId, "clientId é obrigatório");

        final SSLContext effectiveSslContext = customSslContext != null
                ? customSslContext
                : SslContextFactory.buildSslContext(serverTrustAnchor, tlsProtocol);

        String effectiveTokenEndpoint = this.tokenEndpoint;
        if (effectiveTokenEndpoint == null) {
            effectiveTokenEndpoint = discoverTokenEndpoint(
                discoveryBaseUrl,
                effectiveSslContext,
                faultToleranceConfig.getConnectTimeout(),
                faultToleranceConfig.getRequestTimeout()
            );
        }

        // Determina a estratégia de assinatura
        final SigningStrategy effectiveStrategy;
        if (signingStrategy != null) {
            if (privateKeyPem != null) {
                throw new IllegalStateException(
                        "Defina signingStrategy OU privateKeyPem, não ambos");
            }
            effectiveStrategy = signingStrategy;
        } else if (privateKeyPem != null) {
            effectiveStrategy = SigningStrategyFactory.fromPemFile(privateKeyPem, privateKeyPassword);
        } else {
            throw new IllegalStateException(
                    "É obrigatório definir signingStrategy ou privateKeyPem");
        }

        // Certificado é opcional quando usando SigningStrategy diretamente
        final X509Certificate cert = certificatePem != null
                ? SslContextFactory.validateCertificate(certificatePem)
                : null;

        return new SmartTokenClient(
                effectiveTokenEndpoint,
                clientId,
                effectiveStrategy,
                cert,
                effectiveSslContext,
                faultToleranceConfig,
                enableTokenCache,
                tokenCacheMarginSeconds);
    }

    /**
     * Descobre o token_endpoint consultando o /.well-known/smart-configuration
     * a partir de uma URL base FHIR.
     *
     * @param fhirBaseUrl    URL base do servidor FHIR
     * @param sslContext     contexto SSL a ser utilizado
     * @param connectTimeout timeout de conexão HTTP
     * @param requestTimeout timeout de requisição HTTP
     * @return a URL do token_endpoint resolvida dinamicamente
     * @throws IOException em caso de erro de rede ou falha de protocolo
     */
    public static String discoverTokenEndpoint(
            final String fhirBaseUrl,
            final SSLContext sslContext,
            final Duration connectTimeout,
            final Duration requestTimeout) throws IOException {
        final String wellKnownUrl = fhirBaseUrl.endsWith("/")
                ? fhirBaseUrl + ".well-known/smart-configuration"
                : fhirBaseUrl + "/.well-known/smart-configuration";

        try (HttpClient client = HttpClient.newBuilder()
                .sslContext(sslContext)
                .connectTimeout(connectTimeout)
                .build()) {

            final HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(wellKnownUrl))
                    .timeout(requestTimeout)
                    .GET()
                    .build();

            final HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new SmartTokenException(
                        "Falha ao obter smart-configuration (" + response.statusCode() + "): "
                                + SmartTokenClient.sanitizeErrorResponse(response.body()));
            }

            final ObjectMapper mapper = new ObjectMapper()
                    .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            final JsonNode node = mapper.readTree(response.body());

            if (!node.has("token_endpoint")) {
                throw new SmartTokenException("A resposta de smart-configuration não contém 'token_endpoint'");
            }
            return node.get("token_endpoint").asText();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Requisição para smart-configuration interrompida", e);
        }
    }
}
