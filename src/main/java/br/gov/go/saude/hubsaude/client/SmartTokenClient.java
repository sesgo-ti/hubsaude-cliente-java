/*
 * Copyright (c) 2026 SES-GO / UFG
 * Todos os direitos reservados.
 */

package br.gov.go.saude.hubsaude.client;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;

/**
 * Classe de conveniência para obtenção de access tokens SMART Backend Services.
 *
 * <p>
 * Abstrai toda a complexidade de:
 * <ul>
 * <li>Leitura da chave privada PEM</li>
 * <li>Montagem do {@code client_assertion} JWT (assinado com RS384)</li>
 * <li>Comunicação HTTP com o endpoint {@code /auth/token}</li>
 * </ul>
 *
 * <p>
 * Destinada ao uso em aplicações cliente que precisam se autenticar junto
 * ao HubSaúde utilizando o fluxo SMART Backend Services.
 * </p>
 *
 * <h2>Exemplo de uso:</h2>
 *
 * <pre>{@code
 * var tokenClient = new SmartTokenClient(
 *         "https://localhost:8443/auth/token",
 *         "my-backend-app",
 *         Path.of("client-key.pem"),
 *         Path.of("client-cert.pem"));
 *
 * String accessToken = tokenClient.obtainToken("system/Patient.rs");
 * }</pre>
 *
 * <h2>Uso avançado com Builder:</h2>
 * <pre>{@code
 * var tokenClient = SmartTokenClient.builder()
 *         .tokenEndpoint("https://localhost:8443/auth/token")
 *         .clientId("my-backend-app")
 *         .privateKeyPem(Path.of("client-key.pem"))
 *         .certificatePem(Path.of("client-cert.pem"))
 *         .connectTimeout(Duration.ofSeconds(10))
 *         .requestTimeout(Duration.ofSeconds(30))
 *         .assertionTtlSeconds(120)
 *         .enableTokenCache(true)
 *         .tokenCacheMarginSeconds(30)
 *         .maxRetries(3)
 *         .build();
 * }</pre>
 *
 * <h2>Recursos Enterprise:</h2>
 * <ul>
 * <li><strong>Cache de tokens:</strong> Tokens são cacheados e reutilizados até próximo
 *     de sua expiração, reduzindo carga no authorization server</li>
 * <li><strong>Retry com backoff:</strong> Falhas transitórias são tratadas com retry
 *     exponencial (1s, 2s, 4s) até o limite configurado</li>
 * <li><strong>Thread-safe:</strong> Segurança para uso concorrente em aplicações multi-thread</li>
 * <li><strong>Logs sanitizados:</strong> Tokens nunca são expostos em logs</li>
 * </ul>
 *
 * <h2>Integração com Infraestrutura Enterprise</h2>
 *
 * <p>
 * Esta classe implementa resiliência básica (retry com backoff) internamente. Para cenários
 * de produção com requisitos avançados de observabilidade e tolerância a falhas, recomenda-se
 * integrar com frameworks especializados <strong>na camada de orquestração</strong>, não
 * diretamente nesta classe. Isso mantém a separação de responsabilidades e permite configuração
 * centralizada.
 * </p>
 *
 * <h3>Circuit Breaker (Resilience4j)</h3>
 *
 * <p>
 * Para proteger o sistema contra falhas em cascata quando o authorization server estiver
 * degradado, decore as chamadas ao {@link #obtainToken(String)} com um Circuit Breaker:
 * </p>
 *
 * <pre>{@code
 * // Configuração do Circuit Breaker
 * CircuitBreakerConfig config = CircuitBreakerConfig.custom()
 *     .failureRateThreshold(50)
 *     .waitDurationInOpenState(Duration.ofSeconds(30))
 *     .slidingWindowSize(10)
 *     .permittedNumberOfCallsInHalfOpenState(3)
 *     .build();
 *
 * CircuitBreaker circuitBreaker = CircuitBreaker.of("smartToken", config);
 *
 * // Uso decorado
 * Supplier<String> decoratedSupplier = CircuitBreaker
 *     .decorateSupplier(circuitBreaker, () -> {
 *         try {
 *             return tokenClient.obtainToken(scope);
 *         } catch (Exception e) {
 *             throw new RuntimeException(e);
 *         }
 *     });
 *
 * String token = Try.ofSupplier(decoratedSupplier)
 *     .recover(CallNotPermittedException.class, e -> handleCircuitOpen())
 *     .get();
 * }</pre>
 *
 * <h3>Métricas (Micrometer)</h3>
 *
 * <p>
 * Para monitoramento em tempo real da obtenção de tokens, instrumente as chamadas com
 * Micrometer. Métricas recomendadas:
 * </p>
 *
 * <ul>
 * <li>{@code smart.token.requests} — contador de requisições (tags: status, scope)</li>
 * <li>{@code smart.token.latency} — histograma de latência</li>
 * <li>{@code smart.token.cache.hits} — taxa de acerto do cache</li>
 * <li>{@code smart.token.retries} — contador de retries</li>
 * </ul>
 *
 * <pre>{@code
 * // Wrapper com métricas
 * public class InstrumentedTokenClient {
 *     private final SmartTokenClient delegate;
 *     private final MeterRegistry registry;
 *     private final Timer tokenTimer;
 *     private final Counter cacheHits;
 *     private final Counter cacheMisses;
 *
 *     public String obtainToken(String scope) throws IOException, InterruptedException {
 *         return tokenTimer.record(() -> {
 *             try {
 *                 return delegate.obtainToken(scope);
 *             } catch (Exception e) {
 *                 registry.counter("smart.token.errors", "type", e.getClass().getSimpleName()).increment();
 *                 throw e;
 *             }
 *         });
 *     }
 * }
 * }</pre>
 *
 * <h3>Distributed Tracing (OpenTelemetry)</h3>
 *
 * <p>
 * Para rastreamento de requisições distribuídas, propague o contexto de trace nas chamadas
 * HTTP. O {@link SmartTokenClient} utiliza {@link java.net.http.HttpClient} internamente,
 * que pode ser instrumentado via OpenTelemetry Java Agent ou manualmente:
 * </p>
 *
 * <pre>{@code
 * // Com OpenTelemetry Java Agent (recomendado)
 * // Adicione o agent na JVM: -javaagent:opentelemetry-javaagent.jar
 * // O HttpClient será instrumentado automaticamente
 *
 * // Instrumentação manual (se necessário)
 * Tracer tracer = GlobalOpenTelemetry.getTracer("hubsaude-client");
 *
 * public String obtainTokenWithTracing(String scope) throws Exception {
 *     Span span = tracer.spanBuilder("SmartTokenClient.obtainToken")
 *         .setSpanKind(SpanKind.CLIENT)
 *         .setAttribute("smart.client_id", clientId)
 *         .setAttribute("smart.scope", scope)
 *         .startSpan();
 *
 *     try (Scope ignored = span.makeCurrent()) {
 *         String token = tokenClient.obtainToken(scope);
 *         span.setStatus(StatusCode.OK);
 *         return token;
 *     } catch (Exception e) {
 *         span.setStatus(StatusCode.ERROR, e.getMessage());
 *         span.recordException(e);
 *         throw e;
 *     } finally {
 *         span.end();
 *     }
 * }
 * }</pre>
 *
 * <h3>Arquitetura Recomendada</h3>
 *
 * <p>
 * Para aplicações Spring Boot, encapsule o {@link SmartTokenClient} em um {@code @Service}
 * que centraliza as integrações enterprise:
 * </p>
 *
 * <pre>{@code
 * @Service
 * public class TokenService {
 *     private final SmartTokenClient tokenClient;
 *     private final CircuitBreaker circuitBreaker;
 *     private final MeterRegistry meterRegistry;
 *
 *     @Timed("smart.token.obtain")
 *     public String getToken(String scope) {
 *         return circuitBreaker.executeSupplier(() -> {
 *             try {
 *                 return tokenClient.obtainToken(scope);
 *             } catch (Exception e) {
 *                 throw new TokenServiceException("Falha ao obter token", e);
 *             }
 *         });
 *     }
 * }
 * }</pre>
 *
 * @see <a href="https://resilience4j.readme.io/docs/circuitbreaker">Resilience4j Circuit Breaker</a>
 * @see <a href="https://micrometer.io/docs">Micrometer Documentation</a>
 * @see <a href="https://opentelemetry.io/docs/instrumentation/java/">OpenTelemetry Java</a>
 */
// Suppress: classe responsável por integração completa SMART Backend Services
@SuppressWarnings("PMD.CouplingBetweenObjects")
public final class SmartTokenClient {

    private static final Logger LOG = LoggerFactory.getLogger(SmartTokenClient.class);

    private static final String GRANT_TYPE = "client_credentials";
    private static final String ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    /** Delay base para retry exponencial em milissegundos. */
    private static final long RETRY_BASE_DELAY_MS = 1000L;

    /** ObjectMapper compartilhado (thread-safe). */
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    /** Código HTTP: Rate Limit Exceeded. */
    private static final int HTTP_TOO_MANY_REQUESTS = 429;

    /** Código HTTP: OK. */
    private static final int HTTP_OK = 200;

    /** Tamanho inicial do StringBuilder para form body. */
    private static final int FORM_BODY_INITIAL_CAPACITY = 128;

    /** Limite máximo para sanitização de respostas de erro. */
    private static final int MAX_ERROR_RESPONSE_LENGTH = 500;

    /** TTL padrão do client_assertion em segundos. */
    public static final int DEFAULT_ASSERTION_TTL_SECONDS = 60;

    /** Timeout padrão de conexão. */
    public static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(10);

    /** Timeout padrão de requisição. */
    public static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(30);

    /** Número máximo padrão de tentativas em caso de falha transitória. */
    public static final int DEFAULT_MAX_RETRIES = 3;

    /** Margem padrão em segundos para renovar token antes da expiração. */
    public static final int DEFAULT_TOKEN_CACHE_MARGIN_SECONDS = 30;

    /** Protocolo TLS padrão. */
    public static final String DEFAULT_TLS_PROTOCOL = "TLSv1.3";

    /** Header JWT para RS384. */
    private static final String JWT_HEADER_RS384 = "{\"alg\":\"RS384\",\"typ\":\"JWT\"}";

    /** Encoder Base64 URL-safe sem padding. */
    private static final Base64.Encoder BASE64_URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    private final String tokenEndpoint;
    private final String clientId;
    private final SigningStrategy signingStrategy;
    private final HttpClient httpClient;
    private final int assertionTtlSeconds;
    private final Duration requestTimeout;
    private final boolean enableTokenCache;
    private final int tokenCacheMarginSeconds;
    private final int maxRetries;

    /** Cache de tokens por scope. */
    private final Map<String, CachedToken> tokenCache = new ConcurrentHashMap<>();

    /** Lock para evitar múltiplas renovações simultâneas do mesmo scope. */
    private final Map<String, ReentrantLock> scopeLocks = new ConcurrentHashMap<>();

    /**
     * Cria o cliente carregando chave privada e certificado de arquivos PEM.
     *
     * @param tokenEndpoint  URL do endpoint /auth/token do servidor de autorização
     * @param clientId       identificador do cliente (fornecido pelo Ganesha no credenciamento)
     * @param privateKeyPem  caminho para o arquivo PEM da chave privada
     * @param certificatePem caminho para o arquivo PEM do certificado (não usado na
     *                       assinatura,
     *                       mas validado para garantir consistência do par)
     */
    public SmartTokenClient(
            final String tokenEndpoint,
            final String clientId,
            final Path privateKeyPem,
            final Path certificatePem) throws IOException {
        this(tokenEndpoint,
                clientId,
                SigningStrategyFactory.fromPemFile(privateKeyPem),
                validateCertificate(certificatePem),
                buildSslContext(null, DEFAULT_TLS_PROTOCOL),
                DEFAULT_CONNECT_TIMEOUT,
                DEFAULT_REQUEST_TIMEOUT,
                DEFAULT_ASSERTION_TTL_SECONDS,
                true,
                DEFAULT_TOKEN_CACHE_MARGIN_SECONDS,
                DEFAULT_MAX_RETRIES);
    }

    /**
     * Versão avançada que aceita um certificado público do servidor para ser
     * utilizado como trust anchor, evitando o uso de SSL permissivo quando o
     * chamador possui a cadeia correta.
     *
     * @param tokenEndpoint        URL do endpoint /auth/token do servidor de autorização
     * @param clientId             identificador do cliente (fornecido pelo Ganesha no credenciamento)
     * @param privateKeyPem        caminho para o arquivo PEM da chave privada
     * @param certificatePem       caminho para o arquivo PEM do certificado do
     *                             cliente
     * @param serverTrustAnchor certificado X.509 confiável do servidor; quando
     *                             {@code null}, usa-se SSL permissivo para testes
     */
    public SmartTokenClient(
            final String tokenEndpoint,
            final String clientId,
            final Path privateKeyPem,
            final Path certificatePem,
            final Path serverTrustAnchor) throws IOException {
        this(tokenEndpoint,
                clientId,
                SigningStrategyFactory.fromPemFile(privateKeyPem),
                validateCertificate(certificatePem),
                buildSslContext(serverTrustAnchor, DEFAULT_TLS_PROTOCOL),
                DEFAULT_CONNECT_TIMEOUT,
                DEFAULT_REQUEST_TIMEOUT,
                DEFAULT_ASSERTION_TTL_SECONDS,
                true,
                DEFAULT_TOKEN_CACHE_MARGIN_SECONDS,
                DEFAULT_MAX_RETRIES);
    }

    /**
     * Construtor de baixo nível para cenários em que os artefatos criptográficos
     * já foram carregados (ex: Vault, Secret Manager).
     *
     * @param tokenEndpoint URL do endpoint /auth/token do servidor de autorização
     * @param clientId      identificador do cliente (fornecido pelo Ganesha no credenciamento)
     * @param privateKey    chave privada previamente carregada
     * @param certificate   certificado X.509 correspondente à chave
     * @param sslContext    contexto SSL a ser utilizado pelo {@link HttpClient}
     */
    public SmartTokenClient(
            final String tokenEndpoint,
            final String clientId,
            final PrivateKey privateKey,
            final X509Certificate certificate,
            final SSLContext sslContext) {
        this(tokenEndpoint, clientId, privateKey, certificate, sslContext,
                DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT, DEFAULT_ASSERTION_TTL_SECONDS,
                true, DEFAULT_TOKEN_CACHE_MARGIN_SECONDS, DEFAULT_MAX_RETRIES);
    }

    /**
     * Construtor completo com todas as configurações disponíveis (retrocompatível).
     *
     * @param tokenEndpoint           URL do endpoint /auth/token do servidor de autorização
     * @param clientId                identificador do cliente (fornecido pelo Ganesha no credenciamento)
     * @param privateKey              chave privada previamente carregada
     * @param certificate             certificado X.509 correspondente à chave
     * @param sslContext              contexto SSL a ser utilizado pelo {@link HttpClient}
     * @param connectTimeout          timeout de conexão
     * @param requestTimeout          timeout de requisição HTTP
     * @param assertionTtlSeconds     TTL do client_assertion em segundos
     * @param enableTokenCache        habilita cache de tokens
     * @param tokenCacheMarginSeconds margem para renovar token antes de expirar
     * @param maxRetries              número máximo de tentativas em falhas transitórias
     */
    @SuppressWarnings({"PMD.ExcessiveParameterList", "checkstyle:ParameterNumber"}) // Builder é a API recomendada
    public SmartTokenClient(
            final String tokenEndpoint,
            final String clientId,
            final PrivateKey privateKey,
            final X509Certificate certificate,
            final SSLContext sslContext,
            final Duration connectTimeout,
            final Duration requestTimeout,
            final int assertionTtlSeconds,
            final boolean enableTokenCache,
            final int tokenCacheMarginSeconds,
            final int maxRetries) {
        this(tokenEndpoint, clientId,
                createValidatedSigningStrategy(privateKey, certificate),
                certificate, sslContext,
                connectTimeout, requestTimeout, assertionTtlSeconds, enableTokenCache,
                tokenCacheMarginSeconds, maxRetries);
    }

    /**
     * Cria SigningStrategy validando a consistência entre chave e certificado.
     *
     * @param privateKey  chave privada
     * @param certificate certificado X.509
     * @return SigningStrategy validado
     * @throws SmartTokenException se a chave não corresponder ao certificado
     */
    private static SigningStrategy createValidatedSigningStrategy(
            final PrivateKey privateKey,
            final X509Certificate certificate) {
        verifyKeyPairConsistency(privateKey, certificate);
        return SigningStrategyFactory.fromPrivateKey(privateKey);
    }

    /**
     * Construtor principal que aceita {@link SigningStrategy}.
     *
     * <p>
     * Este é o construtor recomendado para cenários enterprise onde a fonte
     * do material criptográfico pode variar (arquivo, HSM, Vault, etc.).
     * </p>
     *
     * @param tokenEndpoint           URL do endpoint /auth/token do servidor de autorização
     * @param clientId                identificador do cliente (fornecido pelo Ganesha no credenciamento)
     * @param signingStrategy         estratégia de assinatura configurada
     * @param certificate             certificado X.509 para validação (pode ser null se não houver validação)
     * @param sslContext              contexto SSL a ser utilizado pelo {@link HttpClient}
     * @param connectTimeout          timeout de conexão
     * @param requestTimeout          timeout de requisição HTTP
     * @param assertionTtlSeconds     TTL do client_assertion em segundos
     * @param enableTokenCache        habilita cache de tokens
     * @param tokenCacheMarginSeconds margem para renovar token antes de expirar
     * @param maxRetries              número máximo de tentativas em falhas transitórias
     */
    @SuppressWarnings({"PMD.ExcessiveParameterList", "checkstyle:ParameterNumber"}) // Builder é a API recomendada
    public SmartTokenClient(
            final String tokenEndpoint,
            final String clientId,
            final SigningStrategy signingStrategy,
            final X509Certificate certificate,
            final SSLContext sslContext,
            final Duration connectTimeout,
            final Duration requestTimeout,
            final int assertionTtlSeconds,
            final boolean enableTokenCache,
            final int tokenCacheMarginSeconds,
            final int maxRetries) {
        this.tokenEndpoint = Objects.requireNonNull(tokenEndpoint, "tokenEndpoint");
        this.clientId = Objects.requireNonNull(clientId, "clientId");
        this.signingStrategy = Objects.requireNonNull(signingStrategy, "signingStrategy");
        // certificate pode ser null para estratégias onde verificação não é aplicável (ex: Vault)
        final SSLContext context = Objects.requireNonNull(sslContext, "sslContext");
        final Duration connTimeout = Objects.requireNonNull(connectTimeout, "connectTimeout");
        this.requestTimeout = Objects.requireNonNull(requestTimeout, "requestTimeout");
        this.assertionTtlSeconds = assertionTtlSeconds > 0 ? assertionTtlSeconds : DEFAULT_ASSERTION_TTL_SECONDS;
        this.enableTokenCache = enableTokenCache;
        this.tokenCacheMarginSeconds = tokenCacheMarginSeconds > 0
                ? tokenCacheMarginSeconds : DEFAULT_TOKEN_CACHE_MARGIN_SECONDS;
        this.maxRetries = maxRetries > 0 ? maxRetries : DEFAULT_MAX_RETRIES;

        this.httpClient = HttpClient.newBuilder()
                .sslContext(context)
                .connectTimeout(connTimeout)
                .build();

        LOG.debug("SmartTokenClient inicializado para clientId={} endpoint={} cache={} maxRetries={}",
                clientId, tokenEndpoint, enableTokenCache, this.maxRetries);
    }

    /**
     * Cria um novo {@link Builder} para configuração fluente do cliente.
     *
     * @return nova instância do builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Obtém um access token para os scopes informados.
     *
     * <p>
     * Se o cache estiver habilitado, tokens válidos são reutilizados.
     * A renovação ocorre automaticamente quando o token está próximo
     * de expirar (margem configurável).
     * </p>
     *
     * <p>
     * Em caso de falhas transitórias (timeout, erro de rede), o método
     * realiza retry com backoff exponencial até o limite configurado.
     * </p>
     *
     * @param scope scopes separados por espaço (ex: {@code "system/Patient.rs"})
     * @return access token JWT emitido pelo servidor de autorização
     * @throws IOException          em caso de erro de I/O na comunicação
     * @throws InterruptedException se a thread for interrompida durante a requisição
     * @throws SmartTokenException  se o servidor retornar erro ou resposta inválida
     */
    public String obtainToken(final String scope) throws IOException, InterruptedException {
        final String normalizedScope = scope == null ? "" : scope.trim();

        if (enableTokenCache) {
            final CachedToken cached = tokenCache.get(normalizedScope);
            if (cached != null && cached.isValid(tokenCacheMarginSeconds)) {
                LOG.debug("Retornando token em cache para clientId={} scope={}", clientId, normalizedScope);
                return cached.accessToken();
            }
        }

        // Usa lock por scope para evitar múltiplas requisições simultâneas
        final ReentrantLock lock = scopeLocks.computeIfAbsent(normalizedScope, k -> new ReentrantLock());
        lock.lock();
        try {
            // Double-check após adquirir o lock
            if (enableTokenCache) {
                final CachedToken cached = tokenCache.get(normalizedScope);
                if (cached != null && cached.isValid(tokenCacheMarginSeconds)) {
                    LOG.debug("Token renovado por outra thread para clientId={} scope={}", clientId, normalizedScope);
                    return cached.accessToken();
                }
            }

            return obtainTokenWithRetry(normalizedScope);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Invalida o cache de tokens, forçando nova obtenção na próxima chamada.
     *
     * <p>
     * Útil quando o token foi revogado externamente ou após receber
     * erro 401 em uma chamada subsequente.
     * </p>
     */
    public void invalidateCache() {
        tokenCache.clear();
        LOG.info("Cache de tokens invalidado para clientId={}", clientId);
    }

    /**
     * Invalida o cache para um scope específico.
     *
     * @param scope scope cujo token deve ser invalidado
     */
    public void invalidateCache(final String scope) {
        final String normalizedScope = scope == null ? "" : scope.trim();
        tokenCache.remove(normalizedScope);
        LOG.debug("Cache invalidado para clientId={} scope={}", clientId, normalizedScope);
    }

    private String obtainTokenWithRetry(final String scope) throws IOException, InterruptedException {
        LOG.debug("Iniciando obtenção de token para clientId={} scope={}", clientId, scope);

        IOException lastException = null;
        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                return doObtainToken(scope);
            } catch (HttpTimeoutException | java.net.ConnectException ex) {
                lastException = ex;
                if (attempt < maxRetries) {
                    final long delayMs = RETRY_BASE_DELAY_MS * (1L << (attempt - 1));
                    LOG.warn("Tentativa {}/{} falhou para clientId={}: {}. Retry em {}ms",
                            attempt, maxRetries, clientId, ex.getMessage(), delayMs);
                    Thread.sleep(delayMs);
                } else {
                    LOG.error("Todas as {} tentativas falharam para clientId={}", maxRetries, clientId);
                }
            }
        }
        throw new SmartTokenException(
                "Falha após " + maxRetries + " tentativas: " + lastException.getMessage(), lastException);
    }

    private String doObtainToken(final String scope) throws IOException, InterruptedException {
        final String assertion = buildClientAssertion();
        final String body = buildFormBody(assertion, scope);

        final HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(tokenEndpoint))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .timeout(requestTimeout)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        LOG.trace("Enviando requisição POST para {}", tokenEndpoint);
        final HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        final int statusCode = response.statusCode();
        if (statusCode == HTTP_TOO_MANY_REQUESTS) {
            LOG.warn("Rate limit atingido (HTTP 429) para clientId={}", clientId);
            throw new SmartTokenException("Rate limit atingido (HTTP 429). Tente novamente mais tarde.");
        }

        if (statusCode != HTTP_OK) {
            LOG.error("Falha ao obter token: HTTP {} para clientId={}", statusCode, clientId);
            throw new SmartTokenException(
                    "Falha ao obter token: HTTP " + statusCode + " — " + sanitizeErrorResponse(response.body()));
        }

        final TokenResponse tokenResponse = parseTokenResponse(response.body());
        final String accessToken = tokenResponse.accessToken();

        if (enableTokenCache) {
            final Instant expiresAt = Instant.now().plusSeconds(tokenResponse.expiresIn());
            tokenCache.put(scope, new CachedToken(accessToken, expiresAt));
            LOG.debug("Token cacheado para clientId={} scope={} expiresIn={}s",
                    clientId, scope, tokenResponse.expiresIn());
        }

        LOG.info("Token obtido com sucesso para clientId={}", clientId);
        return accessToken;
    }

    /**
     * Constrói o JWT client_assertion assinado com RS384.
     *
     * @return JWT compacto pronto para uso no campo client_assertion
     */
    String buildClientAssertion() {
        final Instant now = Instant.now();
        final long iat = now.getEpochSecond();
        final long exp = now.plusSeconds(assertionTtlSeconds).getEpochSecond();
        final String jti = UUID.randomUUID().toString();
        LOG.trace("Construindo client_assertion jti={} ttl={}s", jti, assertionTtlSeconds);

        // Constrói o payload JSON manualmente para independência de bibliotecas JWT
        final String payload = String.format(
                "{\"iss\":\"%s\",\"sub\":\"%s\",\"aud\":\"%s\",\"iat\":%d,\"exp\":%d,\"jti\":\"%s\"}",
                escapeJson(clientId),
                escapeJson(clientId),
                escapeJson(tokenEndpoint),
                iat,
                exp,
                jti);

        // Codifica header e payload em Base64Url
        final String headerB64 = BASE64_URL_ENCODER.encodeToString(
                JWT_HEADER_RS384.getBytes(StandardCharsets.UTF_8));
        final String payloadB64 = BASE64_URL_ENCODER.encodeToString(
                payload.getBytes(StandardCharsets.UTF_8));

        // Dados a serem assinados: header.payload
        final String dataToSign = headerB64 + "." + payloadB64;

        // Assina usando a estratégia configurada (pode ser HSM, Vault, etc.)
        final byte[] signature = signingStrategy.sign(dataToSign.getBytes(StandardCharsets.UTF_8));
        final String signatureB64 = BASE64_URL_ENCODER.encodeToString(signature);

        return dataToSign + "." + signatureB64;
    }

    /**
     * Escapa caracteres especiais para JSON.
     *
     * @param value valor a escapar
     * @return valor escapado
     */
    private static String escapeJson(final String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    /**
     * Monta o payload {@code application/x-www-form-urlencoded} exigido pelo
     * endpoint {@code /auth/token}, incluindo {@code client_assertion} e scopes.
     *
     * @param assertion JWT assinado que comprova a identidade do cliente
     * @param scope     escopos solicitados, separados por espaço (opcional)
     * @return string pronta para envio no corpo da requisição HTTP
     */
    public static String buildFormBody(final String assertion, final String scope) {
        final StringBuilder sb = new StringBuilder(FORM_BODY_INITIAL_CAPACITY)
                .append("grant_type=").append(encode(GRANT_TYPE))
                .append("&client_assertion_type=").append(encode(ASSERTION_TYPE))
                .append("&client_assertion=").append(encode(assertion));
        if (scope != null && !scope.isBlank()) {
            sb.append("&scope=").append(encode(scope));
        }
        return sb.toString();
    }

    /**
     * Encapsula {@link URLEncoder} para garantir codificação UTF-8 consistente nos
     * campos do formulário.
     *
     * @param value texto a ser percent-encoded
     * @return valor codificado no formato {@code application/x-www-form-urlencoded}
     */
    public static String encode(final String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /**
     * Faz o parse da resposta JSON retornada pelo servidor e extrai o campo
     * {@code access_token}, validando sua presença.
     *
     * @param jsonBody corpo JSON completo retornado pelo endpoint /auth/token
     * @return access token extraído
     * @throws IOException caso o JSON seja inválido ou não contenha o atributo
     */
    public static String extractAccessToken(final String jsonBody) throws IOException {
        return parseTokenResponse(jsonBody).accessToken();
    }

    /**
     * Faz o parse completo da resposta do token endpoint.
     *
     * @param jsonBody corpo JSON da resposta
     * @return objeto com access_token e expires_in
     * @throws IOException em caso de erro de parse
     */
    static TokenResponse parseTokenResponse(final String jsonBody) throws IOException {
        final JsonNode node = OBJECT_MAPPER.readTree(jsonBody);
        if (!node.has("access_token")) {
            throw new SmartTokenException("Resposta não contém 'access_token'");
        }
        final String accessToken = node.get("access_token").asText();
        final int expiresIn = node.has("expires_in") ? node.get("expires_in").asInt() : 3600;
        return new TokenResponse(accessToken, expiresIn);
    }

    /**
     * Sanitiza a resposta de erro para evitar vazamento de tokens em logs.
     *
     * @param responseBody corpo da resposta HTTP
     * @return resposta sanitizada
     */
    private static String sanitizeErrorResponse(final String responseBody) {
        if (responseBody == null || responseBody.length() > MAX_ERROR_RESPONSE_LENGTH) {
            return responseBody == null ? "<empty>"
                    : responseBody.substring(0, MAX_ERROR_RESPONSE_LENGTH) + "...";
        }
        // Remove possíveis tokens do erro
        return responseBody.replaceAll("(access_token|token)[^&\"]*", "$1=[REDACTED]");
    }

    /**
     * Converte um arquivo PEM (PKCS#1 ou PKCS#8) em {@link PrivateKey}, aceitando
     * chaves RSA geradas para o HubSaúde.
     *
     * @param path caminho absoluto para o arquivo PEM
     * @return chave privada pronta para assinar o {@code client_assertion}
     * @throws IOException caso o arquivo não possa ser lido ou decodificado
     */
    public static PrivateKey loadPrivateKey(final Path path) throws IOException {
        final String pem = Files.readString(path, StandardCharsets.UTF_8);
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            final Object obj = parser.readObject();
            if (obj instanceof PEMKeyPair pemKeyPair) {
                return new JcaPEMKeyConverter().getKeyPair(pemKeyPair).getPrivate();
            } else if (obj instanceof PrivateKeyInfo pki) {
                return new JcaPEMKeyConverter().getPrivateKey(pki);
            }
            throw new SmartTokenException("Arquivo PEM não contém chave privada válida: " + path);
        }
    }

    /**
     * Realiza um sanity check no certificado PEM associado ao cliente, garantindo
     * que seja um X.509 válido antes de iniciar o fluxo de autenticação.
     *
     * @param path caminho absoluto para o certificado PEM
     * @return certificado X.509 decodificado
     * @throws IOException quando o arquivo não pode ser lido
     * @throws SmartTokenException quando o conteúdo não representa um
     *                             certificado X.509 válido
     */
    public static X509Certificate validateCertificate(final Path path) throws IOException {
        final String pem = Files.readString(path, StandardCharsets.UTF_8);
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            final Object obj = parser.readObject();
            if (obj instanceof X509CertificateHolder holder) {
                final X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
                if (cert == null) {
                    throw new SmartTokenException("Certificado inválido: " + path);
                }
                return cert;
            }
            throw new SmartTokenException("Arquivo PEM não contém certificado X.509: " + path);
        } catch (CertificateException ex) {
            throw new SmartTokenException("Falha ao converter certificado: " + ex.getMessage(), ex);
        }
    }

    /**
     * Constrói um {@link SSLContext} configurado com o certificado do servidor.
     *
     * @param serverTrustAnchor certificado do servidor; se null, usa trust-all
     * @param tlsProtocol          protocolo TLS (ex: "TLSv1.3", "TLSv1.2")
     * @return contexto SSL configurado
     * @throws SmartTokenException se o protocolo for inválido ou houver erro de configuração
     */
    public static SSLContext buildSslContext(final Path serverTrustAnchor, final String tlsProtocol) {
        if (serverTrustAnchor == null) {
            return buildTrustAllSslContext(tlsProtocol);
        }
        try {
            final X509Certificate trustedCert = validateCertificate(serverTrustAnchor);
            final KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);
            trustStore.setCertificateEntry("trusted-server", trustedCert);

            final TrustManagerFactory tmf = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            final SSLContext ctx = SSLContext.getInstance(tlsProtocol);
            ctx.init(null, tmf.getTrustManagers(), new SecureRandom());
            return ctx;
        } catch (SmartTokenException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new SmartTokenException("Falha ao construir SSLContext customizado: " + ex.getMessage(), ex);
        }
    }

    /**
     * Validação fail-fast de consistência entre chave privada e certificado.
     *
     * <p>
     * Este método realiza uma assinatura de teste com a chave privada e verifica
     * o resultado usando a chave pública extraída do certificado. Se a verificação
     * falhar, significa que os arquivos não formam um par criptográfico válido.
     * </p>
     *
     * <h3>Propósito</h3>
     * <p>
     * Detectar <strong>erros de configuração na inicialização</strong>, antes de
     * qualquer tentativa de obter tokens. Sem esta validação, o erro só seria
     * descoberto quando o authorization server rejeitasse o JWT — uma falha mais
     * difícil de diagnosticar.
     * </p>
     *
     * <h3>Quando é executado</h3>
     * <p>
     * Automaticamente durante a construção do {@link SmartTokenClient} quando
     * são fornecidos objetos {@link PrivateKey} e {@link X509Certificate} diretamente
     * (não via arquivo PEM ou {@link SigningStrategy}).
     * </p>
     *
     * <h3>Cenários detectados</h3>
     * <ul>
     *   <li>Arquivos trocados (certificado de um sistema, chave de outro)</li>
     *   <li>Chave privada corrompida ou truncada</li>
     *   <li>Certificado regenerado sem atualizar a chave</li>
     * </ul>
     *
     * @param privateKey  chave privada a validar
     * @param certificate certificado X.509 contendo a chave pública correspondente
     * @throws SmartTokenException se a assinatura de teste falhar, indicando
     *         que chave e certificado não formam um par válido
     */
    public static void verifyKeyPairConsistency(
            final PrivateKey privateKey,
            final X509Certificate certificate) {
        try {
            final byte[] challenge = "key-pair-consistency-check".getBytes(StandardCharsets.UTF_8);
            final Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(privateKey);
            signer.update(challenge);
            final byte[] signature = signer.sign();

            final Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(certificate.getPublicKey());
            verifier.update(challenge);

            if (!verifier.verify(signature)) {
                throw new SmartTokenException(
                        "Chave privada não corresponde ao certificado: assinatura inválida");
            }
            LOG.trace("Verificação de consistência key-cert concluída com sucesso");
        } catch (SmartTokenException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new SmartTokenException(
                    "Falha ao verificar consistência entre chave privada e certificado: " + ex.getMessage(), ex);
        }
    }

    /**
     * Cria um {@link javax.net.ssl.SSLContext} que confia em todos os certificados.
     *
     * <p>
     * <strong>⚠️ ATENÇÃO: USO EXCLUSIVO PARA TESTES E DESENVOLVIMENTO LOCAL!</strong>
     * </p>
     *
     * <p>
     * Este método cria um contexto SSL que <strong>DESABILITA COMPLETAMENTE</strong>
     * a validação de certificados TLS, tornando a conexão vulnerável a:
     * </p>
     * <ul>
     * <li>Ataques Man-in-the-Middle (MITM)</li>
     * <li>Interceptação de tráfego</li>
     * <li>Roubo de credenciais e tokens</li>
     * <li>Violação de dados sensíveis de saúde</li>
     * </ul>
     *
     * <p>
     * <strong>NUNCA</strong> utilize este método em:
     * </p>
     * <ul>
     * <li>Ambiente de produção</li>
     * <li>Ambiente de homologação</li>
     * <li>Qualquer ambiente que processe dados reais de pacientes</li>
     * </ul>
     *
     * <p>
     * Para ambientes de produção, utilize SEMPRE um {@link SSLContext} configurado
     * com a cadeia de certificados correta do servidor de autorização.
     * </p>
     *
     * @param tlsProtocol protocolo TLS (ex: "TLSv1.3", "TLSv1.2")
     * @return contexto SSL que aceita qualquer certificado (⚠️ INSEGURO)
     * @see #buildSslContext(Path, String) para configuração segura com certificado específico
     */
    public static SSLContext buildTrustAllSslContext(final String tlsProtocol) {
        LOG.warn("⚠️ Criando SSLContext trust-all ({}) - USO EXCLUSIVO PARA TESTES!", tlsProtocol);
        try {
            final TrustManager[] trustAll = {
                new X509TrustManager() {
                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    @Override
                    public void checkClientTrusted(
                            final X509Certificate[] c, final String a) {
                    }

                    @Override
                    public void checkServerTrusted(
                            final X509Certificate[] c, final String a) {
                    }
                }
            };
            final SSLContext ctx = SSLContext.getInstance(tlsProtocol);
            ctx.init(null, trustAll, new SecureRandom());
            return ctx;
        } catch (Exception ex) {
            throw new SmartTokenException("Falha ao criar SSLContext trust-all com protocolo '" + tlsProtocol + "'", ex);
        }
    }

    /**
     * Builder fluente para construção de instâncias de {@link SmartTokenClient}.
     *
     * <p>
     * Permite configurar timeouts, TTL do assertion e demais parâmetros
     * de forma legível e segura.
     * </p>
     *
     * <h2>Exemplo com arquivo PEM</h2>
     * <pre>{@code
     * var client = SmartTokenClient.builder()
     *     .tokenEndpoint("https://auth.example.com/token")
     *     .clientId("my-app")
     *     .privateKeyPem(Path.of("key.pem"))
     *     .certificatePem(Path.of("cert.pem"))
     *     .build();
     * }</pre>
     *
     * <h2>Exemplo com SigningStrategy (HSM, Vault, etc.)</h2>
     * <pre>{@code
     * var client = SmartTokenClient.builder()
     *     .tokenEndpoint("https://auth.example.com/token")
     *     .clientId("my-app")
     *     .signingStrategy(SigningStrategyFactory.fromPkcs11(provider, "alias", pin))
     *     .certificatePem(Path.of("cert.pem"))
     *     .build();
     * }</pre>
     */
    @SuppressWarnings("checkstyle:HiddenField") // Padrão Builder usa nomes iguais
    public static final class Builder {
        private String tokenEndpoint;
        private String clientId;
        private Path privateKeyPem;
        private char[] privateKeyPassword;
        private SigningStrategy signingStrategy;
        private Path certificatePem;
        private Path serverTrustAnchor;
        private String tlsProtocol = DEFAULT_TLS_PROTOCOL;
        private Duration connectTimeout = DEFAULT_CONNECT_TIMEOUT;
        private Duration requestTimeout = DEFAULT_REQUEST_TIMEOUT;
        private int assertionTtlSeconds = DEFAULT_ASSERTION_TTL_SECONDS;
        private boolean enableTokenCache = true;
        private int tokenCacheMarginSeconds = DEFAULT_TOKEN_CACHE_MARGIN_SECONDS;
        private int maxRetries = DEFAULT_MAX_RETRIES;

        private Builder() {
        }

        /**
         * Define a URL do endpoint de token.
         *
         * @param tokenEndpoint URL completa (ex: https://host/auth/token)
         * @return este builder
         */
        public Builder tokenEndpoint(final String tokenEndpoint) {
            this.tokenEndpoint = tokenEndpoint;
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
        public Builder clientId(final String clientId) {
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
        public Builder privateKeyPem(final Path privateKeyPem) {
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
        @SuppressFBWarnings(value = "EI_EXPOSE_REP2",
                justification = "Não copiar char[] minimiza exposição de senha em memória")
        public Builder privateKeyPassword(final char[] password) {
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
        public Builder signingStrategy(final SigningStrategy signingStrategy) {
            this.signingStrategy = signingStrategy;
            return this;
        }

        /**
         * Define o caminho para o arquivo PEM do certificado do cliente.
         *
         * @param certificatePem caminho absoluto
         * @return este builder
         */
        public Builder certificatePem(final Path certificatePem) {
            this.certificatePem = certificatePem;
            return this;
        }

        /**
         * Define o certificado do servidor para validação TLS customizada.
         *
         * @param serverTrustAnchor caminho absoluto; null usa trust-all
         * @return este builder
         */
        public Builder serverTrustAnchor(final Path serverTrustAnchor) {
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
        public Builder tlsProtocol(final String tlsProtocol) {
            this.tlsProtocol = tlsProtocol;
            return this;
        }

        /**
         * Define o timeout de conexão TCP.
         *
         * @param connectTimeout duração positiva
         * @return este builder
         */
        public Builder connectTimeout(final Duration connectTimeout) {
            this.connectTimeout = connectTimeout;
            return this;
        }

        /**
         * Define o timeout máximo da requisição HTTP.
         *
         * @param requestTimeout duração positiva
         * @return este builder
         */
        public Builder requestTimeout(final Duration requestTimeout) {
            this.requestTimeout = requestTimeout;
            return this;
        }

        /**
         * Define o TTL do client_assertion JWT em segundos.
         *
         * @param assertionTtlSeconds valor positivo
         * @return este builder
         */
        public Builder assertionTtlSeconds(final int assertionTtlSeconds) {
            this.assertionTtlSeconds = assertionTtlSeconds;
            return this;
        }

        /**
         * Habilita ou desabilita o cache de tokens.
         *
         * <p>
         * Quando habilitado (padrão), tokens são reutilizados até próximo
         * de sua expiração, reduzindo carga no authorization server.
         * </p>
         *
         * @param enableTokenCache true para habilitar (padrão)
         * @return este builder
         */
        public Builder enableTokenCache(final boolean enableTokenCache) {
            this.enableTokenCache = enableTokenCache;
            return this;
        }

        /**
         * Define a margem em segundos para renovar token antes de expirar.
         *
         * <p>
         * Exemplo: se tokenCacheMarginSeconds=30 e o token expira em 60s,
         * o cliente renovará o token quando restarem 30s para expiração.
         * </p>
         *
         * @param tokenCacheMarginSeconds margem positiva (padrão: 30s)
         * @return este builder
         */
        public Builder tokenCacheMarginSeconds(final int tokenCacheMarginSeconds) {
            this.tokenCacheMarginSeconds = tokenCacheMarginSeconds;
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
        public Builder maxRetries(final int maxRetries) {
            this.maxRetries = maxRetries;
            return this;
        }

        /**
         * Constrói a instância de {@link SmartTokenClient}.
         *
         * @return cliente configurado
         * @throws IOException se os arquivos PEM não puderem ser lidos
         * @throws IllegalStateException se nem privateKeyPem nem signingStrategy forem definidos
         */
        public SmartTokenClient build() throws IOException {
            Objects.requireNonNull(tokenEndpoint, "tokenEndpoint é obrigatório");
            Objects.requireNonNull(clientId, "clientId é obrigatório");

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
                    ? validateCertificate(certificatePem)
                    : null;

            return new SmartTokenClient(
                    tokenEndpoint,
                    clientId,
                    effectiveStrategy,
                    cert,
                    buildSslContext(serverTrustAnchor, tlsProtocol),
                    connectTimeout,
                    requestTimeout,
                    assertionTtlSeconds,
                    enableTokenCache,
                    tokenCacheMarginSeconds,
                    maxRetries);
        }
    }

    /**
     * Representa um token em cache com seu tempo de expiração.
     */
    record CachedToken(String accessToken, Instant expiresAt) {
        /**
         * Verifica se o token ainda é válido considerando a margem.
         *
         * @param marginSeconds segundos de margem antes da expiração
         * @return true se o token ainda pode ser usado
         */
        boolean isValid(final int marginSeconds) {
            return Instant.now().plusSeconds(marginSeconds).isBefore(expiresAt);
        }
    }

    /**
     * Representa a resposta do token endpoint.
     */
    record TokenResponse(String accessToken, int expiresIn) {
    }
}
