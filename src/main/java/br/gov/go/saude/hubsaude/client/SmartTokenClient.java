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

import java.io.EOFException;
import java.io.IOException;
import java.net.SocketException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

import javax.crypto.AEADBadTagException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Classe de conveniência para obtenção de access tokens
 * SMART Backend Services.
 *
 * <p>
 * Abstrai toda a complexidade de:
 * <ul>
 * <li>Leitura da chave privada PEM</li>
 * <li>Montagem do {@code client_assertion} JWT (assinado com RS256 por padrão)</li>
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
 *
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
 * <li><strong>Cache de tokens:</strong> Tokens são cacheados e reutilizados até
 * próximo
 * de sua expiração, reduzindo carga no authorization server</li>
 * <li><strong>Retry com backoff:</strong> Falhas transitórias de rede
 * (timeout de conexão ou de requisição, recusa e queda de conexão TCP)
 * são tratadas com retry exponencial (1s, 2s, 4s) até o limite
 * configurado. Respostas HTTP recebidas (qualquer status, inclusive 429
 * e 5xx) não sofrem retry automático: resultam em erro imediato e,
 * quando presente, o valor de {@code Retry-After} é incluído na mensagem
 * como diagnóstico — a decisão de aguardar e reenviar é do chamador</li>
 * <li><strong>Thread-safe:</strong> Segurança para uso concorrente em
 * aplicações multi-thread</li>
 * <li><strong>Logs sanitizados:</strong> Tokens nunca são expostos em logs</li>
 * </ul>
 *
 * <h2>Integração com Infraestrutura Enterprise</h2>
 *
 * <p>
 * Esta classe implementa resiliência básica (retry com backoff) internamente.
 * Para cenários
 * de produção com requisitos avançados de observabilidade e tolerância a
 * falhas, recomenda-se
 * integrar com frameworks especializados <strong>na camada de
 * orquestração</strong>, não
 * diretamente nesta classe. Isso mantém a separação de responsabilidades e
 * permite configuração
 * centralizada.
 * </p>
 *
 * <h3>Circuit Breaker (Resilience4j)</h3>
 *
 * <p>
 * Para proteger o sistema contra falhas em cascata quando o authorization
 * server estiver
 * degradado, decore as chamadas ao {@link #obtainToken(String)} com um Circuit
 * Breaker:
 * </p>
 *
 * <pre>{@code
 * // Configuração do Circuit Breaker
 * CircuitBreakerConfig config = CircuitBreakerConfig.custom()
 *         .failureRateThreshold(50)
 *         .waitDurationInOpenState(Duration.ofSeconds(30))
 *         .slidingWindowSize(10)
 *         .permittedNumberOfCallsInHalfOpenState(3)
 *         .build();
 *
 * CircuitBreaker circuitBreaker = CircuitBreaker.of("smartToken", config);
 *
 * // Uso decorado
 * Supplier<String> decoratedSupplier = CircuitBreaker
 *         .decorateSupplier(circuitBreaker, () -> {
 *             try {
 *                 return tokenClient.obtainToken(scope);
 *             } catch (Exception e) {
 *                 throw new RuntimeException(e);
 *             }
 *         });
 *
 * String token = Try.ofSupplier(decoratedSupplier)
 *         .recover(CallNotPermittedException.class, e -> handleCircuitOpen())
 *         .get();
 * }</pre>
 *
 * <h3>Métricas (Micrometer)</h3>
 *
 * <p>
 * Para monitoramento em tempo real da obtenção de tokens, instrumente as
 * chamadas com
 * Micrometer. Métricas recomendadas:
 * </p>
 *
 * <ul>
 * <li>{@code smart.token.requests} — contador de requisições (tags: status,
 * scope)</li>
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
 * Para rastreamento de requisições distribuídas, propague o contexto de trace
 * nas chamadas
 * HTTP. O {@link SmartTokenClient} utiliza {@link java.net.http.HttpClient}
 * internamente,
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
 *             .setSpanKind(SpanKind.CLIENT)
 *             .setAttribute("smart.client_id", clientId)
 *             .setAttribute("smart.scope", scope)
 *             .startSpan();
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
 * Para aplicações Spring Boot, encapsule o {@link SmartTokenClient} em um
 * {@code @Service}
 * que centraliza as integrações enterprise:
 * </p>
 *
 * <pre>{@code
 * {@literal @Service}
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
 * @see <a href=
 *      "https://resilience4j.readme.io/docs/circuitbreaker">Resilience4j
 *      Circuit Breaker</a>
 * @see <a href="https://micrometer.io/docs">Micrometer Documentation</a>
 * @see <a href=
 *      "https://opentelemetry.io/docs/instrumentation/java/">OpenTelemetry
 *      Java</a>
 */
// Suppress: classe responsável por integração completa SMART Backend Services
// DeclarationOrder: grouping by logical role over access modifier
// PMD.GodClass/TooManyMethods/CyclomaticComplexity: TODO débito técnico —
// extrair builder, retry e cache em colaboradores dedicados em refatoração
// futura.
@SuppressWarnings({"PMD.CouplingBetweenObjects", "PMD.GodClass",
    "PMD.TooManyMethods", "PMD.CyclomaticComplexity",
    "checkstyle:DeclarationOrder"})
public final class SmartTokenClient implements AutoCloseable {

    private static final Logger LOG = LoggerFactory.getLogger(SmartTokenClient.class);

    private static final String GRANT_TYPE = "client_credentials";
    private static final String ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    /** ObjectMapper compartilhado (thread-safe) com configuração de segurança. */
    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.builder()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .build();

    /** Código HTTP: Rate Limit Exceeded. */
    private static final int HTTP_TOO_MANY_REQUESTS = 429;

    /** Código HTTP: OK. */
    private static final int HTTP_OK = 200;

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
    public static final String DEFAULT_TLS_PROTOCOL = SslContextFactory.DEFAULT_TLS_PROTOCOL;

    /** Algoritmo JWT padrão. */
    public static final String DEFAULT_JWT_ALGORITHM = "RS256";

    /** Tamanho inicial do StringBuilder para form body. */
    private static final int FORM_BODY_INITIAL_CAPACITY = 128;

    /** Limite máximo para sanitização de respostas de erro. */
    private static final int MAX_ERROR_RESPONSE_LENGTH = 500;

    /**
     * Quantidade fixa de locks usados no striping de {@link #scopeLocks}.
     * Limita a memória a O(1) — constante, independentemente do número
     * de scopes distintos (ver issue #731).
     */
    private static final int SCOPE_LOCK_STRIPES = 32;

    /** Encoder Base64 URL-safe sem padding. */
    private static final Base64.Encoder BASE64_URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    private final String tokenEndpoint;
    private final String clientId;
    private final SigningStrategy signingStrategy;
    private final HttpClient httpClient;
    private final FaultToleranceConfig faultToleranceConfig;
    private final boolean enableTokenCache;
    private final int tokenCacheMarginSeconds;
    private final String jwtAlgorithm;
    private final String keyId;

    /** Indica se {@link #close()} já foi invocado (close idempotente). */
    private final AtomicBoolean closed = new AtomicBoolean();

    /** Sleeper usado entre tentativas de retry (padrão: {@link Thread#sleep(long)}). */
    private volatile Sleeper sleeper = Thread::sleep;

    /** Cache de tokens por scope. */
    private final Map<String, CachedToken> tokenCache = new ConcurrentHashMap<>();

    /**
     * Locks (lock striping) para evitar múltiplas renovações simultâneas
     * do mesmo scope.
     *
     * <p>
     * Cada scope é mapeado de forma determinística a um dos
     * {@link #SCOPE_LOCK_STRIPES} locks via hash. Scopes distintos podem
     * compartilhar o mesmo lock (contenção falsa ocasional), mas o
     * single-flight por scope é preservado e a memória é fixa —
     * independentemente da quantidade de scopes distintos usados ao longo
     * da vida do cliente.
     * </p>
     */
    private final ReentrantLock[] scopeLocks;

    /**
     * Cria o cliente carregando chave privada e certificado de arquivos PEM.
     *
     * <p>
     * O {@link SSLContext} é configurado automaticamente com a chave privada
     * e o certificado do cliente como {@code KeyManager}, habilitando mTLS
     * quando o servidor solicitar autenticação mútua. Quando o servidor não
     * exige certificado do cliente, a conexão se comporta como TLS
     * unidirecional — totalmente retrocompatível.
     * </p>
     *
     * @param tokenEndpoint  URL do endpoint /auth/token do servidor de autorização
     * @param clientId       identificador do cliente (fornecido pelo Ganesha no
     *                       credenciamento)
     * @param privateKeyPem  caminho para o arquivo PEM da chave privada
     * @param certificatePem caminho para o arquivo PEM do certificado do cliente
     */
    public SmartTokenClient(
            final String tokenEndpoint,
            final String clientId,
            final Path privateKeyPem,
            final Path certificatePem) throws IOException {
        this(tokenEndpoint, clientId,
                loadFromPem(privateKeyPem, certificatePem, null, DEFAULT_TLS_PROTOCOL),
                new FaultToleranceConfig(DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT,
                        DEFAULT_ASSERTION_TTL_SECONDS, DEFAULT_MAX_RETRIES),
                true, DEFAULT_TOKEN_CACHE_MARGIN_SECONDS);
    }

    /**
     * Versão avançada que aceita um certificado público do servidor para ser
     * utilizado como trust anchor, permitindo validação TLS específica quando
     * o chamador possui a cadeia correta.
     *
     * <p>
     * O {@link SSLContext} é configurado automaticamente com a chave privada
     * e o certificado do cliente como {@code KeyManager}, habilitando mTLS
     * quando o servidor solicitar autenticação mútua.
     * </p>
     *
     * @param tokenEndpoint     URL do endpoint /auth/token do servidor de
     *                          autorização
     * @param clientId          identificador do cliente (fornecido pelo Ganesha no
     *                          credenciamento)
     * @param privateKeyPem     caminho para o arquivo PEM da chave privada
     * @param certificatePem    caminho para o arquivo PEM do certificado do
     *                          cliente
     * @param serverTrustAnchor certificado X.509 confiável do servidor; quando
     *                          {@code null}, usa-se o trust store padrão da JVM
     */
    public SmartTokenClient(
            final String tokenEndpoint,
            final String clientId,
            final Path privateKeyPem,
            final Path certificatePem,
            final Path serverTrustAnchor) throws IOException {
        this(tokenEndpoint, clientId,
                loadFromPem(privateKeyPem, certificatePem, serverTrustAnchor, DEFAULT_TLS_PROTOCOL),
                new FaultToleranceConfig(DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT,
                        DEFAULT_ASSERTION_TTL_SECONDS, DEFAULT_MAX_RETRIES),
                true, DEFAULT_TOKEN_CACHE_MARGIN_SECONDS);
    }

    /**
     * Construtor privado que delega a partir do contexto de inicialização PEM.
     */
    private SmartTokenClient(
            final String tokenEndpoint,
            final String clientId,
            final PemInitContext init,
            final FaultToleranceConfig faultToleranceConfig,
            final boolean enableTokenCache,
            final int tokenCacheMarginSeconds) {
        this(tokenEndpoint, clientId,
                init.signingStrategy(), init.certificate(), init.sslContext(),
                faultToleranceConfig, enableTokenCache, tokenCacheMarginSeconds);
    }

    /**
     * Construtor de baixo nível para cenários em que os artefatos criptográficos
     * já foram carregados (ex: Vault, Secret Manager).
     *
     * @param tokenEndpoint URL do endpoint /auth/token do servidor de autorização
     * @param clientId      identificador do cliente (fornecido pelo Ganesha no
     *                      credenciamento)
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
        this(tokenEndpoint, clientId,
                createValidatedSigningStrategy(privateKey, certificate),
                certificate, sslContext,
                new FaultToleranceConfig(DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT,
                        DEFAULT_ASSERTION_TTL_SECONDS, DEFAULT_MAX_RETRIES),
                true, DEFAULT_TOKEN_CACHE_MARGIN_SECONDS);
    }

    // === Construtor principal ===
    /**
     * Construtor principal de baixo nível.
     *
     * <p>Validações fail-fast executadas na construção:</p>
     * <ul>
     * <li>{@code jwtAlgorithm} é validado contra a allowlist de algoritmos
     * suportados (famílias RS, PS e ES); valores como {@code none} ou
     * {@code HS256} são rejeitados com {@link SmartTokenException};</li>
     * <li>quando {@code certificate} não é {@code null}, a consistência entre
     * a estratégia de assinatura e a chave pública do certificado é
     * verificada (mesma semântica de
     * {@link #verifyKeyPairConsistency(PrivateKey, X509Certificate)}).</li>
     * </ul>
     *
     * @param tokenEndpoint           URL do endpoint /auth/token
     * @param clientId                identificador do cliente
     * @param signingStrategy         estratégia de assinatura JWT
     * @param certificate             certificado X.509 do cliente
     * @param sslContext              contexto SSL para o {@link HttpClient}
     * @param faultToleranceConfig    configuração de resiliência
     * @param enableTokenCache        se {@code true}, habilita cache de tokens
     * @param tokenCacheMarginSeconds margem em segundos antes da expiração
     * @param jwtAlgorithm            algoritmo JWT (ex: RS256, ES256)
     * @param keyId                   identificador da chave ({@code kid} do
     *                                header JWT); {@code null} para omitir
     */
    @SuppressWarnings({"checkstyle:ParameterNumber", "PMD.ExcessiveParameterList"})
    public SmartTokenClient(
        String tokenEndpoint,
        String clientId,
        SigningStrategy signingStrategy,
        X509Certificate certificate,
        SSLContext sslContext,
        FaultToleranceConfig faultToleranceConfig,
        boolean enableTokenCache,
        int tokenCacheMarginSeconds,
        String jwtAlgorithm,
        String keyId
    ) {
        this.tokenEndpoint = Objects.requireNonNull(tokenEndpoint, "tokenEndpoint");
        this.clientId = Objects.requireNonNull(clientId, "clientId");
        this.signingStrategy = Objects.requireNonNull(signingStrategy, "signingStrategy");
        final SSLContext context = Objects.requireNonNull(sslContext, "sslContext");
        this.faultToleranceConfig = Objects.requireNonNull(faultToleranceConfig, "faultToleranceConfig");
        this.enableTokenCache = enableTokenCache;
        this.tokenCacheMarginSeconds = tokenCacheMarginSeconds > 0
                ? tokenCacheMarginSeconds
                : DEFAULT_TOKEN_CACHE_MARGIN_SECONDS;
        this.jwtAlgorithm = jwtAlgorithm != null ? jwtAlgorithm : DEFAULT_JWT_ALGORITHM;
        // Valida o algoritmo contra a allowlist (rejeita none, HS256, etc.)
        SigningStrategyFactory.jwtAlgorithmToJava(this.jwtAlgorithm);
        this.keyId = keyId;
        this.scopeLocks = new ReentrantLock[SCOPE_LOCK_STRIPES];
        for (int i = 0; i < SCOPE_LOCK_STRIPES; i++) {
            this.scopeLocks[i] = new ReentrantLock();
        }
        if (certificate != null) {
            SslContextFactory.checkCertificateValidity(certificate,
                    certificate.getSubjectX500Principal().getName());
            verifyStrategyCertificateConsistency(this.signingStrategy, certificate);
        }
        this.httpClient = HttpClient.newBuilder()
                .sslContext(context)
                .connectTimeout(faultToleranceConfig.connectTimeout())
                .build();
        LOG.debug("SmartTokenClient inicializado para clientId={} endpoint={} cache={} maxRetries={} alg={}",
                clientId, tokenEndpoint, enableTokenCache, faultToleranceConfig.maxRetries(), this.jwtAlgorithm);
    }

    /**
     * Construtor de compatibilidade (sem {@code keyId}).
     *
     * @param tokenEndpoint           URL do endpoint /auth/token
     * @param clientId                identificador do cliente
     * @param signingStrategy         estratégia de assinatura JWT
     * @param certificate             certificado X.509 do cliente
     * @param sslContext              contexto SSL para o {@link HttpClient}
     * @param faultToleranceConfig    configuração de resiliência
     * @param enableTokenCache        se {@code true}, habilita cache de tokens
     * @param tokenCacheMarginSeconds margem em segundos antes da expiração
     * @param jwtAlgorithm            algoritmo JWT (ex: RS256, ES256)
     */
    @SuppressWarnings({"checkstyle:ParameterNumber", "PMD.ExcessiveParameterList"})
    public SmartTokenClient(
        String tokenEndpoint,
        String clientId,
        SigningStrategy signingStrategy,
        X509Certificate certificate,
        SSLContext sslContext,
        FaultToleranceConfig faultToleranceConfig,
        boolean enableTokenCache,
        int tokenCacheMarginSeconds,
        String jwtAlgorithm
    ) {
        this(tokenEndpoint, clientId, signingStrategy, certificate, sslContext,
                faultToleranceConfig, enableTokenCache, tokenCacheMarginSeconds,
                jwtAlgorithm, null);
    }

    /**
     * Construtor de compatibilidade (sem jwtAlgorithm).
     *
     * @param tokenEndpoint           URL do endpoint /auth/token
     * @param clientId                identificador do cliente
     * @param signingStrategy         estratégia de assinatura JWT
     * @param certificate             certificado X.509 do cliente
     * @param sslContext              contexto SSL para o {@link HttpClient}
     * @param faultToleranceConfig    configuração de resiliência
     * @param enableTokenCache        se {@code true}, habilita cache de tokens
     * @param tokenCacheMarginSeconds margem em segundos antes da expiração
     */
    @SuppressWarnings("checkstyle:ParameterNumber")
    public SmartTokenClient(
        String tokenEndpoint,
        String clientId,
        SigningStrategy signingStrategy,
        X509Certificate certificate,
        SSLContext sslContext,
        FaultToleranceConfig faultToleranceConfig,
        boolean enableTokenCache,
        int tokenCacheMarginSeconds
    ) {
        this(tokenEndpoint, clientId, signingStrategy, certificate, sslContext,
                faultToleranceConfig, enableTokenCache, tokenCacheMarginSeconds, DEFAULT_JWT_ALGORITHM);
    }

    /**
     * Cria SigningStrategy validando a consistência entre chave e certificado.
     */
    private static SigningStrategy createValidatedSigningStrategy(
            final PrivateKey privateKey,
            final X509Certificate certificate) {
        verifyKeyPairConsistency(privateKey, certificate);
        return SigningStrategyFactory.fromPrivateKey(privateKey);
    }

    /**
     * Validação fail-fast de consistência entre a estratégia de assinatura e
     * o certificado do cliente.
     *
     * <p>
     * Realiza uma assinatura de teste por meio da própria estratégia (o que
     * funciona inclusive para HSM/PKCS#11, pois a assinatura é delegada ao
     * hardware) e a verifica com a chave pública do certificado, usando o
     * mesmo algoritmo e parâmetros da estratégia.
     * </p>
     *
     * <p>
     * <strong>Limitação:</strong> a verificação só é possível quando a
     * estratégia é uma {@link PrivateKeySigningStrategy}, pois é necessário
     * conhecer o algoritmo JCA para verificar a assinatura. Estratégias
     * customizadas (implementações próprias de {@link SigningStrategy}) são
     * aceitas sem validação.
     * </p>
     *
     * @param strategy    estratégia de assinatura a validar
     * @param certificate certificado X.509 com a chave pública correspondente
     * @throws SmartTokenException se a assinatura de teste não puder ser
     *                             verificada com a chave pública do certificado
     */
    private static void verifyStrategyCertificateConsistency(
            final SigningStrategy strategy,
            final X509Certificate certificate) {
        if (!(strategy instanceof PrivateKeySigningStrategy pkStrategy)) {
            LOG.debug("Estratégia de assinatura customizada: consistência com o"
                    + " certificado não pode ser verificada automaticamente");
            return;
        }
        try {
            final byte[] challenge = "key-pair-consistency-check".getBytes(StandardCharsets.UTF_8);
            final byte[] signature = pkStrategy.sign(challenge);

            final Signature verifier = Signature.getInstance(pkStrategy.getAlgorithm());
            if (pkStrategy.getParameterSpec() != null) {
                verifier.setParameter(pkStrategy.getParameterSpec());
            }
            verifier.initVerify(certificate.getPublicKey());
            verifier.update(challenge);
            if (!verifier.verify(signature)) {
                throw new SmartTokenException(
                        "Chave privada não corresponde ao certificado: assinatura inválida");
            }
            LOG.trace("Verificação de consistência estratégia-certificado concluída com sucesso");
        } catch (SmartTokenException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new SmartTokenException(
                    "Falha ao verificar consistência entre chave privada e certificado: "
                            + ex.getMessage(), ex);
        }
    }

    /**
     * Cria um novo {@link SmartTokenClientBuilder} para configuração fluente do
     * cliente.
     *
     * @return nova instância do builder
     */
    public static SmartTokenClientBuilder builder() {
        return new SmartTokenClientBuilder();
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
     * Em caso de falhas transitórias de rede (timeout de conexão ou de
     * requisição, recusa ou queda de conexão TCP), o método realiza retry
     * com backoff exponencial (1s, 2s, 4s...) até o limite configurado.
     * Respostas HTTP recebidas (qualquer status, inclusive 429 e 5xx) não
     * sofrem retry automático: resultam em erro imediato com o corpo
     * sanitizado e, quando presente, o valor de {@code Retry-After} como
     * diagnóstico — a decisão de aguardar e reenviar é do chamador.
     * </p>
     *
     * @param scope scopes separados por espaço (ex: {@code "system/Patient.rs"})
     * @return access token JWT emitido pelo servidor de autorização
     * @throws IOException          em caso de erro de I/O na comunicação
     * @throws InterruptedException se a thread for interrompida durante a
     *                              requisição
     * @throws SmartTokenException  se o servidor retornar erro ou resposta inválida
     */
    public String obtainToken(final String scope) throws IOException, InterruptedException {
        return obtainTokenResponse(scope).accessToken();
    }

    /**
     * Obtém um token de acesso e devolve a resposta completa do servidor de
     * autorização, incluindo o corpo JSON cru (quando disponível).
     *
     * <p>Compartilha exatamente a mesma lógica de cache, lock por scope e
     * tolerância a falhas de {@link #obtainToken(String)} — na verdade,
     * {@code obtainToken} delega a este método.</p>
     *
     * <p><strong>Atenção:</strong> {@link TokenResponse#rawJson()} só é
     * preenchido em uma requisição HTTP real. Quando o token é servido a
     * partir do cache, {@code rawJson()} retorna {@code null} (o corpo
     * original não é mantido em cache). Para o caso de uso de inspeção/CLI,
     * cada execução é um processo novo e portanto sempre realiza um fetch
     * fresco.</p>
     *
     * @param scope scopes separados por espaço (ex: {@code "system/Patient.rs"})
     * @return resposta do token endpoint (access token, expires_in e JSON cru)
     * @throws IOException          em caso de erro de I/O na comunicação
     * @throws InterruptedException se a thread for interrompida durante a
     *                              requisição
     * @throws SmartTokenException  se o servidor retornar erro ou resposta inválida
     */
    public TokenResponse obtainTokenResponse(final String scope)
            throws IOException, InterruptedException {
        final String normalizedScope = scope == null ? "" : scope.trim();

        final TokenResponse early = cachedResponseIfValid(normalizedScope);
        if (early != null) {
            return early;
        }

        // Usa lock por scope (striping) para evitar múltiplas requisições
        // simultâneas. O lock é adquirido por tentativa e liberado antes do
        // backoff, de modo que a espera entre tentativas NÃO ocorre em seção
        // crítica. A garantia de single-flight vale por tentativa: apenas uma
        // thread executa a requisição HTTP de um scope por vez; entre
        // tentativas, outra thread pode adquirir o lock, mas o double-check
        // do cache evita requisições redundantes quando o token já foi
        // renovado. Scopes distintos podem compartilhar o mesmo lock (ver
        // scopeLockFor), sem afetar a correção.
        final ReentrantLock lock = scopeLockFor(normalizedScope);
        LOG.debug("Iniciando obtenção de token para clientId={} scope={}", clientId, normalizedScope);

        final int maxRetries = faultToleranceConfig.maxRetries();
        IOException lastException = null;
        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            lock.lock();
            try {
                final TokenResponse cached = cachedResponseIfValid(normalizedScope);
                if (cached != null) {
                    return cached;
                }
                return doObtainToken(normalizedScope);
            } catch (IOException ex) {
                // Lança SmartTokenException/IOException se não retriável
                lastException = retriableOrRethrow(ex);
            } finally {
                lock.unlock();
            }
            waitBeforeNextAttempt(attempt, maxRetries, lastException);
        }
        throw new SmartTokenException(
                "Falha após " + maxRetries + " tentativas: "
                        + (lastException != null ? lastException.getMessage() : "sem causa capturada"),
                lastException);
    }

    /**
     * Retorna o token em cache para o scope, quando o cache está habilitado
     * e o token ainda é válido; caso contrário, {@code null}.
     *
     * @param normalizedScope scope normalizado
     * @return resposta reconstruída do cache ou {@code null}
     */
    private TokenResponse cachedResponseIfValid(final String normalizedScope) {
        if (!enableTokenCache) {
            return null;
        }
        final CachedToken cached = tokenCache.get(normalizedScope);
        if (cached != null && cached.isValid(tokenCacheMarginSeconds)) {
            LOG.debug("Retornando token em cache para clientId={} scope={}",
                    clientId, normalizedScope);
            return fromCache(cached);
        }
        return null;
    }

    /**
     * Classifica a exceção de I/O: devolve-a quando representa falha
     * transitória de rede (timeout de conexão ou de requisição, recusa ou
     * queda de conexão TCP) para que o chamador realize retry; caso
     * contrário, propaga. Respostas HTTP recebidas nunca chegam aqui como
     * exceção — falham imediatamente em {@link #doObtainToken(String)}.
     *
     * @param ex exceção capturada na tentativa
     * @return a própria exceção, quando retriável
     * @throws IOException         quando a exceção não é retriável
     * @throws SmartTokenException quando a falha aparenta ser rejeição do
     *                             certificado de cliente no mTLS
     */
    private IOException retriableOrRethrow(final IOException ex) throws IOException {
        if (isLikelyClientCertificateRejection(ex)) {
            LOG.error("Falha de TLS após handshake mTLS para clientId={} endpoint={}: {}."
                    + " Causa provável: certificado de cliente rejeitado pelo servidor"
                    + " (revogado, expirado ou não confiável) — o servidor abortou a conexão"
                    + " em vez de retornar uma resposta HTTP de erro.",
                    clientId, tokenEndpoint, ex.toString());
            throw new SmartTokenException(
                    "Conexão TLS abortada pelo servidor após o handshake mTLS contra "
                            + tokenEndpoint
                            + ". Causa provável: certificado de cliente rejeitado"
                            + " (revogado, expirado ou não confiável)."
                            + " Verifique a validade do certificado em uso e, se ele estiver"
                            + " correto, contate o operador do servidor de autorização —"
                            + " a resposta esperada nesse cenário seria um alerta TLS"
                            + " (certificate_revoked/certificate_expired) ou HTTP 401,"
                            + " e não o encerramento abrupto da conexão.",
                    ex);
        }
        if (isTransientNetworkFailure(ex)) {
            return ex;
        }
        throw ex;
    }

    /**
     * Identifica falhas transitórias de rede elegíveis a retry: timeout de
     * conexão ou de requisição HTTP e recusa/queda de conexão TCP
     * (conexão recusada, connection reset ou EOF prematuro).
     *
     * <p>A cadeia de causas é percorrida porque o {@link HttpClient}
     * frequentemente envolve a causa original em {@link IOException}
     * genérica (ex.: "HTTP/1.1 header parser received no bytes" com causa
     * {@link EOFException} ou {@link SocketException}). Em algumas
     * execuções o JDK lança essa mesma {@link IOException} sem causa
     * anexada; por isso a mensagem também é inspecionada — ela indica
     * conexão encerrada pelo servidor antes de qualquer byte de resposta.
     * Falhas da camada TLS ({@link SSLException}) nunca são consideradas
     * transitórias — são tratadas pela heurística de
     * {@link #isLikelyClientCertificateRejection(Throwable)} ou propagadas
     * como estão.</p>
     *
     * @param ex exceção de I/O capturada
     * @return {@code true} quando a falha é transitória de rede
     */
    static boolean isTransientNetworkFailure(final IOException ex) {
        for (Throwable t = ex; t != null; t = t.getCause()) {
            if (t instanceof SSLException) {
                return false;
            }
            if (t instanceof HttpTimeoutException
                    || t instanceof SocketException
                    || t instanceof EOFException) {
                return true;
            }
            final String msg = t.getMessage();
            if (msg != null && msg.toLowerCase(java.util.Locale.ROOT)
                    .contains("received no bytes")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Aguarda o backoff entre tentativas — FORA da seção crítica (o lock por
     * scope já foi liberado pelo chamador). Na última tentativa apenas
     * registra a falha.
     *
     * <p>O delay é calculado por {@link RetryPolicy#computeRetryDelayMs}:
     * backoff exponencial (1s, 2s, 4s...), sem jitter.</p>
     *
     * @param attempt       tentativa que acabou de falhar (1-based)
     * @param maxRetries    total de tentativas configurado
     * @param lastException exceção da tentativa
     * @throws InterruptedException se a thread for interrompida no sleep
     */
    private void waitBeforeNextAttempt(
            final int attempt, final int maxRetries, final IOException lastException)
            throws InterruptedException {
        if (attempt >= maxRetries) {
            LOG.error("Todas as {} tentativas falharam para clientId={}", maxRetries, clientId);
            return;
        }
        final long delayMs = RetryPolicy.computeRetryDelayMs(attempt);
        LOG.warn("Tentativa {}/{} falhou para clientId={}: {}. Retry em {}ms",
                attempt, maxRetries, clientId, lastException.getMessage(), delayMs);
        sleeper.sleep(delayMs);
    }

    /**
     * Retorna o lock associado ao scope via striping: o hash do scope
     * seleciona um dos {@link #SCOPE_LOCK_STRIPES} locks fixos. O mesmo
     * scope sempre mapeia para o mesmo lock, preservando o single-flight
     * por scope; scopes distintos podem compartilhar um lock.
     */
    ReentrantLock scopeLockFor(final String scope) {
        final int index = Math.floorMod(scope.hashCode(), SCOPE_LOCK_STRIPES);
        return scopeLocks[index];
    }

    /**
     * Reconstrói uma {@link TokenResponse} a partir de um token em cache.
     * O corpo JSON original não é preservado em cache, portanto
     * {@code rawJson} é {@code null}.
     */
    private static TokenResponse fromCache(final CachedToken cached) {
        final long remaining = Duration.between(Instant.now(), cached.expiresAt()).getSeconds();
        return new TokenResponse(cached.accessToken(), (int) Math.max(0, remaining), null);
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
        LOG.info("Cache invalidado para clientId={} scope={}", clientId, normalizedScope);
    }

    /**
     * Retorna a URL do token endpoint configurado.
     *
     * <p>
     * Útil para diagnóstico, especialmente quando o endpoint foi
     * descoberto automaticamente via {@code .well-known/smart-configuration}.
     * </p>
     *
     * @return URL do token endpoint
     */
    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    /**
     * Retorna o algoritmo JWT configurado para assinatura do client_assertion.
     *
     * @return nome do algoritmo JWT (ex: RS384, RS256)
     */
    public String getJwtAlgorithm() {
        return jwtAlgorithm;
    }

    /**
     * Retorna o identificador de chave ({@code kid}) configurado, se houver.
     *
     * @return valor do {@code kid} incluído no header do client_assertion,
     *         ou {@code null} quando não configurado
     */
    public String getKeyId() {
        return keyId;
    }

    /**
     * Substitui o sleeper usado no backoff. Visibilidade package-private,
     * destinado exclusivamente a testes.
     *
     * @param sleeper implementação alternativa de sleep
     */
    void setSleeper(final Sleeper sleeper) {
        this.sleeper = Objects.requireNonNull(sleeper, "sleeper");
    }

    /**
     * Fecha o {@link HttpClient} interno, liberando threads e conexões.
     *
     * <p>
     * O {@code HttpClient} é sempre criado internamente por esta classe
     * (não há injeção de cliente HTTP externo), portanto é seguro fechá-lo
     * aqui. Chamadas subsequentes a {@link #obtainToken(String)} após o
     * fechamento falharão.
     * </p>
     *
     * <p>Este método é idempotente: invocações repetidas não têm efeito.</p>
     */
    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            httpClient.close();
            LOG.debug("SmartTokenClient fechado para clientId={}", clientId);
        }
    }

    /**
     * Heurística para identificar falhas de TLS que tipicamente indicam que o
     * servidor rejeitou o certificado de cliente (revogado, expirado ou não
     * confiável) sem produzir uma resposta HTTP de erro adequada.
     *
     * <p>São tratadas como suspeitas:
     * <ul>
     *   <li>{@link SSLHandshakeException} — rejeição durante o handshake;</li>
     *   <li>{@link AEADBadTagException} na cadeia de causas — record cifrado
     *       com tag AEAD inválido, sintoma típico de servidor que aceita o
     *       handshake mas corrompe o estado da conexão ao decidir rejeitar
     *       o certificado de cliente após o {@code Finished};</li>
     *   <li>{@link SSLException} com mensagem mencionando {@code bad_record_mac}
     *       — equivalente do ponto anterior visto pelo lado JSSE.</li>
     * </ul>
     *
     * <p>Falhas cuja cadeia de causas contém
     * {@link java.security.cert.CertificateException},
     * {@link java.security.cert.CertPathBuilderException} ou
     * {@link java.security.cert.CertPathValidatorException} são excluídas:
     * indicam que foi ESTE cliente que rejeitou o certificado do servidor
     * (ex.: {@code PKIX path building failed} por trust anchor ausente ou
     * incorreto), e não o contrário.</p>
     *
     * <p>Esta verificação é heurística e deve ser usada apenas para enriquecer
     * mensagens de erro; não substitui o diagnóstico do servidor.
     */
    static boolean isLikelyClientCertificateRejection(final Throwable ex) {
        for (Throwable t = ex; t != null; t = t.getCause()) {
            if (t instanceof java.security.cert.CertificateException
                    || t instanceof java.security.cert.CertPathBuilderException
                    || t instanceof java.security.cert.CertPathValidatorException) {
                // Cliente rejeitou o certificado do SERVIDOR (validação
                // local do trust anchor) — não é rejeição mTLS pelo servidor.
                return false;
            }
        }
        for (Throwable t = ex; t != null; t = t.getCause()) {
            if (t instanceof AEADBadTagException || t instanceof SSLHandshakeException) {
                return true;
            }
            if (t instanceof SSLException) {
                final String msg = t.getMessage();
                if (msg != null && msg.toLowerCase(java.util.Locale.ROOT).contains("bad_record_mac")) {
                    return true;
                }
            }
        }
        return false;
    }

    private TokenResponse doObtainToken(final String scope) throws IOException, InterruptedException {
        final String assertion = buildClientAssertion();
        final String body = buildFormBody(clientId, assertion, scope);

        final HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(tokenEndpoint))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .timeout(faultToleranceConfig.requestTimeout())
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        LOG.trace("Enviando requisição POST para {}", tokenEndpoint);
        final HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        final int statusCode = response.statusCode();
        if (statusCode != HTTP_OK) {
            if (statusCode == HTTP_TOO_MANY_REQUESTS) {
                LOG.warn("Rate limit (HTTP 429) para clientId={} — sem retry automático",
                        clientId);
            } else {
                LOG.error("Falha ao obter token: HTTP {} para clientId={}",
                        statusCode, clientId);
            }
            throw new SmartTokenException(buildHttpErrorMessage(statusCode, response));
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
        return tokenResponse;
    }

    /**
     * Monta a mensagem de erro para resposta HTTP ≠ 200: status, valor de
     * {@code Retry-After} quando presente (apenas diagnóstico — nenhuma
     * resposta HTTP recebida sofre retry automático; a decisão de aguardar
     * e reenviar é do chamador) e corpo sanitizado.
     *
     * @param statusCode status HTTP da resposta
     * @param response   resposta recebida do servidor de autorização
     * @return mensagem de erro pronta para {@link SmartTokenException}
     */
    private static String buildHttpErrorMessage(
            final int statusCode, final HttpResponse<String> response) {
        final String retryAfter = response.headers().firstValue("Retry-After")
                .map(value -> " (Retry-After: " + value.trim() + ")")
                .orElse("");
        final String hint = statusCode == HTTP_TOO_MANY_REQUESTS
                ? " Rate limit atingido; a decisão de aguardar e reenviar é do chamador."
                : "";
        return "Falha ao obter token: HTTP " + statusCode + retryAfter
                + " — " + sanitizeErrorResponse(response.body()) + hint;
    }

    /**
     * Constrói o JWT client_assertion assinado com o algoritmo configurado.
     *
     * @return JWT compacto pronto para uso no campo client_assertion
     */
    @SuppressWarnings("PMD.UseConcurrentHashMap")
    String buildClientAssertion() {
        final Instant now = Instant.now();
        final long iat = now.getEpochSecond();
        final long exp = now.plusSeconds(faultToleranceConfig.assertionTtlSeconds()).getEpochSecond();
        final String jti = UUID.randomUUID().toString();
        LOG.trace("Construindo client_assertion ttl={}s alg={}",
                faultToleranceConfig.assertionTtlSeconds(), jwtAlgorithm);

        // Constrói o payload JSON usando ObjectMapper para escape correto e seguro
        final Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", clientId);
        claims.put("sub", clientId);
        claims.put("aud", tokenEndpoint);
        claims.put("iat", iat);
        claims.put("exp", exp);
        claims.put("jti", jti);

        final String payload;
        try {
            payload = OBJECT_MAPPER.writeValueAsString(claims);
        } catch (JacksonException e) {
            throw new SmartTokenException("Falha ao serializar payload do JWT", e);
        }

        // Constrói o header JWT via Jackson (escape correto e seguro),
        // incluindo o kid quando configurado
        final ObjectNode headerNode = OBJECT_MAPPER.createObjectNode();
        headerNode.put("alg", jwtAlgorithm);
        headerNode.put("typ", "JWT");
        if (keyId != null && !keyId.isBlank()) {
            headerNode.put("kid", keyId);
        }
        final String jwtHeader;
        try {
            jwtHeader = OBJECT_MAPPER.writeValueAsString(headerNode);
        } catch (JacksonException e) {
            throw new SmartTokenException("Falha ao serializar header do JWT", e);
        }

        // Codifica header e payload em Base64Url
        final String headerB64 = BASE64_URL_ENCODER.encodeToString(
                jwtHeader.getBytes(StandardCharsets.UTF_8));
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
     * Monta o payload {@code application/x-www-form-urlencoded} exigido pelo
     * endpoint {@code /auth/token}, incluindo {@code client_id}, {@code client_assertion} e scopes.
     *
     * <p>
     * O parâmetro {@code client_id} é incluído no corpo da requisição para
     * compatibilidade com servidores OAuth2/OIDC como Keycloak, que exigem
     * esse parâmetro além do JWT assertion.
     * </p>
     *
     * @param clientId  identificador do cliente
     * @param assertion JWT assinado que comprova a identidade do cliente
     * @param scope     escopos solicitados, separados por espaço (opcional)
     * @return string pronta para envio no corpo da requisição HTTP
     */
    public static String buildFormBody(final String clientId, final String assertion, final String scope) {
        final StringBuilder sb = new StringBuilder(FORM_BODY_INITIAL_CAPACITY)
                .append("grant_type=").append(encode(GRANT_TYPE))
                .append("&client_id=").append(encode(clientId))
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
        final String accessToken = node.get("access_token").asString();
        final int expiresIn = node.has("expires_in") ? node.get("expires_in").asInt() : 3600;
        return new TokenResponse(accessToken, expiresIn, jsonBody);
    }

    /**
     * Sanitiza a resposta de erro para evitar vazamento de tokens em logs.
     *
     * <p>
     * A redação de tokens é aplicada <strong>antes</strong> do truncamento,
     * garantindo que nenhum token apareça mesmo em respostas longas.
     * </p>
     *
     * @param responseBody corpo da resposta HTTP
     * @return resposta sanitizada
     */
    static String sanitizeErrorResponse(final String responseBody) {
        if (responseBody == null) {
            return "<empty>";
        }
        // Remove possíveis tokens do erro (JSON e form-encoded) ANTES de truncar
        final String redacted = responseBody
                .replaceAll("(\"(?:access_token|token)\")\\s*:\\s*\"[^\"]*\"", "$1:\"[REDACTED]\"")
                .replaceAll("(access_token|token)=[^&\\s]*", "$1=[REDACTED]");
        if (redacted.length() > MAX_ERROR_RESPONSE_LENGTH) {
            return redacted.substring(0, MAX_ERROR_RESPONSE_LENGTH) + "...";
        }
        return redacted;
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
     * são fornecidos objetos {@link PrivateKey} e {@link X509Certificate}
     * diretamente
     * (não via arquivo PEM ou {@link SigningStrategy}).
     * </p>
     *
     * <h3>Cenários detectados</h3>
     * <ul>
     * <li>Arquivos trocados (certificado de um sistema, chave de outro)</li>
     * <li>Chave privada corrompida ou truncada</li>
     * <li>Certificado regenerado sem atualizar a chave</li>
     * </ul>
     *
     * @param privateKey  chave privada a validar
     * @param certificate certificado X.509 contendo a chave pública correspondente
     * @throws SmartTokenException se a assinatura de teste falhar, indicando
     *                             que chave e certificado não formam um par válido
     */
    public static void verifyKeyPairConsistency(
            final PrivateKey privateKey,
            final X509Certificate certificate) {
        try {
            // Determina o algoritmo de assinatura baseado no tipo da chave
            final String signatureAlgorithm = determineSignatureAlgorithm(privateKey);

            final byte[] challenge = "key-pair-consistency-check".getBytes(StandardCharsets.UTF_8);
            final Signature signer = Signature.getInstance(signatureAlgorithm);
            signer.initSign(privateKey);
            signer.update(challenge);
            final byte[] signature = signer.sign();

            final Signature verifier = Signature.getInstance(signatureAlgorithm);
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
     * Determina o algoritmo de assinatura apropriado para o tipo de chave.
     *
     * @param privateKey chave privada
     * @return algoritmo de assinatura compatível
     */
    private static String determineSignatureAlgorithm(final PrivateKey privateKey) {
        final String keyAlgorithm = privateKey.getAlgorithm();
        return switch (keyAlgorithm) {
            case "RSA" -> "SHA256withRSA";
            case "EC" -> "SHA256withECDSA";
            case "Ed25519" -> "Ed25519";
            case "Ed448" -> "Ed448";
            default -> throw new SmartTokenException(
                    "Tipo de chave não suportado para validação: " + keyAlgorithm);
        };
    }

    /**
     * Carrega material criptográfico de arquivos PEM e constrói o contexto
     * de inicialização com suporte a mTLS.
     *
     * <p>
     * A chave privada é carregada uma única vez e reutilizada tanto para a
     * {@link SigningStrategy} (assinatura do JWT) quanto para o
     * {@link javax.net.ssl.KeyManager} (apresentação do certificado no TLS).
     * </p>
     *
     * @param privateKeyPem     caminho para a chave privada PEM
     * @param certificatePem    caminho para o certificado PEM do cliente
     * @param serverTrustAnchor trust anchor do servidor (null = JVM default)
     * @param tlsProtocol       protocolo TLS
     * @return contexto de inicialização com signing strategy, certificado e SSLContext
     * @throws IOException se os arquivos não puderem ser lidos
     */
    private static PemInitContext loadFromPem(
            final Path privateKeyPem,
            final Path certificatePem,
            final Path serverTrustAnchor,
            final String tlsProtocol) throws IOException {
        final PrivateKey key = PemLoader.loadPrivateKey(privateKeyPem);
        final X509Certificate cert = SslContextFactory.validateCertificate(certificatePem);
        final SSLContext ssl = SslContextFactory.buildSslContext(
                serverTrustAnchor, tlsProtocol, key, cert);
        return new PemInitContext(
                SigningStrategyFactory.fromPrivateKey(key), cert, ssl);
    }

    /**
     * Contexto de inicialização a partir de arquivos PEM.
     *
     * <p>
     * Agrupa os artefatos construídos a partir de PEM (signing strategy,
     * certificado validado e SSLContext com mTLS) para passagem eficiente
     * entre métodos estáticos e construtores.
     * </p>
     */
    private record PemInitContext(
            SigningStrategy signingStrategy,
            X509Certificate certificate,
            SSLContext sslContext) {
    }

    /**
     * Abstração injetável de sleep para backoff, permitindo testes
     * determinísticos sem depender de tempo real.
     */
    @FunctionalInterface
    interface Sleeper {
        /**
         * Suspende a thread corrente pelo tempo indicado.
         *
         * @param millis duração em milissegundos
         * @throws InterruptedException se a thread for interrompida
         */
        void sleep(long millis) throws InterruptedException;
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

        /**
         * Representação textual com o token mascarado, evitando exposição
         * acidental em logs.
         *
         * @return string sem o valor do access token
         */
        @Override
        public String toString() {
            return "CachedToken[accessToken=[REDACTED], expiresAt=" + expiresAt + "]";
        }
    }

    /**
     * Representa a resposta do token endpoint.
     *
     * @param accessToken token de acesso emitido
     * @param expiresIn   validade do token em segundos
     * @param rawJson     corpo JSON cru da resposta do servidor de autorização;
     *                    {@code null} quando o token é servido a partir do cache
     */
    public record TokenResponse(String accessToken, int expiresIn, String rawJson) {

        /**
         * Representação textual com o token e o JSON cru mascarados,
         * evitando exposição acidental em logs.
         *
         * @return string sem o valor do access token nem o corpo cru
         */
        @Override
        public String toString() {
            return "TokenResponse[accessToken=[REDACTED], expiresIn=" + expiresIn
                    + ", rawJson=[REDACTED]]";
        }
    }
}
