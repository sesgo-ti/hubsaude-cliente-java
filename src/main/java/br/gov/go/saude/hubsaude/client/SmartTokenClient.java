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

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.net.ssl.SSLContext;

import org.jspecify.annotations.Nullable;
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
 * <li>Montagem do {@code client_assertion} JWT (assinado com RS384 por padrão)</li>
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
 * <li><strong>Correlação (traceparent W3C):</strong> cada requisição HTTP
 * carrega um header {@code traceparent} gerado localmente; o trace-id é
 * exposto nos logs de erro/retry para correlação com a plataforma</li>
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
 * <h3>Distributed Tracing e correlação (traceparent W3C)</h3>
 *
 * <p>
 * Por padrão, <strong>toda requisição HTTP desta biblioteca</strong> (token
 * endpoint e descoberta via {@code .well-known/smart-configuration}) carrega
 * o header {@code traceparent} do
 * <a href="https://www.w3.org/TR/trace-context/">W3C Trace Context</a>, com
 * trace-id (16 bytes) e span-id (8 bytes) gerados criptograficamente por
 * requisição — sem dependência do SDK OpenTelemetry. A flag {@code sampled}
 * é {@code 00} (a biblioteca não grava spans). O HubSaúde deriva o
 * identificador de correlação exclusivamente desse header; o trace-id é
 * registrado nos logs de erro/retry e nas mensagens de exceção
 * ({@code traceId=...}) — informe-o ao suporte para correlacionar o log
 * local do integrador com o {@code correlation-id} da plataforma.
 * </p>
 *
 * <p>
 * Aplicações instrumentadas com o OpenTelemetry Java Agent
 * ({@code -javaagent:opentelemetry-javaagent.jar}) continuam funcionando:
 * a instrumentação automática do {@link java.net.http.HttpClient} substitui
 * o header pelo contexto do span ativo, e o trace-id efetivo passa a ser o
 * do agente.
 * </p>
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
// DeclarationOrder: agrupamento por papel lógico em vez de modificador de acesso.
// PMD.CouplingBetweenObjects: fachada pública da biblioteca — orquestra
// colaboradores internos (cache, classificação de erros, TLS, assinatura)
// e tipos do JDK; acoplamento inerente ao papel de ponto único de entrada.
@SuppressWarnings({"PMD.CouplingBetweenObjects", "checkstyle:DeclarationOrder"})
public final class SmartTokenClient implements AutoCloseable {

    private static final Logger LOG = LoggerFactory.getLogger(SmartTokenClient.class);

    private static final String GRANT_TYPE = "client_credentials";
    private static final String ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    /** ObjectMapper compartilhado (thread-safe) com configuração de segurança. */
    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.builder()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .build();

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

    /** Quantidade máxima padrão de scopes retidos no cache de tokens. */
    public static final int DEFAULT_TOKEN_CACHE_MAX_ENTRIES = 1_000;

    /** Protocolo TLS padrão. */
    public static final String DEFAULT_TLS_PROTOCOL = SslContextFactory.DEFAULT_TLS_PROTOCOL;

    /**
     * Algoritmo JWT padrão (RS384 — concern client-assertion-contexto-ig.md
     * §3.2: o Servidor de Autorização aceita apenas RS384 e ES384).
     */
    public static final String DEFAULT_JWT_ALGORITHM = "RS384";

    /** Tamanho inicial do StringBuilder para form body. */
    private static final int FORM_BODY_INITIAL_CAPACITY = 128;

    /** Encoder Base64 URL-safe sem padding. */
    private static final Base64.Encoder BASE64_URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    /**
     * Formato do alias de IG no claim {@code hub_ctx.ig} (concern
     * client-assertion-contexto-ig.md §3.4).
     */
    private static final java.util.regex.Pattern HUB_CTX_IG_PATTERN =
            java.util.regex.Pattern.compile("^[a-z][a-z0-9-]{1,30}$");

    /**
     * Formato SemVer completo (MAJOR.MINOR.PATCH, sem pre-release/build) do
     * claim {@code hub_ctx.versao} (concern client-assertion-contexto-ig.md
     * §3.4).
     */
    private static final java.util.regex.Pattern HUB_CTX_VERSAO_PATTERN =
            java.util.regex.Pattern.compile("^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)$");

    private final String tokenEndpoint;
    private final String clientId;
    private final SigningStrategy signingStrategy;
    private final HttpClient httpClient;
    private final FaultToleranceConfig faultToleranceConfig;
    private final String jwtAlgorithm;
    private final @Nullable String keyId;
    private final @Nullable String hubCtxIg;
    private final @Nullable String hubCtxVersao;

    /** Classificador de falhas (retry, mTLS, respostas HTTP de erro). */
    private final ErrorClassifier errorClassifier;

    /** Cache de tokens por scope com lock striping (single-flight). */
    private final TokenCacheStrategy tokenCache;

    /** Indica se {@link #close()} já foi invocado (close idempotente). */
    private final AtomicBoolean closed = new AtomicBoolean();

    /** Coordena operações em voo com o fechamento e a limpeza final do cache. */
    private final ReentrantReadWriteLock lifecycleLock = new ReentrantReadWriteLock(true);

    /** Sleeper usado entre tentativas de retry (padrão: {@link Thread#sleep(long)}). */
    private volatile Sleeper sleeper = Thread::sleep;

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
            final @Nullable Path serverTrustAnchor) throws IOException {
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
     * {@link #verifyKeyPairConsistency(PrivateKey, X509Certificate)});</li>
     * <li>quando o contexto de IG é fornecido, {@code hubCtxIg} e
     * {@code hubCtxVersao} são validados contra os formatos do concern
     * client-assertion-contexto-ig.md §3.4.</li>
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
     * @param jwtAlgorithm            algoritmo JWT (ex: RS384, ES384)
     * @param keyId                   identificador da chave ({@code kid} do
     *                                header JWT); {@code null} para omitir
     * @param hubCtxIg                alias do Guia de Implementação para o
     *                                claim {@code hub_ctx.ig}; {@code null}
     *                                para omitir o claim
     * @param hubCtxVersao            versão SemVer do Guia de Implementação
     *                                para o claim {@code hub_ctx.versao};
     *                                {@code null} para omitir o claim
     */
    @SuppressWarnings({"checkstyle:ParameterNumber", "PMD.ExcessiveParameterList"})
    public SmartTokenClient(
        String tokenEndpoint,
        String clientId,
        SigningStrategy signingStrategy,
        @Nullable X509Certificate certificate,
        SSLContext sslContext,
        FaultToleranceConfig faultToleranceConfig,
        boolean enableTokenCache,
        int tokenCacheMarginSeconds,
        @Nullable String jwtAlgorithm,
        @Nullable String keyId,
        @Nullable String hubCtxIg,
        @Nullable String hubCtxVersao
    ) {
        this(tokenEndpoint, clientId, signingStrategy, certificate, sslContext,
                faultToleranceConfig, enableTokenCache, tokenCacheMarginSeconds,
                DEFAULT_TOKEN_CACHE_MAX_ENTRIES, jwtAlgorithm, keyId, hubCtxIg, hubCtxVersao);
    }

    /**
     * Construtor interno usado pelo builder para configurar o teto do cache.
     */
    @SuppressWarnings({"checkstyle:ParameterNumber", "PMD.ExcessiveParameterList"})
    SmartTokenClient(
        String tokenEndpoint,
        String clientId,
        SigningStrategy signingStrategy,
        @Nullable X509Certificate certificate,
        SSLContext sslContext,
        FaultToleranceConfig faultToleranceConfig,
        boolean enableTokenCache,
        int tokenCacheMarginSeconds,
        int tokenCacheMaxEntries,
        @Nullable String jwtAlgorithm,
        @Nullable String keyId,
        @Nullable String hubCtxIg,
        @Nullable String hubCtxVersao
    ) {
        this.tokenEndpoint = Objects.requireNonNull(tokenEndpoint, "tokenEndpoint");
        this.clientId = Objects.requireNonNull(clientId, "clientId");
        this.signingStrategy = Objects.requireNonNull(signingStrategy, "signingStrategy");
        final SSLContext context = Objects.requireNonNull(sslContext, "sslContext");
        this.faultToleranceConfig = Objects.requireNonNull(faultToleranceConfig, "faultToleranceConfig");
        this.jwtAlgorithm = jwtAlgorithm != null ? jwtAlgorithm : DEFAULT_JWT_ALGORITHM;
        // Valida o algoritmo contra a allowlist (rejeita none, HS256, etc.)
        SigningStrategyFactory.jwtAlgorithmToJava(this.jwtAlgorithm);
        this.keyId = keyId;
        if (hubCtxIg != null || hubCtxVersao != null) {
            validateHubContext(hubCtxIg, hubCtxVersao);
        }
        this.hubCtxIg = hubCtxIg;
        this.hubCtxVersao = hubCtxVersao;
        this.errorClassifier = new ErrorClassifier(this.clientId, this.tokenEndpoint);
        this.tokenCache = new TokenCacheStrategy(enableTokenCache,
                tokenCacheMarginSeconds > 0
                        ? tokenCacheMarginSeconds
                        : DEFAULT_TOKEN_CACHE_MARGIN_SECONDS,
                this.clientId,
                tokenCacheMaxEntries);
        if (certificate != null) {
            SslContextFactory.checkCertificateValidity(certificate,
                    certificate.getSubjectX500Principal().getName());
            KeyCertificateConsistency.verifyStrategy(this.signingStrategy, certificate);
        }
        this.httpClient = HttpClient.newBuilder()
                .sslContext(context)
                .connectTimeout(faultToleranceConfig.connectTimeout())
                .build();
        LOG.debug("SmartTokenClient inicializado para clientId={} endpoint={} cache={} maxRetries={} alg={}",
                clientId, tokenEndpoint, enableTokenCache, faultToleranceConfig.maxRetries(), this.jwtAlgorithm);
    }

    /**
     * Construtor de compatibilidade (sem contexto de IG).
     *
     * @param tokenEndpoint           URL do endpoint /auth/token
     * @param clientId                identificador do cliente
     * @param signingStrategy         estratégia de assinatura JWT
     * @param certificate             certificado X.509 do cliente
     * @param sslContext              contexto SSL para o {@link HttpClient}
     * @param faultToleranceConfig    configuração de resiliência
     * @param enableTokenCache        se {@code true}, habilita cache de tokens
     * @param tokenCacheMarginSeconds margem em segundos antes da expiração
     * @param jwtAlgorithm            algoritmo JWT (ex: RS384, ES384)
     * @param keyId                   identificador da chave ({@code kid} do
     *                                header JWT); {@code null} para omitir
     */
    @SuppressWarnings({"checkstyle:ParameterNumber", "PMD.ExcessiveParameterList"})
    public SmartTokenClient(
        String tokenEndpoint,
        String clientId,
        SigningStrategy signingStrategy,
        @Nullable X509Certificate certificate,
        SSLContext sslContext,
        FaultToleranceConfig faultToleranceConfig,
        boolean enableTokenCache,
        int tokenCacheMarginSeconds,
        @Nullable String jwtAlgorithm,
        @Nullable String keyId
    ) {
        this(tokenEndpoint, clientId, signingStrategy, certificate, sslContext,
                faultToleranceConfig, enableTokenCache, tokenCacheMarginSeconds,
                jwtAlgorithm, keyId, null, null);
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
     * @param jwtAlgorithm            algoritmo JWT (ex: RS384, ES384)
     */
    @SuppressWarnings({"checkstyle:ParameterNumber", "PMD.ExcessiveParameterList"})
    public SmartTokenClient(
        String tokenEndpoint,
        String clientId,
        SigningStrategy signingStrategy,
        @Nullable X509Certificate certificate,
        SSLContext sslContext,
        FaultToleranceConfig faultToleranceConfig,
        boolean enableTokenCache,
        int tokenCacheMarginSeconds,
        @Nullable String jwtAlgorithm
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
        @Nullable X509Certificate certificate,
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
     * Valida o par de valores do claim {@code hub_ctx} contra os formatos do
     * concern client-assertion-contexto-ig.md §3.4: {@code ig} segue
     * {@code [a-z][a-z0-9-]{1,30}} e {@code versao} é SemVer completo
     * {@code MAJOR.MINOR.PATCH} (sem pre-release/build).
     *
     * @param ig     alias do Guia de Implementação
     * @param versao versão SemVer do Guia de Implementação
     * @throws IllegalArgumentException se qualquer valor for nulo ou não
     *                                  seguir o formato exigido
     */
    static void validateHubContext(final @Nullable String ig, final @Nullable String versao) {
        if (ig == null || !HUB_CTX_IG_PATTERN.matcher(ig).matches()) {
            throw new IllegalArgumentException(
                    "hub_ctx.ig inválido: '" + ig + "' (use minúsculas, dígitos e hífen,"
                            + " iniciando por letra, 2 a 31 caracteres)");
        }
        if (versao == null || !HUB_CTX_VERSAO_PATTERN.matcher(versao).matches()) {
            throw new IllegalArgumentException(
                    "hub_ctx.versao inválido: '" + versao
                            + "' (use SemVer completo MAJOR.MINOR.PATCH, ex.: 0.0.1)");
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
    public String obtainToken(final @Nullable String scope) throws IOException, InterruptedException {
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
    public TokenResponse obtainTokenResponse(final @Nullable String scope)
            throws IOException, InterruptedException {
        final Lock operationLock = lifecycleLock.readLock();
        operationLock.lock();
        try {
            ensureOpen();
            final String normalizedScope = scope == null ? "" : scope.trim();

            final TokenResponse early = tokenCache.cachedResponseIfValid(normalizedScope);
            if (early != null) {
                return early;
            }
            return fetchTokenWithRetry(normalizedScope);
        } finally {
            operationLock.unlock();
        }
    }

    /**
     * Executa o laço de tentativas com single-flight por scope: adquire o
     * lock do scope, faz double-check do cache e realiza a requisição HTTP;
     * entre tentativas aplica o backoff FORA da seção crítica.
     *
     * <p>O lock é adquirido por tentativa e liberado antes do backoff, de
     * modo que a espera entre tentativas NÃO ocorre em seção crítica. A
     * garantia de single-flight vale por tentativa: apenas uma thread
     * executa a requisição HTTP de um scope por vez; entre tentativas,
     * outra thread pode adquirir o lock, mas o double-check do cache evita
     * requisições redundantes quando o token já foi renovado. Scopes
     * distintos podem compartilhar o mesmo lock (ver
     * {@link #scopeLockFor(String)}), sem afetar a correção.</p>
     *
     * @param normalizedScope scope normalizado
     * @return resposta do token endpoint
     * @throws IOException          em caso de erro de I/O não retriável
     * @throws InterruptedException se a thread for interrompida no backoff
     * @throws SmartTokenException  quando todas as tentativas falham
     */
    private TokenResponse fetchTokenWithRetry(final String normalizedScope)
            throws IOException, InterruptedException {
        final ReentrantLock lock = scopeLockFor(normalizedScope);
        LOG.debug("Iniciando obtenção de token para clientId={} scope={}", clientId, normalizedScope);

        final int maxRetries = faultToleranceConfig.maxRetries();
        IOException lastException = null;
        TraceContext lastTrace = null;
        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            // Novo contexto de trace W3C por tentativa: cada requisição HTTP
            // (inclusive retries) carrega um par trace-id/span-id próprio.
            final TraceContext trace = TraceContext.generate();
            lastTrace = trace;
            lock.lock();
            try {
                final TokenResponse cached = tokenCache.cachedResponseIfValid(normalizedScope);
                if (cached != null) {
                    return cached;
                }
                return doObtainToken(normalizedScope, trace);
            } catch (IOException ex) {
                // Lança SmartTokenException/IOException se não retriável
                lastException = errorClassifier.retriableOrRethrow(ex, trace);
            } finally {
                lock.unlock();
            }
            waitBeforeNextAttempt(attempt, maxRetries, lastException, trace);
        }
        throw new SmartTokenException(
                "Falha após " + maxRetries + " tentativas (último traceId="
                        + (lastTrace != null ? lastTrace.traceId() : "n/d") + "): "
                        + (lastException != null ? lastException.getMessage() : "sem causa capturada"),
                lastException);
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
     * @param trace         contexto de trace W3C enviado na tentativa que falhou
     * @throws InterruptedException se a thread for interrompida no sleep
     */
    private void waitBeforeNextAttempt(
            final int attempt, final int maxRetries, final @Nullable IOException lastException,
            final TraceContext trace)
            throws InterruptedException {
        if (attempt >= maxRetries) {
            LOG.error("Todas as {} tentativas falharam para clientId={} traceId={}",
                    maxRetries, clientId, trace.traceId());
            return;
        }
        final long delayMs = RetryPolicy.computeRetryDelayMs(attempt);
        LOG.warn("Tentativa {}/{} falhou para clientId={} traceId={}: {}. Retry em {}ms",
                attempt, maxRetries, clientId, trace.traceId(),
                lastException != null ? lastException.getMessage() : "sem causa capturada", delayMs);
        sleeper.sleep(delayMs);
    }

    /**
     * Retorna o lock associado ao scope, delegando ao striping do
     * {@link TokenCacheStrategy}: o mesmo scope sempre mapeia para o mesmo
     * lock, preservando o single-flight por scope; scopes distintos podem
     * compartilhar um lock. Visibilidade package-private para testes.
     */
    ReentrantLock scopeLockFor(final String scope) {
        return tokenCache.lockFor(scope);
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
        tokenCache.invalidateAll();
    }

    /**
     * Invalida o cache para um scope específico.
     *
     * @param scope scope cujo token deve ser invalidado
     */
    public void invalidateCache(final @Nullable String scope) {
        final String normalizedScope = scope == null ? "" : scope.trim();
        tokenCache.invalidate(normalizedScope);
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
    public @Nullable String getKeyId() {
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
        final Lock closeLock = lifecycleLock.writeLock();
        closeLock.lock();
        try {
            if (closed.compareAndSet(false, true)) {
                try {
                    httpClient.close();
                } finally {
                    tokenCache.invalidateAll();
                }
                LOG.debug("SmartTokenClient fechado para clientId={}", clientId);
            }
        } finally {
            closeLock.unlock();
        }
    }

    private void ensureOpen() {
        if (closed.get()) {
            throw new IllegalStateException("SmartTokenClient já foi fechado");
        }
    }

    /** Retorna o tamanho do cache para testes determinísticos de lifecycle. */
    int tokenCacheSize() {
        return tokenCache.size();
    }

    /**
     * Executa a requisição HTTP ao token endpoint com o contexto de trace
     * W3C informado (header {@code traceparent}) e trata a resposta.
     *
     * @param scope scopes normalizados
     * @param trace contexto de trace W3C desta requisição
     * @return resposta do token endpoint
     * @throws IOException          em caso de erro de I/O na comunicação
     * @throws InterruptedException se a thread for interrompida
     */
    private TokenResponse doObtainToken(final String scope, final TraceContext trace)
            throws IOException, InterruptedException {
        final String assertion = buildClientAssertion();
        final String body = buildFormBody(clientId, assertion, scope);

        final HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(tokenEndpoint))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header(TraceContext.TRACEPARENT_HEADER, trace.traceparent())
                .timeout(faultToleranceConfig.requestTimeout())
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        LOG.trace("Enviando requisição POST para {} traceId={}", tokenEndpoint, trace.traceId());
        final HttpResponse<String> response;
        try {
            response = httpClient.send(request,
                    TokenResponseGuard.boundedStringBodyHandler(TokenResponseGuard.MAX_RESPONSE_BODY_BYTES));
        } catch (IOException ex) {
            throw TokenResponseGuard.unwrapBodyLimitViolation(ex);
        }

        final int statusCode = response.statusCode();
        if (statusCode != HTTP_OK) {
            throw errorClassifier.httpFailure(response, trace);
        }

        final TokenResponse tokenResponse = parseTokenResponse(response.body());
        tokenCache.store(scope, tokenResponse);

        LOG.info("Token obtido com sucesso para clientId={}", clientId);
        return tokenResponse;
    }

    /**
     * Constrói o JWT client_assertion assinado com o algoritmo configurado.
     *
     * @return JWT compacto pronto para uso no campo client_assertion
     */
    @SuppressWarnings({"PMD.UseConcurrentHashMap", "checkstyle:MethodLength"})
    // Construção do JWS (RFC 7523) ponta a ponta: claims, header e
    // assinatura em sequência auditável — dividir dificultaria a revisão.
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
        if (hubCtxIg != null && hubCtxVersao != null) {
            // Claim de contexto do HubSaúde: IG e versão pretendidos
            // (concern client-assertion-contexto-ig.md §3.4)
            final Map<String, Object> hubCtx = new LinkedHashMap<>();
            hubCtx.put("ig", hubCtxIg);
            hubCtx.put("versao", hubCtxVersao);
            claims.put("hub_ctx", hubCtx);
        }

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
    public static String buildFormBody(
            final String clientId, final String assertion, final @Nullable String scope) {
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
     * Faz o parse completo da resposta do token endpoint, aplicando a
     * política de sanidade de {@code expires_in} descrita em
     * {@link TokenResponseGuard#sanitizeExpiresIn(JsonNode)}.
     *
     * @param jsonBody corpo JSON da resposta
     * @return objeto com access_token e expires_in saneado
     * @throws IOException em caso de erro de parse
     */
    static TokenResponse parseTokenResponse(final String jsonBody) throws IOException {
        final JsonNode node = OBJECT_MAPPER.readTree(jsonBody);
        if (!node.has("access_token")) {
            throw new SmartTokenException("Resposta não contém 'access_token'");
        }
        final String accessToken = node.get("access_token").asString();
        final int expiresIn = TokenResponseGuard.sanitizeExpiresIn(node);
        return new TokenResponse(accessToken, expiresIn, jsonBody);
    }

    /**
     * Validação fail-fast de consistência entre chave privada e certificado.
     *
     * <p>
     * Realiza uma assinatura de teste com a chave privada e a verifica com a
     * chave pública extraída do certificado, detectando erros de configuração
     * (arquivos trocados, chave corrompida, certificado regenerado) na
     * inicialização — antes de qualquer tentativa de obter tokens. Executada
     * automaticamente na construção do {@link SmartTokenClient} quando são
     * fornecidos {@link PrivateKey} e {@link X509Certificate} diretamente.
     * </p>
     *
     * @param privateKey  chave privada a validar
     * @param certificate certificado X.509 contendo a chave pública correspondente
     * @throws SmartTokenException se a assinatura de teste falhar, indicando
     *                             que chave e certificado não formam um par válido
     */
    public static void verifyKeyPairConsistency(
            final PrivateKey privateKey,
            final X509Certificate certificate) {
        KeyCertificateConsistency.verifyKeyPair(privateKey, certificate);
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
            final @Nullable Path serverTrustAnchor,
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
     * Representa a resposta do token endpoint.
     *
     * @param accessToken token de acesso emitido
     * @param expiresIn   validade do token em segundos
     * @param rawJson     corpo JSON cru da resposta do servidor de autorização;
     *                    {@code null} quando o token é servido a partir do cache
     */
    public record TokenResponse(String accessToken, int expiresIn, @Nullable String rawJson) {

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
