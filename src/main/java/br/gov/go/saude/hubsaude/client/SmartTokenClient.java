/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.hubsaude.client;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
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
 * <h2>Exemplo com builder</h2>
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
 * String accessToken = tokenClient.obtainToken("system/Patient.rs");
 * }</pre>
 *
 * <h2>Recursos enterprise</h2>
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
 * <p>A instância é thread-safe e deve ser mantida durante o ciclo de vida
 * da aplicação. O método {@link #close()} é idempotente, encerra o cliente
 * HTTP interno e invalida o cache; obtenções posteriores falham
 * explicitamente.</p>
 *
 * <p>Integrações com circuit breaker, métricas e contêineres de aplicação
 * pertencem à camada de orquestração. Consulte o guia de integração
 * enterprise para exemplos sem acoplar esta biblioteca a frameworks.</p>
 *
 * @see <a href=
 *      "https://github.com/sesgo-ti/hubsaude-cliente-java/blob/develop/docs/integracao-enterprise.md">
 *      Guia de integração enterprise</a>
 * @see <a href="https://www.w3.org/TR/trace-context/">W3C Trace Context</a>
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
     * Construtor interno usado exclusivamente pelo builder.
     *
     * <p>Centraliza as validações fail-fast da configuração e mantém a
     * construção pública restrita a {@link #builder()}.</p>
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
     * (arquivos trocados, chave corrompida, certificado regenerado) antes da
     * primeira tentativa de obter tokens. O builder executa verificação
     * equivalente quando recebe uma estratégia de assinatura e um certificado.
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
