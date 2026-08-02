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
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Objects;

import javax.net.ssl.SSLContext;

import org.jspecify.annotations.Nullable;

/**
 * Builder para construção de instâncias de {@link SmartTokenClient}.
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
// Exceção inerente ao padrão Builder fluente com API pública congelada
// (biblioteca publicada): os métodos fluentes espelham os nomes dos campos
// (HiddenField) e a superfície de configuração documentada excede os limites
// de contagem de métodos (MethodCount/TooManyMethods). Justificativa
// registrada no concern docs/design/concerns/cliente.md (issue #1032).
@SuppressWarnings({ "checkstyle:HiddenField", "checkstyle:MethodCount",
    "PMD.TooManyMethods" })
public final class SmartTokenClientBuilder {

    private @Nullable String tokenEndpoint;
    private @Nullable String discoveryBaseUrl;
    private @Nullable String clientId;
    private @Nullable String hubCtxIg;
    private @Nullable String hubCtxVersao;
    private final SigningSettings signing = new SigningSettings();
    private final TlsSettings tls = new TlsSettings();
    private FaultToleranceConfig faultToleranceConfig = new FaultToleranceConfig(
        SmartTokenClient.DEFAULT_CONNECT_TIMEOUT,
        SmartTokenClient.DEFAULT_REQUEST_TIMEOUT,
        SmartTokenClient.DEFAULT_ASSERTION_TTL_SECONDS,
        SmartTokenClient.DEFAULT_MAX_RETRIES
    );
    // As opções do cache são mutáveis pelos métodos fluentes do builder.
    // Para evitar warnings, suprimimos a sugestão de torná-los finais.
    @SuppressWarnings({"PMD.ImmutableField", "java:S1104"})
    private boolean enableTokenCache = true;
    @SuppressWarnings({"PMD.ImmutableField", "java:S1104"})
    private int tokenCacheMarginSeconds = SmartTokenClient.DEFAULT_TOKEN_CACHE_MARGIN_SECONDS;
    @SuppressWarnings({"PMD.ImmutableField", "java:S1104"})
    private int tokenCacheMaxEntries = SmartTokenClient.DEFAULT_TOKEN_CACHE_MAX_ENTRIES;

    SmartTokenClientBuilder() {
        // Construtor package-private; instanciação via SmartTokenClient.builder().
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
        signing.setPrivateKeyPem(privateKeyPem);
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
     * <p>
     * O array <strong>não é copiado</strong> e é consumido por
     * {@link #build()}: após a construção (com sucesso ou erro), o
     * conteúdo é zerado para minimizar exposição do segredo em memória.
     * Forneça um novo array caso precise reconstruir o cliente.
     * </p>
     *
     * @param password senha da chave privada; zerada após {@link #build()}
     * @return este builder
     */
    @SuppressWarnings("PMD.UseVarargs") // char[] para senha é intencional - segurança
    public SmartTokenClientBuilder privateKeyPassword(final char[] password) {
        signing.setPrivateKeyPassword(password);
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
        signing.setSigningStrategy(signingStrategy);
        return this;
    }

    /**
     * Define o caminho para o arquivo PEM do certificado do cliente.
     *
     * @param certificatePem caminho absoluto
     * @return este builder
     */
    public SmartTokenClientBuilder certificatePem(final Path certificatePem) {
        tls.setCertificatePem(certificatePem);
        return this;
    }

    /**
     * Define o {@link KeyStore} do cliente para mTLS.
     *
     * <p>
     * Indicado para dispositivos criptográficos (smartcard, USB token, HSM)
     * via PKCS#11, ou para KeyStores PKCS#12/JKS. A chave privada é usada
     * pelo {@link javax.net.ssl.KeyManager} para apresentar o certificado
     * do cliente durante o handshake TLS, sem nunca extraí-la do dispositivo.
     * </p>
     *
     * <p>
     * Quando usado com {@link #signingStrategy(SigningStrategy)}, permite
     * que a mesma chave criptográfica seja utilizada tanto para assinatura
     * do JWT quanto para mTLS, mantendo o material no hardware.
     * </p>
     *
     * @param keyStore    KeyStore já carregado (PKCS#11, PKCS#12, JKS)
     * @param keyAlias    alias da chave privada no KeyStore
     * @param keyPassword senha/PIN da chave; o array não é copiado e é
     *                    zerado após {@link #build()} (sucesso ou erro)
     * @return este builder
     */
    @SuppressWarnings("PMD.UseVarargs")
    public SmartTokenClientBuilder clientKeyStore(
            final KeyStore keyStore,
            final String keyAlias,
            final char[] keyPassword) {
        tls.setClientKeyStore(keyStore, keyAlias, keyPassword);
        return this;
    }

    /**
     * Define o certificado do servidor para validação TLS customizada.
     *
     * @param serverTrustAnchor caminho absoluto; null usa trust store da JVM
     * @return este builder
     */
    public SmartTokenClientBuilder serverTrustAnchor(final @Nullable Path serverTrustAnchor) {
        tls.setServerTrustAnchor(serverTrustAnchor);
        return this;
    }

    /**
     * Define o certificado do servidor para validação TLS customizada (em memória).
     *
     * <p>
     * Use esta sobrecarga quando o certificado já estiver carregado em memória,
     * como em testes de integração que extraem o certificado dinamicamente.
     * </p>
     *
     * @param serverTrustAnchorCert certificado X.509; null usa trust store da JVM
     * @return este builder
     */
    public SmartTokenClientBuilder serverTrustAnchor(final @Nullable X509Certificate serverTrustAnchorCert) {
        tls.setServerTrustAnchorCert(serverTrustAnchorCert);
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
        tls.setTlsProtocol(tlsProtocol);
        return this;
    }

    /**
     * Define o algoritmo JWT para assinatura do client_assertion.
     *
     * <p>
     * O Servidor de Autorização do HubSaúde aceita apenas <strong>RS384</strong>
     * e <strong>ES384</strong> (concern client-assertion-contexto-ig.md §3.2).
     * Algoritmos suportados pelo SDK:
     * <ul>
     *   <li><strong>RS384</strong> (padrão) — RSA PKCS#1 v1.5 + SHA-384</li>
     *   <li><strong>ES384</strong> — ECDSA + SHA-384 (P-384)</li>
     *   <li>RS256, RS512, PS256, PS384, PS512, ES256 e ES512 — aceitos pelo
     *   SDK para uso com outros servidores de autorização, mas rejeitados
     *   pelo HubSaúde</li>
     * </ul>
     * </p>
     *
     * <p>
     * <strong>Nota:</strong> O algoritmo configurado define o valor do campo
     * {@code alg} no header do JWT e, quando a chave é carregada pelo próprio
     * builder ({@code privateKeyPem} ou {@code clientKeyStore}), também o
     * algoritmo criptográfico usado na assinatura. Quando uma
     * {@link SigningStrategy} própria é fornecida, ela deve ser compatível
     * com o algoritmo escolhido — se usar chave RSA com algoritmo ES*,
     * a assinatura falhará.
     * </p>
     *
     * @param jwtAlgorithm nome do algoritmo JWT (ex: RS384, ES384)
     * @return este builder
     */
    public SmartTokenClientBuilder jwtAlgorithm(final String jwtAlgorithm) {
        signing.setJwtAlgorithm(jwtAlgorithm);
        return this;
    }

    /**
     * Define o contexto de Guia de Implementação (claim {@code hub_ctx}) do
     * client_assertion.
     *
     * <p>
     * O claim {@code hub_ctx} declara o IG e a versão pretendidos na sessão
     * (concern client-assertion-contexto-ig.md §3.4). Quando não definido, o
     * claim é omitido — servidores que o exigem rejeitarão o assertion.
     * </p>
     *
     * @param ig     alias do Guia de Implementação (minúsculas, dígitos e
     *               hífen, iniciando por letra — ex.: {@code hemograma})
     * @param versao versão SemVer completa do IG ({@code MAJOR.MINOR.PATCH},
     *               sem pre-release — ex.: {@code 0.0.1})
     * @return este builder
     * @throws IllegalArgumentException se {@code ig} ou {@code versao} não
     *                                  seguirem o formato exigido
     */
    public SmartTokenClientBuilder hubContext(final String ig, final String versao) {
        SmartTokenClient.validateHubContext(ig, versao);
        this.hubCtxIg = ig;
        this.hubCtxVersao = versao;
        return this;
    }

    /**
     * Define o identificador da chave ({@code kid}) a incluir no header do
     * JWT client_assertion.
     *
     * <p>
     * O {@code kid} permite ao servidor de autorização selecionar a chave
     * pública correta (por exemplo, em um JWKS com múltiplas chaves) para
     * validar a assinatura do client_assertion. Opcional: quando não
     * definido, o header contém apenas {@code alg} e {@code typ}.
     * </p>
     *
     * @param keyId identificador da chave registrado junto ao servidor
     * @return este builder
     */
    public SmartTokenClientBuilder keyId(final String keyId) {
        signing.setKeyId(keyId);
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
        tls.setCustomSslContext(sslContext);
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
            faultToleranceConfig.requestTimeout(),
            faultToleranceConfig.assertionTtlSeconds(),
            faultToleranceConfig.maxRetries()
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
            faultToleranceConfig.connectTimeout(),
            requestTimeout,
            faultToleranceConfig.assertionTtlSeconds(),
            faultToleranceConfig.maxRetries()
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
            faultToleranceConfig.connectTimeout(),
            faultToleranceConfig.requestTimeout(),
            assertionTtlSeconds,
            faultToleranceConfig.maxRetries()
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
            faultToleranceConfig.connectTimeout(),
            faultToleranceConfig.requestTimeout(),
            faultToleranceConfig.assertionTtlSeconds(),
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
     * Define a quantidade máxima de scopes retidos no cache de tokens.
     *
     * @param tokenCacheMaxEntries teto positivo (padrão: 1.000)
     * @return este builder
     */
    public SmartTokenClientBuilder tokenCacheMaxEntries(final int tokenCacheMaxEntries) {
        this.tokenCacheMaxEntries = tokenCacheMaxEntries;
        return this;
    }

    /**
     * Constrói a instância de {@link SmartTokenClient}.
     *
     * <p>
     * As senhas fornecidas via {@link #privateKeyPassword(char[])} e
     * {@link #clientKeyStore(KeyStore, String, char[])} são consumidas:
     * os arrays são zerados e as referências descartadas ao final desta
     * chamada, em sucesso ou erro (minimiza exposição de segredos em
     * memória e evita retenção após a construção). Para construir outro
     * cliente, forneça as senhas novamente.
     * </p>
     *
     * @return cliente configurado
     * @throws IOException           se os arquivos PEM não puderem ser lidos
     * @throws IllegalStateException se nem privateKeyPem nem signingStrategy forem
     *                               definidos
     */
    public SmartTokenClient build() throws IOException {
        try {
            return doBuild();
        } finally {
            // Zera e descarta os segredos: o builder não os retém após build()
            signing.clearSecrets();
            tls.clearSecrets();
        }
    }

    /**
     * Lógica de construção propriamente dita; ver {@link #build()}.
     *
     * @return cliente configurado
     * @throws IOException se os arquivos PEM não puderem ser lidos
     */
    private SmartTokenClient doBuild() throws IOException {
        validateRequiredConfiguration();

        // === Carrega credenciais do cliente primeiro (necessário para mTLS) ===
        final SigningSettings.Resolved credentials = signing.resolve();

        // Certificado é opcional quando usando SigningStrategy diretamente
        final X509Certificate cert = tls.loadCertificate();

        // === Constrói SSLContext (com mTLS quando material está disponível) ===
        final SSLContext effectiveSslContext =
                tls.resolveSslContext(credentials.clientKey(), cert);

        // === Descobre token endpoint (usando SSLContext com mTLS) ===
        final String effectiveTokenEndpoint = resolveTokenEndpoint(effectiveSslContext);

        return new SmartTokenClient(
                effectiveTokenEndpoint,
                clientId,
                credentials.strategy(),
                cert,
                effectiveSslContext,
                faultToleranceConfig,
                enableTokenCache,
                tokenCacheMarginSeconds,
                tokenCacheMaxEntries,
                signing.getJwtAlgorithm(),
                signing.getKeyId(),
                hubCtxIg,
                hubCtxVersao);
    }

    /**
     * Valida a configuração obrigatória do builder: exclusividade mútua
     * entre {@code tokenEndpoint} e {@code fhirBase}, presença do
     * {@code clientId} e uso de https nas URLs informadas.
     *
     * @throws IllegalStateException    se a configuração de endpoints for
     *                                  inválida
     * @throws NullPointerException     se {@code clientId} não foi definido
     * @throws IllegalArgumentException se alguma URL não usar https
     */
    private void validateRequiredConfiguration() {
        if (tokenEndpoint != null && discoveryBaseUrl != null) {
            throw new IllegalStateException("Defina tokenEndpoint OU fhirBase, não ambos");
        }
        if (tokenEndpoint == null && discoveryBaseUrl == null) {
            throw new IllegalStateException("É obrigatório definir tokenEndpoint ou fhirBase");
        }
        Objects.requireNonNull(clientId, "clientId é obrigatório");
        if (tokenEndpoint != null) {
            SmartConfigurationDiscovery.requireHttps(tokenEndpoint, "tokenEndpoint");
        }
        if (discoveryBaseUrl != null) {
            SmartConfigurationDiscovery.requireHttps(discoveryBaseUrl, "fhirBase");
        }
    }

    /**
     * Resolve o token endpoint efetivo: o valor configurado diretamente ou,
     * na sua ausência, o descoberto via /.well-known/smart-configuration a
     * partir da URL base FHIR.
     *
     * @param sslContext contexto SSL a utilizar na descoberta
     * @return URL do token endpoint efetivo
     * @throws IOException em caso de erro de rede na descoberta
     */
    private String resolveTokenEndpoint(final SSLContext sslContext) throws IOException {
        if (tokenEndpoint != null) {
            return tokenEndpoint;
        }
        // discoveryBaseUrl garantidamente não nulo após a validação
        return SmartConfigurationDiscovery.discoverTokenEndpoint(
                discoveryBaseUrl,
                sslContext,
                faultToleranceConfig.connectTimeout(),
                faultToleranceConfig.requestTimeout());
    }

    /**
     * Descobre o token_endpoint consultando o /.well-known/smart-configuration
     * a partir de uma URL base FHIR.
     *
     * <p>
     * O valor retornado pelo servidor é validado: deve usar o esquema
     * {@code https} (exceção para {@code localhost}/{@code 127.0.0.1}),
     * evitando que um endpoint inseguro seja adotado silenciosamente.
     * </p>
     *
     * <p>
     * A requisição carrega um header {@code traceparent} (W3C Trace
     * Context) gerado localmente; em caso de falha, o trace-id integra a
     * mensagem de erro para correlação com a plataforma.
     * </p>
     *
     * @param fhirBaseUrl    URL base do servidor FHIR
     * @param sslContext     contexto SSL a ser utilizado
     * @param connectTimeout timeout de conexão HTTP
     * @param requestTimeout timeout de requisição HTTP
     * @return a URL do token_endpoint resolvida dinamicamente
     * @throws IOException em caso de erro de rede ou falha de protocolo
     * @throws IllegalArgumentException se o token_endpoint descoberto não
     *                                  usar https (fora de localhost)
     */
    public static String discoverTokenEndpoint(
            final String fhirBaseUrl,
            final SSLContext sslContext,
            final Duration connectTimeout,
            final Duration requestTimeout) throws IOException {
        return SmartConfigurationDiscovery.discoverTokenEndpoint(
                fhirBaseUrl, sslContext, connectTimeout, requestTimeout);
    }
}
