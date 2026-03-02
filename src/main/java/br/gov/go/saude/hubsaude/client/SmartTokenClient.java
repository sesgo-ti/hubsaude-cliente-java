/*
 * Copyright (c) 2026 SES-GO / UFG
 * Todos os direitos reservados.
 */

package br.gov.go.saude.hubsaude.simulador.client;

import io.jsonwebtoken.Jwts;
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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;
import java.util.Objects;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
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
 * Destinada ao uso em testes de integração com Testcontainers e exemplos
 * no README, evitando boilerplate criptográfico nos casos de teste.
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
 *         .build();
 * }</pre>
 */
public class SmartTokenClient {

    private static final Logger LOG = LoggerFactory.getLogger(SmartTokenClient.class);

    private static final String GRANT_TYPE = "client_credentials";
    private static final String ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    /** TTL padrão do client_assertion em segundos. */
    public static final int DEFAULT_ASSERTION_TTL_SECONDS = 60;

    /** Timeout padrão de conexão. */
    public static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(10);

    /** Timeout padrão de requisição. */
    public static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(30);

    private final String tokenEndpoint;
    private final String clientId;
    private final PrivateKey privateKey;
    private final HttpClient httpClient;
    private final int assertionTtlSeconds;
    private final Duration requestTimeout;

    /**
     * Cria o cliente carregando chave privada e certificado de arquivos PEM.
     *
     * @param tokenEndpoint  URL do endpoint /auth/token do simulador
     * @param clientId       identificador do cliente registrado
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
                loadPrivateKey(privateKeyPem),
                validateCertificate(certificatePem),
                buildSslContext(null),
                DEFAULT_CONNECT_TIMEOUT,
                DEFAULT_REQUEST_TIMEOUT,
                DEFAULT_ASSERTION_TTL_SECONDS);
    }

    /**
     * Versão avançada que aceita um certificado público do servidor para ser
     * utilizado como trust anchor, evitando o uso de SSL permissivo quando o
     * chamador possui a cadeia correta.
     *
     * @param tokenEndpoint        URL do endpoint /auth/token do simulador
     * @param clientId             identificador do cliente registrado
     * @param privateKeyPem        caminho para o arquivo PEM da chave privada
     * @param certificatePem       caminho para o arquivo PEM do certificado do
     *                             cliente
     * @param serverCertificatePem certificado X.509 confiável do servidor; quando
     *                             {@code null}, usa-se SSL permissivo para testes
     */
    public SmartTokenClient(
            final String tokenEndpoint,
            final String clientId,
            final Path privateKeyPem,
            final Path certificatePem,
            final Path serverCertificatePem) throws IOException {
        this(tokenEndpoint,
                clientId,
                loadPrivateKey(privateKeyPem),
                validateCertificate(certificatePem),
                buildSslContext(serverCertificatePem),
                DEFAULT_CONNECT_TIMEOUT,
                DEFAULT_REQUEST_TIMEOUT,
                DEFAULT_ASSERTION_TTL_SECONDS);
    }

    /**
     * Construtor de baixo nível para cenários em que os artefatos criptográficos
     * já foram carregados (ex: Vault, Secret Manager).
     *
     * @param tokenEndpoint URL do endpoint /auth/token do simulador
     * @param clientId      identificador do cliente registrado
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
                DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT, DEFAULT_ASSERTION_TTL_SECONDS);
    }

    /**
     * Construtor completo com todas as configurações disponíveis.
     *
     * @param tokenEndpoint      URL do endpoint /auth/token do simulador
     * @param clientId           identificador do cliente registrado
     * @param privateKey         chave privada previamente carregada
     * @param certificate        certificado X.509 correspondente à chave
     * @param sslContext         contexto SSL a ser utilizado pelo {@link HttpClient}
     * @param connectTimeout     timeout de conexão
     * @param requestTimeout     timeout de requisição HTTP
     * @param assertionTtlSeconds TTL do client_assertion em segundos
     */
    public SmartTokenClient(
            final String tokenEndpoint,
            final String clientId,
            final PrivateKey privateKey,
            final X509Certificate certificate,
            final SSLContext sslContext,
            final Duration connectTimeout,
            final Duration requestTimeout,
            final int assertionTtlSeconds) {
        this.tokenEndpoint = Objects.requireNonNull(tokenEndpoint, "tokenEndpoint");
        this.clientId = Objects.requireNonNull(clientId, "clientId");
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey");
        Objects.requireNonNull(certificate, "certificate");
        final SSLContext context = Objects.requireNonNull(sslContext, "sslContext");
        final Duration connTimeout = Objects.requireNonNull(connectTimeout, "connectTimeout");
        this.requestTimeout = Objects.requireNonNull(requestTimeout, "requestTimeout");
        this.assertionTtlSeconds = assertionTtlSeconds > 0 ? assertionTtlSeconds : DEFAULT_ASSERTION_TTL_SECONDS;

        verifyKeyPairConsistency(privateKey, certificate);

        this.httpClient = HttpClient.newBuilder()
                .sslContext(context)
                .connectTimeout(connTimeout)
                .build();

        LOG.debug("SmartTokenClient inicializado para clientId={} endpoint={}", clientId, tokenEndpoint);
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
     * @param scope scopes separados por espaço (ex: {@code "system/Patient.rs"})
     * @return access token JWT emitido pelo simulador
     * @throws IOException          em caso de erro de I/O na comunicação
     * @throws InterruptedException se a thread for interrompida durante a requisição
     * @throws SmartTokenException  se o servidor retornar erro ou resposta inválida
     */
    public String obtainToken(final String scope) throws IOException, InterruptedException {
        LOG.debug("Iniciando obtenção de token para clientId={} scope={}", clientId, scope);

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

        if (response.statusCode() != 200) {
            LOG.error("Falha ao obter token: HTTP {} — {}", response.statusCode(), response.body());
            throw new SmartTokenException(
                    "Falha ao obter token: HTTP " + response.statusCode() + " — " + response.body());
        }

        final String accessToken = extractAccessToken(response.body());
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
        final String jti = UUID.randomUUID().toString();
        LOG.trace("Construindo client_assertion jti={} ttl={}s", jti, assertionTtlSeconds);
        return Jwts.builder()
                .issuer(clientId)
                .subject(clientId)
                .audience().add(tokenEndpoint).and()
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(assertionTtlSeconds)))
                .id(jti)
                .signWith(privateKey, Jwts.SIG.RS384)
                .compact();
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
        final StringBuilder sb = new StringBuilder(128)
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
        final var mapper = new ObjectMapper();
        final var node = mapper.readTree(jsonBody);
        if (!node.has("access_token")) {
            throw new SmartTokenException("Resposta não contém 'access_token': " + jsonBody);
        }
        return node.get("access_token").asText();
    }

    /**
     * Converte um arquivo PEM (PKCS#1 ou PKCS#8) em {@link PrivateKey}, aceitando
     * chaves RSA geradas para o simulador.
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
     * @throws IOException quando o arquivo não pode ser lido
     * @return certificado X.509 decodificado
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

    private static SSLContext buildSslContext(final Path serverCertificatePem) {
        if (serverCertificatePem == null) {
            return buildTrustAllSslContext();
        }
        try {
            final X509Certificate trustedCert = validateCertificate(serverCertificatePem);
            final KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);
            trustStore.setCertificateEntry("trusted-server", trustedCert);

            final TrustManagerFactory tmf = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            final SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, tmf.getTrustManagers(), new SecureRandom());
            return ctx;
        } catch (SmartTokenException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new SmartTokenException("Falha ao construir SSLContext customizado: " + ex.getMessage(), ex);
        }
    }

    /**
     * Verifica se a chave privada corresponde ao certificado X.509,
     * realizando uma assinatura de teste e validando com a chave pública.
     *
     * @param privateKey  chave privada a validar
     * @param certificate certificado contendo a chave pública
     * @throws SmartTokenException se as chaves não corresponderem
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
     * <strong>Uso exclusivo para testes com o simulador local.</strong>
     * Nunca utilizar em ambiente de produção.
     * </p>
     *
     * @return contexto SSL que aceita qualquer certificado
     */
    public static SSLContext buildTrustAllSslContext() {
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
            final SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, trustAll, new SecureRandom());
            return ctx;
        } catch (Exception ex) {
            throw new IllegalStateException("Falha ao criar SSLContext trust-all", ex);
        }
    }

    /**
     * Builder fluente para construção de instâncias de {@link SmartTokenClient}.
     *
     * <p>
     * Permite configurar timeouts, TTL do assertion e demais parâmetros
     * de forma legível e segura.
     * </p>
     */
    public static final class Builder {
        private String tokenEndpoint;
        private String clientId;
        private Path privateKeyPem;
        private Path certificatePem;
        private Path serverCertificatePem;
        private Duration connectTimeout = DEFAULT_CONNECT_TIMEOUT;
        private Duration requestTimeout = DEFAULT_REQUEST_TIMEOUT;
        private int assertionTtlSeconds = DEFAULT_ASSERTION_TTL_SECONDS;

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
         * @param clientId identificador registrado no servidor
         * @return este builder
         */
        public Builder clientId(final String clientId) {
            this.clientId = clientId;
            return this;
        }

        /**
         * Define o caminho para o arquivo PEM da chave privada.
         *
         * @param privateKeyPem caminho absoluto
         * @return este builder
         */
        public Builder privateKeyPem(final Path privateKeyPem) {
            this.privateKeyPem = privateKeyPem;
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
         * @param serverCertificatePem caminho absoluto; null usa trust-all
         * @return este builder
         */
        public Builder serverCertificatePem(final Path serverCertificatePem) {
            this.serverCertificatePem = serverCertificatePem;
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
         * Constrói a instância de {@link SmartTokenClient}.
         *
         * @return cliente configurado
         * @throws IOException se os arquivos PEM não puderem ser lidos
         */
        public SmartTokenClient build() throws IOException {
            Objects.requireNonNull(tokenEndpoint, "tokenEndpoint é obrigatório");
            Objects.requireNonNull(clientId, "clientId é obrigatório");
            Objects.requireNonNull(privateKeyPem, "privateKeyPem é obrigatório");
            Objects.requireNonNull(certificatePem, "certificatePem é obrigatório");

            return new SmartTokenClient(
                    tokenEndpoint,
                    clientId,
                    loadPrivateKey(privateKeyPem),
                    validateCertificate(certificatePem),
                    buildSslContext(serverCertificatePem),
                    connectTimeout,
                    requestTimeout,
                    assertionTtlSeconds);
        }
    }
}