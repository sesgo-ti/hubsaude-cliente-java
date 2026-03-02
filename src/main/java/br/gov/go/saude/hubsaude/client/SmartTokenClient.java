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
import java.security.cert.X509Certificate;
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
 */
public class SmartTokenClient {

    private static final String GRANT_TYPE = "client_credentials";
    private static final String ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private static final int ASSERTION_TTL_SECONDS = 60;

    private final String tokenEndpoint;
    private final String clientId;
    private final PrivateKey privateKey;
    private final HttpClient httpClient;

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
                buildSslContext(null));
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
                buildSslContext(serverCertificatePem));
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
        this.tokenEndpoint = Objects.requireNonNull(tokenEndpoint, "tokenEndpoint");
        this.clientId = Objects.requireNonNull(clientId, "clientId");
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey");
        Objects.requireNonNull(certificate, "certificate");
        final SSLContext context = Objects.requireNonNull(sslContext, "sslContext");
        this.httpClient = HttpClient.newBuilder()
                .sslContext(context)
                .build();
    }

    /**
     * Obtém um access token para os scopes informados.
     *
     * @param scope scopes separados por espaço (ex: {@code "system/Patient.rs"})
     * @return access token JWT emitido pelo simulador
     */
    public String obtainToken(final String scope) throws IOException, InterruptedException {
        final String assertion = buildClientAssertion();
        final String body = buildFormBody(assertion, scope);

        final HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(tokenEndpoint))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        final HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new SmartTokenException(
                    "Falha ao obter token: HTTP " + response.statusCode() + " — " + response.body());
        }

        return extractAccessToken(response.body());
    }

    /** Constrói o JWT client_assertion assinado com RS384. */
    String buildClientAssertion() {
        final Instant now = Instant.now();
        return Jwts.builder()
                .issuer(clientId)
                .subject(clientId)
                .audience().add(tokenEndpoint).and()
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(ASSERTION_TTL_SECONDS)))
                .id(UUID.randomUUID().toString())
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
     * Cria um {@link javax.net.ssl.SSLContext} que confia em todos os certificados.
     *
     * <p>
     * <strong>Uso exclusivo para testes com o simulador local.</strong>
     * Nunca utilizar em ambiente de produção.
     * </p>
     */
    /**
     * Constrói um SSLContext permissivo utilizado apenas em cenários de testes.
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

}