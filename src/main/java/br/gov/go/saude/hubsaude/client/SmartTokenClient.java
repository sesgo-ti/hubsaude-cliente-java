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
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

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
        this.tokenEndpoint = tokenEndpoint;
        this.clientId = clientId;
        this.privateKey = loadPrivateKey(privateKeyPem);
        this.httpClient = HttpClient.newBuilder()
                .sslContext(buildTrustAllSslContext())
                .build();
        // valida que o certificado é legível (opcional, falha rápida)
        loadCertificate(certificatePem);
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

    private String buildFormBody(final String assertion, final String scope) {
        final StringBuilder sb = new StringBuilder();
        sb.append("grant_type=").append(encode(GRANT_TYPE));
        sb.append("&client_assertion_type=").append(encode(ASSERTION_TYPE));
        sb.append("&client_assertion=").append(encode(assertion));
        if (scope != null && !scope.isBlank()) {
            sb.append("&scope=").append(encode(scope));
        }
        return sb.toString();
    }

    private String encode(final String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private String extractAccessToken(final String jsonBody) throws IOException {
        final var mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        final var node = mapper.readTree(jsonBody);
        if (!node.has("access_token")) {
            throw new SmartTokenException("Resposta não contém 'access_token': " + jsonBody);
        }
        return node.get("access_token").asText();
    }

    private PrivateKey loadPrivateKey(final Path path) throws IOException {
        final String pem = Files.readString(path, StandardCharsets.UTF_8);
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            final Object obj = parser.readObject();
            if (obj instanceof PEMKeyPair pemKeyPair) {
                return new JcaPEMKeyConverter().getKeyPair(pemKeyPair).getPrivate();
            } else if (obj instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo pki) {
                return new JcaPEMKeyConverter().getPrivateKey(pki);
            }
            throw new SmartTokenException("Arquivo PEM não contém chave privada válida: " + path);
        }
    }

    private void loadCertificate(final Path path) throws IOException {
        final String pem = Files.readString(path, StandardCharsets.UTF_8);
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            final Object obj = parser.readObject();
            if (obj instanceof X509CertificateHolder holder) {
                final X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
                if (cert == null) {
                    throw new SmartTokenException("Certificado inválido: " + path);
                }
                return;
            }
            throw new SmartTokenException("Arquivo PEM não contém certificado X.509: " + path);
        } catch (java.security.cert.CertificateException ex) {
            throw new SmartTokenException("Falha ao converter certificado: " + ex.getMessage());
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
    private static javax.net.ssl.SSLContext buildTrustAllSslContext() {
        try {
            final javax.net.ssl.TrustManager[] trustAll = {
                    new javax.net.ssl.X509TrustManager() {
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return new java.security.cert.X509Certificate[0];
                        }

                        public void checkClientTrusted(
                                final java.security.cert.X509Certificate[] c, final String a) {
                        }

                        public void checkServerTrusted(
                                final java.security.cert.X509Certificate[] c, final String a) {
                        }
                    }
            };
            final javax.net.ssl.SSLContext ctx = javax.net.ssl.SSLContext.getInstance("TLS");
            ctx.init(null, trustAll, new java.security.SecureRandom());
            return ctx;
        } catch (Exception ex) {
            throw new IllegalStateException("Falha ao criar SSLContext trust-all", ex);
        }
    }

    /** Exceção de domínio da classe de conveniência. */
    public static class SmartTokenException extends RuntimeException {
        public SmartTokenException(final String message) {
            super(message);
        }
    }
}