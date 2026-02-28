package br.gov.go.saude.hubsaude.simulador.client;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Testes unitários do SmartTokenClient.
 *
 * <p>
 * Gera par RSA real para validar a montagem do client_assertion sem
 * necessidade de subir o servidor.
 * </p>
 */
class SmartTokenClientTest {

        private static final String TOKEN_ENDPOINT = "https://localhost:8443/auth/token";
        private static final String CLIENT_ID = "test-client";

        private static Path keyFile;
        private static Path certFile;
        private static RSAPublicKey publicKey;

        @BeforeAll
        static void gerarParChaves(@TempDir final Path tempDir) throws Exception {
                final KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
                gen.initialize(2048);
                final KeyPair pair = gen.generateKeyPair();
                publicKey = (RSAPublicKey) pair.getPublic();

                // Escrever chave privada PEM
                keyFile = tempDir.resolve("client-key.pem");
                final String pkcs8Pem = toPkcs8Pem(pair.getPrivate().getEncoded());
                Files.writeString(keyFile, pkcs8Pem, StandardCharsets.UTF_8);

                // Escrever certificado auto-assinado PEM (stub mínimo para satisfazer o
                // construtor)
                certFile = tempDir.resolve("client-cert.pem");
                final String certPem = generateSelfSignedCertPem(pair);
                Files.writeString(certFile, certPem, StandardCharsets.UTF_8);
        }

        @Test
        void deveConstruirClientAssertionComCamposCorretos() throws Exception {
                final SmartTokenClient client = new SmartTokenClient(TOKEN_ENDPOINT, CLIENT_ID, keyFile, certFile);

                final String assertion = client.buildClientAssertion();

                final Claims claims = Jwts.parser()
                                .verifyWith(publicKey)
                                .build()
                                .parseSignedClaims(assertion)
                                .getPayload();

                assertThat(claims.getSubject()).isEqualTo(CLIENT_ID);
                assertThat(claims.getIssuer()).isEqualTo(CLIENT_ID);
                assertThat(claims.getAudience()).containsExactly(TOKEN_ENDPOINT);
                assertThat(claims.getId()).isNotBlank();
                assertThat(claims.getExpiration()).isAfter(claims.getIssuedAt());
        }

        @Test
        void deveFalharComArquivoChaveInexistente(@TempDir final Path tempDir) {
                assertThatThrownBy(() -> new SmartTokenClient(TOKEN_ENDPOINT, CLIENT_ID,
                                tempDir.resolve("nao-existe.pem"), certFile))
                                .isInstanceOf(Exception.class);
        }

        // ---------- helpers ----------

        private static String toPkcs8Pem(final byte[] encoded) {
                final String b64 = java.util.Base64.getMimeEncoder(64, "\n".getBytes())
                                .encodeToString(encoded);
                return "-----BEGIN PRIVATE KEY-----\n" + b64 + "\n-----END PRIVATE KEY-----\n";
        }

        /**
         * Gera certificado X.509 auto-assinado mínimo via BouncyCastle para o teste.
         */
        private static String generateSelfSignedCertPem(final KeyPair pair) throws Exception {
                final org.bouncycastle.asn1.x500.X500Name subject = new org.bouncycastle.asn1.x500.X500Name(
                                "CN=test-client,O=Test,C=BR");
                final java.math.BigInteger serial = java.math.BigInteger.ONE;
                final java.util.Date notBefore = new java.util.Date();
                final java.util.Date notAfter = new java.util.Date(
                                System.currentTimeMillis() + 365L * 24 * 3600 * 1000);

                final org.bouncycastle.cert.X509v3CertificateBuilder builder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                                subject, serial, notBefore, notAfter, subject, pair.getPublic());

                final org.bouncycastle.operator.ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(
                                "SHA256WithRSA")
                                .build(pair.getPrivate());

                final byte[] certDer = builder.build(signer).getEncoded();
                final String b64 = java.util.Base64.getMimeEncoder(64, "\n".getBytes())
                                .encodeToString(certDer);
                return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n";
        }
}
