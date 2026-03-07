/*
 * Copyright (c) 2026 SES-GO / UFG
 * Todos os direitos reservados.
 */

package br.gov.go.saude.hubsaude.client;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * Fábrica de {@link SSLContext} para o cliente HubSaúde.
 *
 * <p>
 * Centraliza toda a lógica de construção de contextos SSL/TLS e validação
 * de certificados X.509, mantendo a classe {@link SmartTokenClient} focada
 * na lógica de aquisição de tokens.
 * </p>
 *
 * <h2>Modos de operação</h2>
 * <ul>
 * <li><strong>Trust store da JVM:</strong> Usa
 * {@code $JAVA_HOME/lib/security/cacerts}
 * quando nenhum trust anchor é fornecido (comportamento seguro por padrão)</li>
 * <li><strong>Trust anchor específico:</strong> Aceita um certificado PEM do
 * servidor para validação TLS customizada</li>
 * </ul>
 *
 * @see SmartTokenClient
 * @see SmartTokenClientBuilder#serverTrustAnchor(Path)
 */
public final class SslContextFactory {

    /** Protocolo TLS padrão utilizado quando nenhum é especificado. */
    public static final String DEFAULT_TLS_PROTOCOL = "TLSv1.3";

    private SslContextFactory() {
        // Utility class
    }

    /**
     * Constrói um {@link SSLContext} configurado com o certificado do servidor.
     *
     * <p>
     * Quando {@code serverTrustAnchor} é {@code null}, utiliza o trust store padrão
     * da JVM ({@code $JAVA_HOME/lib/security/cacerts}), que é o comportamento
     * seguro
     * por padrão. Para ambientes de teste com certificados auto-assinados, utilize
     * {@link #buildTrustAllSslContext(String)} explicitamente.
     * </p>
     *
     * @param serverTrustAnchor certificado do servidor; se null, usa trust store
     *                          padrão da JVM
     * @param tlsProtocol       protocolo TLS (ex: "TLSv1.3", "TLSv1.2")
     * @return contexto SSL configurado
     * @throws SmartTokenException se o protocolo for inválido ou houver erro de
     *                             configuração
     */
    public static SSLContext buildSslContext(final Path serverTrustAnchor, final String tlsProtocol) {
        if (serverTrustAnchor == null) {
            try {
                return SSLContext.getDefault();
            } catch (NoSuchAlgorithmException ex) {
                throw new SmartTokenException("Falha ao obter SSLContext padrão da JVM", ex);
            }
        }
        try {
            final X509Certificate trustedCert = validateCertificate(serverTrustAnchor);
            return buildSslContext(trustedCert, tlsProtocol);
        } catch (SmartTokenException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new SmartTokenException("Falha ao construir SSLContext customizado: " + ex.getMessage(), ex);
        }
    }

    /**
     * Constrói um {@link SSLContext} configurado com o certificado X.509 fornecido.
     *
     * <p>
     * Este método permite construir um contexto SSL a partir de um certificado
     * já carregado em memória, útil para cenários onde o certificado foi obtido
     * dinamicamente (ex: extraído de uma conexão SSL).
     * </p>
     *
     * @param trustedCert certificado X.509 do servidor a ser confiado
     * @param tlsProtocol protocolo TLS (ex: "TLSv1.3", "TLSv1.2")
     * @return contexto SSL configurado para confiar no certificado fornecido
     * @throws SmartTokenException se o protocolo for inválido ou houver erro de
     *                             configuração
     */
    public static SSLContext buildSslContext(final X509Certificate trustedCert, final String tlsProtocol) {
        try {
            final KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);
            trustStore.setCertificateEntry("trusted-server", trustedCert);

            final TrustManagerFactory tmf = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            final SSLContext ctx = SSLContext.getInstance(tlsProtocol);
            ctx.init(null, tmf.getTrustManagers(), new SecureRandom());
            return ctx;
        } catch (Exception ex) {
            throw new SmartTokenException("Falha ao construir SSLContext: " + ex.getMessage(), ex);
        }
    }


    /**
     * Realiza um sanity check no certificado PEM associado ao cliente, garantindo
     * que seja um X.509 válido e dentro do período de validade antes de iniciar
     * o fluxo de autenticação.
     *
     * @param path caminho absoluto para o certificado PEM
     * @return certificado X.509 decodificado
     * @throws IOException         quando o arquivo não pode ser lido
     * @throws SmartTokenException quando o conteúdo não representa um
     *                             certificado X.509 válido ou está expirado
     */
    public static X509Certificate validateCertificate(final Path path) throws IOException {
        final String pem = Files.readString(path, StandardCharsets.UTF_8);
        PEMParser parser = new PEMParser(new StringReader(pem));
        return validateCertificate(path, parser);
    }

    static X509Certificate validateCertificate(Path path, PEMParser parser) throws IOException {
        try (parser) {
            final Object obj = parser.readObject();
            if (obj instanceof X509CertificateHolder holder) {
                final X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
                validateCertificate(path, cert);
                return cert;
            }
            throw new SmartTokenException("Arquivo PEM não contém certificado X.509: " + path);
        } catch (CertificateException ex) {
            throw new SmartTokenException("Falha ao converter certificado: " + ex.getMessage(), ex);
        }
    }

    static void validateCertificate(Path path, X509Certificate cert) {
        if (cert == null) {
            throw new SmartTokenException("Certificado inválido: " + path);
        }
        try {
            cert.checkValidity();
        } catch (CertificateExpiredException ex) {
            throw new SmartTokenException("Certificado expirado: " + path, ex);
        } catch (CertificateNotYetValidException ex) {
            throw new SmartTokenException("Certificado ainda não é válido: " + path, ex);
        }
    }
}
