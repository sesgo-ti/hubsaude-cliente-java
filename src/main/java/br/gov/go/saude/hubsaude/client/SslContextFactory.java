/*
 * Copyright (c) 2026 SES-GO / UFG
 * Todos os direitos reservados.
 */

package br.gov.go.saude.hubsaude.client;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

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
 * servidor
 * para validação TLS customizada</li>
 * <li><strong>Trust-all:</strong> Desabilita validação de certificados (⚠️
 * EXCLUSIVO
 * para testes)</li>
 * </ul>
 *
 * @see SmartTokenClient
 * @see SmartTokenClientBuilder#serverTrustAnchor(Path)
 */
public final class SslContextFactory {

    private static final Logger LOG = LoggerFactory.getLogger(SslContextFactory.class);

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
            } catch (java.security.NoSuchAlgorithmException ex) {
                throw new SmartTokenException("Falha ao obter SSLContext padrão da JVM", ex);
            }
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
     * Cria um {@link SSLContext} que confia em todos os certificados.
     *
     * <p>
     * <strong>⚠️ ATENÇÃO: USO EXCLUSIVO PARA TESTES E DESENVOLVIMENTO
     * LOCAL!</strong>
     * </p>
     *
     * <p>
     * Este método cria um contexto SSL que <strong>DESABILITA
     * COMPLETAMENTE</strong>
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
     * @see #buildSslContext(Path, String) para configuração segura com certificado
     *      específico
     */
    static SSLContext buildTrustAllSslContext(final String tlsProtocol) {
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
            throw new SmartTokenException("Falha ao criar SSLContext trust-all com protocolo '" + tlsProtocol + "'",
                    ex);
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
        return validateCertificate(path, pem);
    }

    static X509Certificate validateCertificate(Path path, String pem) throws IOException {
        PEMParser parser = new PEMParser(new StringReader(pem));
        return validateCertificate(path, parser);
    }

    static X509Certificate validateCertificate(Path path, PEMParser parser) throws IOException {
        try (parser) {
            final Object obj = parser.readObject();
            return validateCertificate(path, obj);
        } catch (CertificateException ex) {
            throw new SmartTokenException("Falha ao converter certificado: " + ex.getMessage(), ex);
        }
    }

    static X509Certificate validateCertificate(Path path, Object obj) throws CertificateException {
        if (obj instanceof X509CertificateHolder holder) {
            return validateCertificate(path, holder);
        }
        throw new SmartTokenException("Arquivo PEM não contém certificado X.509: " + path);
    }

    static X509Certificate validateCertificate(Path path, X509CertificateHolder holder) throws CertificateException {
        final X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
        if (cert == null) {
            throw new SmartTokenException("Certificado inválido: " + path);
        }
        validateCertificate(path, cert);
        return cert;
    }

    static void validateCertificate(Path path, X509Certificate cert) {
        try {
            cert.checkValidity();
        } catch (CertificateExpiredException ex) {
            throw new SmartTokenException("Certificado expirado: " + path, ex);
        } catch (CertificateNotYetValidException ex) {
            throw new SmartTokenException("Certificado ainda não é válido: " + path, ex);
        }
    }
}
