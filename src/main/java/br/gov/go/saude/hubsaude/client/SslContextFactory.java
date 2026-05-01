/*
 * Copyright (c) 2026 SES-GO / UFG
 * Todos os direitos reservados.
 */

package br.gov.go.saude.hubsaude.client;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;

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
// PMD.GodClass: TODO débito técnico — separar parsing PEM, KeyStore e
// construção do SSLContext em utilitários dedicados.
@SuppressWarnings({"checkstyle:OverloadMethodsDeclarationOrder",
        "PMD.GodClass"}) // grouped by PEM vs KeyStore use case
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
     * da JVM ({@code $JAVA_HOME/lib/security/cacerts}) com o protocolo TLS
     * especificado. Para ambientes de teste com certificados auto-assinados,
     * utilize {@code TestSslContextFactory.buildTrustAllSslContext()} (apenas em testes).
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
            // Sem trust anchor customizado: usa trust store da JVM mas respeita o protocolo
            try {
                final SSLContext ctx = SSLContext.getInstance(tlsProtocol);
                ctx.init(null, null, null); // null = trust store padrão da JVM
                return ctx;
            } catch (NoSuchAlgorithmException ex) {
                throw new SmartTokenException("Protocolo TLS não suportado: " + tlsProtocol, ex);
            } catch (Exception ex) {
                throw new SmartTokenException("Falha ao criar SSLContext com protocolo " + tlsProtocol, ex);
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
     * Constrói um {@link SSLContext} com suporte a mTLS (mutual TLS).
     *
     * <p>
     * Além da validação do servidor (TrustManager), configura a apresentação
     * do certificado do cliente durante o handshake TLS (KeyManager), habilitando
     * autenticação mútua quando o servidor a exige.
     * </p>
     *
     * <p>
     * Quando o servidor não solicita certificado do cliente (não envia
     * {@code CertificateRequest}), o KeyManager permanece inativo e a conexão
     * se comporta como TLS unidirecional — totalmente retrocompatível.
     * </p>
     *
     * @param serverTrustAnchor certificado do servidor; se null, usa trust store
     *                          padrão da JVM
     * @param tlsProtocol       protocolo TLS (ex: "TLSv1.3", "TLSv1.2")
     * @param clientKey         chave privada do cliente para mTLS
     * @param clientCert        certificado X.509 do cliente para mTLS
     * @return contexto SSL configurado com suporte a mTLS
     * @throws SmartTokenException se houver erro de configuração
     */
    public static SSLContext buildSslContext(
            final Path serverTrustAnchor,
            final String tlsProtocol,
            final PrivateKey clientKey,
            final X509Certificate clientCert) {
        final KeyManager[] keyManagers = buildKeyManagers(clientKey, clientCert);
        if (serverTrustAnchor == null) {
            try {
                final SSLContext ctx = SSLContext.getInstance(tlsProtocol);
                ctx.init(keyManagers, null, keyManagers != null ? new SecureRandom() : null);
                return ctx;
            } catch (NoSuchAlgorithmException ex) {
                throw new SmartTokenException("Protocolo TLS não suportado: " + tlsProtocol, ex);
            } catch (Exception ex) {
                throw new SmartTokenException(
                        "Falha ao criar SSLContext com mTLS: " + ex.getMessage(), ex);
            }
        }
        try {
            final X509Certificate trustedCert = validateCertificate(serverTrustAnchor);
            return buildSslContext(trustedCert, tlsProtocol, clientKey, clientCert);
        } catch (SmartTokenException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new SmartTokenException(
                    "Falha ao construir SSLContext com mTLS: " + ex.getMessage(), ex);
        }
    }

    /**
     * Constrói um {@link SSLContext} com suporte a mTLS a partir de um certificado
     * de servidor já carregado em memória.
     *
     * @param trustedCert certificado X.509 do servidor a ser confiado
     * @param tlsProtocol protocolo TLS (ex: "TLSv1.3", "TLSv1.2")
     * @param clientKey   chave privada do cliente para mTLS
     * @param clientCert  certificado X.509 do cliente para mTLS
     * @return contexto SSL configurado com mTLS
     * @throws SmartTokenException se houver erro de configuração
     */
    public static SSLContext buildSslContext(
            final X509Certificate trustedCert,
            final String tlsProtocol,
            final PrivateKey clientKey,
            final X509Certificate clientCert) {
        try {
            final KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);
            trustStore.setCertificateEntry("trusted-server", trustedCert);

            final TrustManagerFactory tmf = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            final SSLContext ctx = SSLContext.getInstance(tlsProtocol);
            ctx.init(buildKeyManagers(clientKey, clientCert),
                    tmf.getTrustManagers(), new SecureRandom());
            return ctx;
        } catch (Exception ex) {
            throw new SmartTokenException(
                    "Falha ao construir SSLContext com mTLS: " + ex.getMessage(), ex);
        }
    }

    /**
     * Constrói {@link KeyManager KeyManagers} para apresentação do certificado
     * do cliente durante o handshake TLS (mTLS).
     *
     * <p>
     * Retorna {@code null} quando {@code clientKey} ou {@code clientCert}
     * são {@code null}, resultando em TLS unidirecional (sem mTLS).
     * </p>
     *
     * @param clientKey  chave privada do cliente (pode ser null)
     * @param clientCert certificado X.509 do cliente (pode ser null)
     * @return array de KeyManagers configurados, ou {@code null} se
     *         não houver material para mTLS
     * @throws SmartTokenException se houver erro ao configurar o KeyStore
     */
    @SuppressWarnings("PMD.ReturnEmptyCollectionRatherThanNull")
    // null é semanticamente necessário para SSLContext.init()
    static KeyManager[] buildKeyManagers(
            final PrivateKey clientKey,
            final X509Certificate clientCert) {
        if (clientKey == null || clientCert == null) {
            return null;
        }
        try {
            final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setKeyEntry("client", clientKey, new char[0],
                    new X509Certificate[]{clientCert});

            final KeyManagerFactory kmf = KeyManagerFactory
                    .getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, new char[0]);
            return kmf.getKeyManagers();
        } catch (Exception ex) {
            throw new SmartTokenException(
                    "Falha ao configurar KeyManager para mTLS: " + ex.getMessage(), ex);
        }
    }

    /**
     * Constrói {@link KeyManager KeyManagers} a partir de um {@link KeyStore}
     * já carregado (PKCS#11, PKCS#12, JKS).
     *
     * <p>
     * Este overload é essencial para dispositivos criptográficos (smartcard,
     * USB token, HSM) onde a chave privada <strong>nunca sai do
     * hardware</strong>. O {@code KeyStore} do tipo {@code "PKCS11"} sabe
     * delegar operações ao dispositivo de forma transparente.
     * </p>
     *
     * @param keyStore   KeyStore já carregado (PKCS#11, PKCS#12, JKS)
     * @param keyAlias   alias da chave privada no KeyStore
     * @param keyPassword senha da chave (PIN para PKCS#11)
     * @return array de KeyManagers configurados
     * @throws SmartTokenException se houver erro ao configurar o KeyManager
     */
    @SuppressWarnings({"PMD.UseVarargs", "PMD.ReturnEmptyCollectionRatherThanNull"})
    // null é semanticamente necessário para SSLContext.init()
    static KeyManager[] buildKeyManagers(
            final KeyStore keyStore,
            final String keyAlias,
            final char[] keyPassword) {
        if (keyStore == null) {
            return null;
        }
        try {
            final KeyManagerFactory kmf = KeyManagerFactory
                    .getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, keyPassword);
            return kmf.getKeyManagers();
        } catch (Exception ex) {
            throw new SmartTokenException(
                    "Falha ao configurar KeyManager a partir de KeyStore: " + ex.getMessage(), ex);
        }
    }

    /**
     * Constrói um {@link SSLContext} com suporte a mTLS a partir de um
     * {@link KeyStore} já carregado.
     *
     * <p>
     * Indicado para dispositivos criptográficos (smartcard, USB token, HSM)
     * via PKCS#11, ou para KeyStores PKCS#12/JKS. A chave privada nunca
     * precisa ser extraída do dispositivo.
     * </p>
     *
     * @param serverTrustAnchor certificado do servidor; se null, usa trust store
     *                          padrão da JVM
     * @param tlsProtocol       protocolo TLS
     * @param clientKeyStore    KeyStore com a chave privada do cliente
     * @param keyAlias          alias da chave no KeyStore
     * @param keyPassword       senha/PIN da chave
     * @return contexto SSL configurado com mTLS
     * @throws SmartTokenException se houver erro de configuração
     */
    @SuppressWarnings("PMD.UseVarargs")
    public static SSLContext buildSslContext(
            final Path serverTrustAnchor,
            final String tlsProtocol,
            final KeyStore clientKeyStore,
            final String keyAlias,
            final char[] keyPassword) {
        final KeyManager[] keyManagers = buildKeyManagers(
                clientKeyStore, keyAlias, keyPassword);
        if (serverTrustAnchor == null) {
            try {
                final SSLContext ctx = SSLContext.getInstance(tlsProtocol);
                ctx.init(keyManagers, null,
                        keyManagers != null ? new SecureRandom() : null);
                return ctx;
            } catch (NoSuchAlgorithmException ex) {
                throw new SmartTokenException(
                        "Protocolo TLS não suportado: " + tlsProtocol, ex);
            } catch (Exception ex) {
                throw new SmartTokenException(
                        "Falha ao criar SSLContext com mTLS (KeyStore): "
                                + ex.getMessage(), ex);
            }
        }
        try {
            final X509Certificate trustedCert = validateCertificate(serverTrustAnchor);
            final KeyStore trustStore = KeyStore.getInstance(
                    KeyStore.getDefaultType());
            trustStore.load(null, null);
            trustStore.setCertificateEntry("trusted-server", trustedCert);

            final TrustManagerFactory tmf = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            final SSLContext ctx = SSLContext.getInstance(tlsProtocol);
            ctx.init(keyManagers, tmf.getTrustManagers(), new SecureRandom());
            return ctx;
        } catch (SmartTokenException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new SmartTokenException(
                    "Falha ao construir SSLContext com mTLS (KeyStore): "
                            + ex.getMessage(), ex);
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
