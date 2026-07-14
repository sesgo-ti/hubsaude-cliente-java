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
import java.io.StringReader;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Collections;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;

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
     * @throws SmartTokenException se o protocolo for inválido, o certificado
     *                             estiver fora do período de validade ou
     *                             houver erro de configuração
     */
    public static SSLContext buildSslContext(final X509Certificate trustedCert, final String tlsProtocol) {
        checkCertificateValidity(trustedCert, subjectOf(trustedCert));
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
     * @throws SmartTokenException se algum certificado estiver fora do
     *                             período de validade ou houver erro de
     *                             configuração
     */
    public static SSLContext buildSslContext(
            final X509Certificate trustedCert,
            final String tlsProtocol,
            final PrivateKey clientKey,
            final X509Certificate clientCert) {
        checkCertificateValidity(trustedCert, subjectOf(trustedCert));
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
        checkCertificateValidity(clientCert, subjectOf(clientCert));
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
     * <p>
     * Quando {@code keyAlias} não é nulo, o alias é validado de forma
     * fail-fast (deve existir e ser uma entrada de chave) e a sua seleção é
     * <strong>forçada</strong> durante o handshake TLS — essencial em
     * KeyStores com múltiplos aliases, nos quais o KeyManager padrão da JVM
     * escolheria a chave por conta própria, podendo apresentar o certificado
     * errado. Quando nulo, a escolha permanece a cargo do KeyManager padrão.
     * </p>
     *
     * @param keyStore   KeyStore já carregado (PKCS#11, PKCS#12, JKS)
     * @param keyAlias   alias da chave privada no KeyStore; se não nulo, sua
     *                   seleção é forçada no handshake; se nulo, vale a
     *                   escolha padrão do KeyManager
     * @param keyPassword senha da chave (PIN para PKCS#11); o array não é
     *                    modificado nem zerado por este método — a
     *                    zeroização é responsabilidade do chamador (ex.:
     *                    {@code SmartTokenClientBuilder.build()} consome as
     *                    senhas ao final)
     * @return array de KeyManagers configurados
     * @throws SmartTokenException se o alias não existir no KeyStore, não for
     *                             entrada de chave ou houver erro ao
     *                             configurar o KeyManager
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
            requireKeyEntry(keyStore, keyAlias);
            final KeyManagerFactory kmf = KeyManagerFactory
                    .getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, keyPassword);
            final KeyManager[] keyManagers = kmf.getKeyManagers();
            return keyAlias == null ? keyManagers : forceKeyAlias(keyManagers, keyAlias);
        } catch (SmartTokenException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new SmartTokenException(
                    "Falha ao configurar KeyManager a partir de KeyStore: " + ex.getMessage(), ex);
        }
    }

    /**
     * Valida, de forma fail-fast, que o alias corresponde a uma entrada de
     * chave privada existente no KeyStore.
     *
     * @param keyStore KeyStore já carregado
     * @param keyAlias alias a validar; nulo dispensa a validação
     * @throws KeyStoreException   se o KeyStore não estiver inicializado
     * @throws SmartTokenException se o alias não existir ou não for entrada
     *                             de chave privada
     */
    private static void requireKeyEntry(final KeyStore keyStore, final String keyAlias)
            throws KeyStoreException {
        if (keyAlias == null) {
            return;
        }
        if (!keyStore.containsAlias(keyAlias)) {
            throw new SmartTokenException(
                    "Alias '" + keyAlias + "' não existe no KeyStore; aliases disponíveis: "
                            + Collections.list(keyStore.aliases()));
        }
        if (!keyStore.isKeyEntry(keyAlias)) {
            throw new SmartTokenException(
                    "Alias '" + keyAlias + "' não é uma entrada de chave privada no KeyStore"
                            + " — informe o alias associado à chave do cliente");
        }
    }

    /**
     * Envolve cada {@link X509KeyManager} do array em um wrapper que força a
     * seleção do alias informado durante o handshake TLS.
     *
     * @param keyManagers KeyManagers originais
     * @param keyAlias    alias a ser apresentado no handshake
     * @return novo array com os wrappers aplicados
     */
    private static KeyManager[] forceKeyAlias(final KeyManager[] keyManagers, final String keyAlias) {
        final KeyManager[] wrapped = new KeyManager[keyManagers.length];
        for (int i = 0; i < keyManagers.length; i++) {
            wrapped[i] = keyManagers[i] instanceof X509KeyManager x509
                    ? new FixedAliasKeyManager(x509, keyAlias)
                    : keyManagers[i];
        }
        return wrapped;
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
     * @param keyAlias          alias da chave no KeyStore; se não nulo, sua
     *                          seleção é forçada no handshake (ver
     *                          {@link #buildKeyManagers(KeyStore, String, char[])})
     * @param keyPassword       senha/PIN da chave
     * @return contexto SSL configurado com mTLS
     * @throws SmartTokenException se o alias for inválido ou houver erro de
     *                             configuração
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
        final Object obj;
        try (parser) {
            obj = parser.readObject();
        }
        if (!(obj instanceof X509CertificateHolder holder)) {
            throw new SmartTokenException(
                    "Arquivo PEM não contém certificado X.509: " + path);
        }
        final X509Certificate cert = convertHolder(holder);
        validateCertificate(path, cert);
        return cert;
    }

    private static X509Certificate convertHolder(
            final X509CertificateHolder holder) {
        try {
            return new JcaX509CertificateConverter().getCertificate(holder);
        } catch (CertificateException ex) {
            throw new SmartTokenException(
                    "Falha ao converter certificado: " + ex.getMessage(), ex);
        }
    }

    static void validateCertificate(Path path, X509Certificate cert) {
        if (cert == null) {
            throw new SmartTokenException("Certificado inválido: " + path);
        }
        checkCertificateValidity(cert, String.valueOf(path));
    }

    /**
     * Verifica o período de validade do certificado (fail-fast, RF-11.4).
     *
     * <p>Aplicado em todos os pontos de entrada de certificados — tanto os
     * carregados de arquivo PEM quanto os fornecidos já em memória.</p>
     *
     * @param cert   certificado a verificar
     * @param source identificador da fonte para mensagens de erro (caminho
     *               do arquivo ou subject DN)
     * @throws SmartTokenException se expirado ou ainda não válido
     */
    static void checkCertificateValidity(final X509Certificate cert, final String source) {
        try {
            cert.checkValidity();
        } catch (CertificateExpiredException ex) {
            throw new SmartTokenException("Certificado expirado: " + source, ex);
        } catch (CertificateNotYetValidException ex) {
            throw new SmartTokenException("Certificado ainda não é válido: " + source, ex);
        }
    }

    /**
     * Identificador legível do certificado para mensagens de erro.
     *
     * @param cert certificado
     * @return subject DN do certificado
     */
    private static String subjectOf(final X509Certificate cert) {
        return cert.getSubjectX500Principal().getName();
    }

    /**
     * {@link X509ExtendedKeyManager} que delega ao KeyManager original e força
     * o alias configurado em {@code chooseClientAlias} e
     * {@code chooseEngineClientAlias}.
     *
     * <p>
     * Garante que, em KeyStores com múltiplos aliases (PKCS#12 institucional,
     * tokens PKCS#11), o cliente mTLS apresente exatamente o certificado da
     * chave indicada. As demais operações — inclusive o acesso à chave privada
     * — permanecem delegadas ao KeyManager original, de modo que chaves em
     * dispositivo (PKCS#11) nunca saem do hardware.
     * </p>
     */
    private static final class FixedAliasKeyManager extends X509ExtendedKeyManager {

        /** KeyManager original ao qual as demais operações são delegadas. */
        private final X509KeyManager delegate;

        /** Alias forçado na seleção da chave do cliente. */
        private final String alias;

        /**
         * Cria o wrapper que força o alias na seleção de chave do cliente.
         *
         * @param delegate KeyManager original
         * @param alias    alias a ser apresentado no handshake
         */
        FixedAliasKeyManager(final X509KeyManager delegate, final String alias) {
            this.delegate = delegate;
            this.alias = alias;
        }

        @Override
        public String chooseClientAlias(final String[] keyTypes, final Principal[] issuers,
                final Socket socket) {
            return alias;
        }

        @Override
        public String chooseEngineClientAlias(final String[] keyTypes, final Principal[] issuers,
                final SSLEngine engine) {
            return alias;
        }

        @Override
        public String[] getClientAliases(final String keyType, final Principal[] issuers) {
            return delegate.getClientAliases(keyType, issuers);
        }

        @Override
        public String[] getServerAliases(final String keyType, final Principal[] issuers) {
            return delegate.getServerAliases(keyType, issuers);
        }

        @Override
        public String chooseServerAlias(final String keyType, final Principal[] issuers,
                final Socket socket) {
            return delegate.chooseServerAlias(keyType, issuers, socket);
        }

        @Override
        public String chooseEngineServerAlias(final String keyType, final Principal[] issuers,
                final SSLEngine engine) {
            return delegate instanceof X509ExtendedKeyManager extended
                    ? extended.chooseEngineServerAlias(keyType, issuers, engine)
                    : super.chooseEngineServerAlias(keyType, issuers, engine);
        }

        @Override
        public X509Certificate[] getCertificateChain(final String requestedAlias) {
            return delegate.getCertificateChain(requestedAlias);
        }

        @Override
        public PrivateKey getPrivateKey(final String requestedAlias) {
            return delegate.getPrivateKey(requestedAlias);
        }
    }
}
