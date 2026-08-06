/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.hubsaude.client;

import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;

import org.jspecify.annotations.Nullable;

/**
 * Agrupa a configuração TLS/mTLS do {@link SmartTokenClientBuilder} e
 * resolve o {@link SSLContext} efetivo a partir dela.
 *
 * <p>
 * Colaborador interno do {@link SmartTokenClientBuilder}, extraído para
 * reduzir o número de campos e a complexidade de {@code build()}
 * (issue #1032). Não faz parte da API pública da biblioteca: os valores
 * são definidos exclusivamente pelos métodos fluentes do builder.
 * </p>
 *
 * <p>
 * A precedência na resolução do {@link SSLContext} reproduz o contrato
 * documentado do builder: {@code sslContext} customizado &gt; trust anchor
 * em memória &gt; KeyStore do cliente (PKCS#11/PKCS#12/JKS) &gt; chave em
 * memória (PEM) &gt; TLS unidirecional com trust anchor em arquivo ou
 * trust store da JVM.
 * </p>
 */
final class TlsSettings {

    /** Caminho do certificado PEM do cliente (mTLS); opcional. */
    private @Nullable Path certificatePem;

    /** Caminho do trust anchor do servidor; null usa o trust store da JVM. */
    private @Nullable Path serverTrustAnchor;

    /** Trust anchor do servidor em memória; alternativa ao caminho PEM. */
    private @Nullable X509Certificate serverTrustAnchorCert;

    /** SSLContext customizado; sobrepõe qualquer outra configuração TLS. */
    private @Nullable SSLContext customSslContext;

    /** KeyStore do cliente para mTLS (PKCS#11, PKCS#12, JKS). */
    private @Nullable KeyStore clientKeyStore;

    /** Alias da chave privada no KeyStore do cliente. */
    private @Nullable String clientKeyAlias;

    /** Senha/PIN da chave no KeyStore; zerada por {@link #clearSecrets()}. */
    private char @Nullable [] clientKeyPassword;

    /** Protocolo TLS a utilizar (padrão: TLSv1.3). */
    private String tlsProtocol = SslContextFactory.DEFAULT_TLS_PROTOCOL;

    /**
     * Define o caminho do certificado PEM do cliente.
     *
     * @param certificatePem caminho absoluto do certificado
     */
    void setCertificatePem(final Path certificatePem) {
        this.certificatePem = certificatePem;
    }

    /**
     * Define o caminho do trust anchor do servidor.
     *
     * @param serverTrustAnchor caminho absoluto; null usa trust store da JVM
     */
    void setServerTrustAnchor(final @Nullable Path serverTrustAnchor) {
        this.serverTrustAnchor = serverTrustAnchor;
    }

    /**
     * Define o trust anchor do servidor em memória.
     *
     * @param serverTrustAnchorCert certificado X.509; null usa trust store
     *                              da JVM
     */
    void setServerTrustAnchorCert(final @Nullable X509Certificate serverTrustAnchorCert) {
        this.serverTrustAnchorCert = serverTrustAnchorCert;
    }

    /**
     * Define um SSLContext customizado, que sobrepõe as demais configurações.
     *
     * @param customSslContext contexto SSL a utilizar
     */
    void setCustomSslContext(final SSLContext customSslContext) {
        this.customSslContext = customSslContext;
    }

    /**
     * Define o KeyStore do cliente para mTLS.
     *
     * @param keyStore    KeyStore já carregado (PKCS#11, PKCS#12, JKS)
     * @param keyAlias    alias da chave privada no KeyStore
     * @param keyPassword senha/PIN da chave; o array não é copiado e é
     *                    zerado por {@link #clearSecrets()}
     */
    @SuppressWarnings("PMD.UseVarargs")
    void setClientKeyStore(
            final KeyStore keyStore,
            final String keyAlias,
            final char @Nullable [] keyPassword) {
        this.clientKeyStore = keyStore;
        this.clientKeyAlias = keyAlias;
        this.clientKeyPassword = keyPassword;
    }

    /**
     * Define o protocolo TLS a utilizar.
     *
     * @param tlsProtocol protocolo TLS (ex.: TLSv1.3)
     */
    void setTlsProtocol(final String tlsProtocol) {
        this.tlsProtocol = tlsProtocol;
    }

    /**
     * Carrega e valida o certificado do cliente, quando configurado.
     *
     * @return o certificado X.509 do cliente ou {@code null} quando
     *         {@code certificatePem} não foi definido
     * @throws IOException se o arquivo PEM não puder ser lido
     */
    @Nullable X509Certificate loadCertificate() throws IOException {
        return certificatePem != null
                ? SslContextFactory.validateCertificate(certificatePem)
                : null;
    }

    /**
     * Resolve o {@link SSLContext} efetivo conforme a precedência documentada
     * na descrição da classe, habilitando mTLS quando o material do cliente
     * está disponível.
     *
     * @param clientKey  chave privada do cliente (mTLS via PEM); pode ser null
     * @param clientCert certificado do cliente; pode ser null
     * @return contexto SSL pronto para uso
     */
    SSLContext resolveSslContext(
            final @Nullable PrivateKey clientKey,
            final @Nullable X509Certificate clientCert) {
        if (customSslContext != null) {
            return customSslContext;
        }
        final boolean mtlsInMemory = clientKey != null && clientCert != null;
        final SSLContext resolved;
        if (serverTrustAnchorCert != null) {
            // Trust anchor em memória (extraído dinamicamente, ex: testes de
            // integração); mTLS quando a chave em memória está disponível
            resolved = mtlsInMemory
                    ? SslContextFactory.buildSslContext(
                            serverTrustAnchorCert, tlsProtocol, clientKey, clientCert)
                    : SslContextFactory.buildSslContext(serverTrustAnchorCert, tlsProtocol);
        } else if (clientKeyStore != null) {
            // mTLS via KeyStore (PKCS#11/smartcard/USB token, PKCS#12, JKS)
            resolved = SslContextFactory.buildSslContext(
                    serverTrustAnchor, tlsProtocol,
                    clientKeyStore, clientKeyAlias, clientKeyPassword);
        } else if (mtlsInMemory) {
            // mTLS via chave em memória (PEM)
            resolved = SslContextFactory.buildSslContext(
                    serverTrustAnchor, tlsProtocol, clientKey, clientCert);
        } else {
            // TLS unidirecional (sem mTLS)
            resolved = SslContextFactory.buildSslContext(serverTrustAnchor, tlsProtocol);
        }
        return resolved;
    }

    /**
     * Zera e descarta a senha do KeyStore do cliente, minimizando a
     * exposição do segredo em memória após a construção do cliente.
     */
    void clearSecrets() {
        PemLoader.clearPassword(clientKeyPassword);
        clientKeyPassword = null;
    }
}
