/*
 * Copyright (c) 2026 SES-GO / UFG
 * Todos os direitos reservados.
 */

package br.gov.go.saude.hubsaude.client;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Objects;

/**
 * Utilitário para carregamento de material criptográfico de arquivos PEM.
 *
 * <p>
 * Suporta múltiplos formatos de chave privada:
 * </p>
 * <ul>
 * <li>PKCS#1 RSA (BEGIN RSA PRIVATE KEY)</li>
 * <li>PKCS#8 não criptografado (BEGIN PRIVATE KEY)</li>
 * <li>PKCS#8 criptografado (BEGIN ENCRYPTED PRIVATE KEY)</li>
 * <li>OpenSSL tradicional criptografado (BEGIN RSA PRIVATE KEY + DEK-Info)</li>
 * </ul>
 *
 * <h2>Segurança</h2>
 * <p>
 * Para chaves protegidas por senha, a senha é recebida como {@code char[]}
 * e deve ser limpa pelo chamador após o uso para minimizar exposição em
 * memória.
 * </p>
 *
 * @see SigningStrategyFactory factory methods que utilizam este loader
 */
public final class PemLoader {

    private PemLoader() {
        // Utilitário não instanciável
    }

    /**
     * Carrega chave privada de arquivo PEM sem senha.
     *
     * @param path caminho para o arquivo PEM
     * @return chave privada carregada
     * @throws IOException         se o arquivo não puder ser lido ou decodificado
     * @throws SmartTokenException se o formato não for suportado
     */
    public static PrivateKey loadPrivateKey(final Path path) throws IOException {
        return loadPrivateKey(path, null);
    }

    /**
     * Carrega chave privada de arquivo PEM, com suporte a senha.
     *
     * <p>
     * Detecta automaticamente o formato da chave e aplica decriptação
     * quando necessário.
     * </p>
     *
     * @param path     caminho para o arquivo PEM
     * @param password senha para chaves criptografadas (null se não criptografada)
     * @return chave privada carregada
     * @throws IOException         se o arquivo não puder ser lido
     * @throws SmartTokenException se a chave requer senha não fornecida,
     *                             se a senha for incorreta, ou formato inválido
     */
    @SuppressWarnings("PMD.UseVarargs") // char[] para senha é intencional - segurança
    public static PrivateKey loadPrivateKey(final Path path, final char[] password) throws IOException {
        Objects.requireNonNull(path, "path não pode ser null");
        final String pem = Files.readString(path, StandardCharsets.UTF_8);
        return loadPrivateKeyFromString(pem, password, path.toString());
    }

    /**
     * Carrega chave privada de string PEM.
     *
     * @param pem      conteúdo PEM
     * @param password senha (null se não criptografada)
     * @param source   identificador da fonte para mensagens de erro
     * @return chave privada
     * @throws IOException em caso de erro de parse
     */
    public static PrivateKey loadPrivateKeyFromString(
            final String pem,
            final char[] password,
            final String source) throws IOException {
        Objects.requireNonNull(pem, "pem não pode ser null");

        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            final Object obj = parser.readObject();

            if (obj == null) {
                throw new SmartTokenException("Arquivo PEM vazio ou inválido: " + source);
            }

            // PKCS#8 criptografado (BEGIN ENCRYPTED PRIVATE KEY)
            if (obj instanceof PKCS8EncryptedPrivateKeyInfo encrypted) {
                return decryptPkcs8(encrypted, password, source);
            }

            // OpenSSL tradicional criptografado (BEGIN RSA PRIVATE KEY +
            // Proc-Type/DEK-Info)
            if (obj instanceof PEMEncryptedKeyPair encryptedKeyPair) {
                return decryptOpenSslKey(encryptedKeyPair, password, source);
            }

            // PKCS#1 RSA não criptografado (BEGIN RSA PRIVATE KEY)
            if (obj instanceof PEMKeyPair pemKeyPair) {
                return new JcaPEMKeyConverter().getKeyPair(pemKeyPair).getPrivate();
            }

            // PKCS#8 não criptografado (BEGIN PRIVATE KEY)
            if (obj instanceof PrivateKeyInfo pki) {
                return new JcaPEMKeyConverter().getPrivateKey(pki);
            }

            throw new SmartTokenException(
                    "Formato de chave não suportado (" + obj.getClass().getSimpleName() + "): " + source);
        }
    }

    /**
     * Decripta chave PKCS#8 criptografada.
     *
     * <p>
     * A senha é limpa da memória após uso para minimizar exposição.
     * </p>
     */
    private static PrivateKey decryptPkcs8(
            final PKCS8EncryptedPrivateKeyInfo encrypted,
            final char[] password,
            final String source) {
        if (password == null || password.length == 0) {
            throw new SmartTokenException("Chave PKCS#8 criptografada requer senha: " + source);
        }
        try {
            final InputDecryptorProvider decryptor = new JceOpenSSLPKCS8DecryptorProviderBuilder()
                    .build(password);
            final PrivateKeyInfo pki = encrypted.decryptPrivateKeyInfo(decryptor);
            return new JcaPEMKeyConverter().getPrivateKey(pki);
        } catch (Exception e) {
            throw new SmartTokenException("Falha ao decriptar chave PKCS#8 (senha incorreta?): " + source, e);
        } finally {
            clearPassword(password);
        }
    }

    /**
     * Decripta chave no formato OpenSSL tradicional criptografado.
     *
     * <p>
     * A senha é limpa da memória após uso para minimizar exposição.
     * </p>
     */
    private static PrivateKey decryptOpenSslKey(
            final PEMEncryptedKeyPair encryptedKeyPair,
            final char[] password,
            final String source) {
        if (password == null || password.length == 0) {
            throw new SmartTokenException("Chave criptografada (OpenSSL) requer senha: " + source);
        }
        try {
            final PEMKeyPair decrypted = encryptedKeyPair.decryptKeyPair(
                    new JcePEMDecryptorProviderBuilder().build(password));
            return new JcaPEMKeyConverter().getKeyPair(decrypted).getPrivate();
        } catch (Exception e) {
            throw new SmartTokenException("Falha ao decriptar chave OpenSSL (senha incorreta?): " + source, e);
        } finally {
            clearPassword(password);
        }
    }

    /**
     * Limpa array de senha da memória para minimizar exposição.
     *
     * @param password array de senha a ser limpo (pode ser null)
     */
    @SuppressWarnings("PMD.UseVarargs")
    static void clearPassword(final char[] password) {
        if (password != null) {
            Arrays.fill(password, '\0');
        }
    }

    /**
     * Carrega certificado X.509 de arquivo PEM.
     *
     * @param path caminho para o arquivo PEM do certificado
     * @return certificado X.509
     * @throws IOException         se o arquivo não puder ser lido
     * @throws SmartTokenException se não for um certificado válido
     */
    public static X509Certificate loadCertificate(final Path path) throws IOException {
        Objects.requireNonNull(path, "path não pode ser null");
        final String pem = Files.readString(path, StandardCharsets.UTF_8);
        return loadCertificateFromString(pem, path.toString());
    }

    /**
     * Carrega certificado X.509 de string PEM.
     *
     * @param pem    conteúdo PEM
     * @param source identificador da fonte para mensagens de erro
     * @return certificado X.509
     * @throws IOException em caso de erro de parse
     */
    public static X509Certificate loadCertificateFromString(
            final String pem,
            final String source) throws IOException {
        Objects.requireNonNull(pem, "pem não pode ser null");

        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            final Object obj = parser.readObject();

            if (obj instanceof X509CertificateHolder holder) {
                final X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
                if (cert == null) {
                    throw new SmartTokenException("Certificado inválido: " + source);
                }
                return cert;
            }

            throw new SmartTokenException("Arquivo PEM não contém certificado X.509: " + source);
        } catch (CertificateException ex) {
            throw new SmartTokenException("Falha ao converter certificado: " + ex.getMessage(), ex);
        }
    }
}
