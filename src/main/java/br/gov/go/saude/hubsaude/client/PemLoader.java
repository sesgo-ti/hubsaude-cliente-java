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

import java.io.CharArrayReader;
import java.io.IOException;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.Arrays;
import java.util.Objects;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.jspecify.annotations.Nullable;

/**
 * Utilitário para carregamento de material criptográfico de arquivo PEM.
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
 * <p>
 * Chaves fracas são rejeitadas no carregamento (fail-fast): RSA exige
 * módulo de pelo menos {@value #MIN_RSA_KEY_BITS} bits e EC exige curva
 * com campo de pelo menos {@value #MIN_EC_FIELD_BITS} bits (P-256),
 * conforme NIST SP 800-57.
 * </p>
 *
 * @see SigningStrategyFactory factory methods que utilizam este loader
 */
// PMD.GodClass: utilitário estático coeso de parsing PEM; a métrica dispara
// pelos múltiplos formatos suportados (PKCS#1/PKCS#8/OpenSSL), não por
// acúmulo de responsabilidades distintas.
@SuppressWarnings("PMD.GodClass")
public final class PemLoader {

    /**
     * Tamanho mínimo aceito, em bits, para o módulo de chaves RSA
     * (NIST SP 800-57).
     */
    public static final int MIN_RSA_KEY_BITS = 2048;

    /**
     * Tamanho mínimo aceito, em bits, para o campo da curva de chaves EC
     * (equivalente a P-256, NIST SP 800-57).
     */
    public static final int MIN_EC_FIELD_BITS = 256;

    private PemLoader() {
        // Utilitário não instanciável
    }

    /**
     * Valida o tamanho mínimo de uma chave privada (fail-fast).
     *
     * <p>
     * Chaves RSA com módulo menor que {@value #MIN_RSA_KEY_BITS} bits e
     * chaves EC com campo menor que {@value #MIN_EC_FIELD_BITS} bits
     * (P-256) são consideradas criptograficamente fracas (NIST SP 800-57,
     * BSI TR-02102-1) e rejeitadas. Chaves de outros algoritmos — ou
     * <em>handles</em> PKCS#11 opacos que não expõem os parâmetros — não
     * são validadas.
     * </p>
     *
     * @param key    chave privada a validar
     * @param source identificador da fonte para mensagens de erro
     * @throws IllegalArgumentException se a chave estiver abaixo do
     *                                  tamanho mínimo aceito
     */
    public static void validateMinimumKeySize(final PrivateKey key, final String source) {
        Objects.requireNonNull(key, "key não pode ser null");
        if (key instanceof RSAKey rsaKey) {
            final int bits = rsaKey.getModulus().bitLength();
            if (bits < MIN_RSA_KEY_BITS) {
                throw new IllegalArgumentException(
                        "Chave RSA de " + bits + " bits rejeitada: o tamanho mínimo aceito é "
                                + MIN_RSA_KEY_BITS + " bits (NIST SP 800-57). Fonte: " + source);
            }
        } else if (key instanceof ECKey ecKey) {
            final int bits = ecKey.getParams().getCurve().getField().getFieldSize();
            if (bits < MIN_EC_FIELD_BITS) {
                throw new IllegalArgumentException(
                        "Chave EC com campo de " + bits + " bits rejeitada: a curva mínima aceita é P-256 ("
                                + MIN_EC_FIELD_BITS + " bits, NIST SP 800-57). Fonte: " + source);
            }
        }
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
    public static PrivateKey loadPrivateKey(final Path path, final char @Nullable [] password) throws IOException {
        Objects.requireNonNull(path, "path não pode ser null");
        final byte[] raw = Files.readAllBytes(path);
        try {
            // Decodifica para char[] (nunca String) para permitir zeroização
            return loadPrivateKeyFromChars(decodeUtf8(raw), password, path.toString());
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }

    /**
     * Decodifica bytes UTF-8 em {@code char[]} sem materializar {@link String},
     * zerando o buffer intermediário do decodificador.
     */
    private static char[] decodeUtf8(final byte[] bytes) {
        final CharBuffer buffer = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(bytes));
        final char[] chars = new char[buffer.remaining()];
        buffer.get(chars);
        if (buffer.hasArray()) {
            Arrays.fill(buffer.array(), '\0');
        }
        return chars;
    }

    /**
     * Carrega chave privada de string PEM.
     *
     * <p>
     * A senha, quando fornecida, é <strong>consumida</strong>: o array é
     * zerado ao final da chamada, em sucesso ou erro, mesmo quando a chave
     * não está criptografada e a senha não é utilizada (RNF de segurança —
     * minimizar exposição de segredos em memória).
     * </p>
     *
     * <p>
     * <strong>Atenção:</strong> por ser {@link String} (imutável), o conteúdo
     * PEM fornecido pelo chamador não pode ser zerado e permanecerá no heap
     * até a coleta de lixo. Quando o material da chave for sensível, prefira
     * {@link #loadPrivateKeyFromChars(char[], char[], String)}.
     * </p>
     *
     * @param pem      conteúdo PEM
     * @param password senha (null se não criptografada); zerada após o uso
     * @param source   identificador da fonte para mensagens de erro
     * @return chave privada
     * @throws IOException              em caso de erro de parse
     * @throws IllegalArgumentException se a chave estiver abaixo do tamanho
     *                                  mínimo aceito (RSA &lt; 2048 bits ou
     *                                  EC &lt; P-256)
     */
    public static PrivateKey loadPrivateKeyFromString(
            final String pem,
            final char @Nullable [] password,
            final String source) throws IOException {
        Objects.requireNonNull(pem, "pem não pode ser null");
        return loadPrivateKeyFromChars(pem.toCharArray(), password, source);
    }

    /**
     * Carrega chave privada de conteúdo PEM em {@code char[]}.
     *
     * <p>
     * Tanto o conteúdo PEM quanto a senha são <strong>consumidos</strong>:
     * ambos os arrays são zerados ao final da chamada, em sucesso ou erro
     * (RNF de segurança — minimizar exposição de material de chave e
     * segredos em memória). O chamador não deve reutilizá-los.
     * </p>
     *
     * @param pem      conteúdo PEM; zerado após o uso
     * @param password senha (null se não criptografada); zerada após o uso
     * @param source   identificador da fonte para mensagens de erro
     * @return chave privada
     * @throws IOException              em caso de erro de parse
     * @throws IllegalArgumentException se a chave estiver abaixo do tamanho
     *                                  mínimo aceito (RSA &lt; 2048 bits ou
     *                                  EC &lt; P-256)
     */
    @SuppressWarnings("PMD.UseVarargs") // char[] para material sensível é intencional - segurança
    public static PrivateKey loadPrivateKeyFromChars(
            final char[] pem,
            final char @Nullable [] password,
            final String source) throws IOException {
        Objects.requireNonNull(pem, "pem não pode ser null");

        try (PEMParser parser = new PEMParser(new CharArrayReader(pem))) {
            final Object obj = parser.readObject();

            if (obj == null) {
                throw new SmartTokenException("Arquivo PEM vazio ou inválido: " + source);
            }

            final PrivateKey key = convertToPrivateKey(obj, password, source);
            validateMinimumKeySize(key, source);
            return key;
        } finally {
            Arrays.fill(pem, '\0');
            clearPassword(password);
        }
    }

    /**
     * Converte o objeto lido pelo {@link PEMParser} em {@link PrivateKey},
     * aplicando decriptação quando necessário.
     */
    @SuppressWarnings("PMD.UseVarargs") // char[] para senha é intencional - segurança
    private static PrivateKey convertToPrivateKey(
            final Object obj,
            final char @Nullable [] password,
            final String source) {
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
            try {
                return new JcaPEMKeyConverter().getKeyPair(pemKeyPair).getPrivate();
            } catch (PEMException e) {
                throw new SmartTokenException("Falha ao converter chave PKCS#1: " + source, e);
            }
        }

        // PKCS#8 não criptografado (BEGIN PRIVATE KEY)
        if (obj instanceof PrivateKeyInfo pki) {
            try {
                return new JcaPEMKeyConverter().getPrivateKey(pki);
            } catch (PEMException e) {
                throw new SmartTokenException("Falha ao converter chave PKCS#8: " + source, e);
            }
        }

        throw new SmartTokenException(
                "Formato de chave não suportado (" + obj.getClass().getSimpleName() + "): " + source);
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
            final char @Nullable [] password,
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
            final char @Nullable [] password,
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
    static void clearPassword(final char @Nullable [] password) {
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
     * @throws IOException         em caso de erro de parse
     * @throws SmartTokenException se não for um certificado válido ou
     *                             estiver fora do período de validade
     */
    public static X509Certificate loadCertificateFromString(
            final String pem,
            final String source) throws IOException {
        Objects.requireNonNull(pem, "pem não pode ser null");

        final Object obj;
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            obj = parser.readObject();
        }

        if (!(obj instanceof X509CertificateHolder holder)) {
            throw new SmartTokenException(
                    "Arquivo PEM não contém certificado X.509: " + source);
        }

        final X509Certificate cert = convertHolder(holder);
        if (cert == null) {
            throw new SmartTokenException("Certificado inválido: " + source);
        }
        SslContextFactory.checkCertificateValidity(cert, source);
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
}
