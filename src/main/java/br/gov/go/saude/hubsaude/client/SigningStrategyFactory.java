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
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Objects;

/**
 * Factory para criação de estratégias de assinatura ({@link SigningStrategy}).
 *
 * <p>
 * Centraliza a criação de estratégias para diferentes fontes de material
 * criptográfico, garantindo configuração correta e consistente.
 * </p>
 *
 * <h2>Fontes Suportadas</h2>
 * <ul>
 *   <li>{@link #fromPrivateKey(PrivateKey)} — chave já carregada em memória</li>
 *   <li>{@link #fromPemFile(Path)} — arquivo PEM sem senha</li>
 *   <li>{@link #fromPemFile(Path, char[])} — arquivo PEM com senha</li>
 *   <li>{@link #fromPkcs11(Provider, String, char[])} — HSM/Smart Token</li>
 * </ul>
 *
 * <h2>Exemplo de Uso</h2>
 * <pre>{@code
 * // Arquivo PEM simples
 * SigningStrategy strategy = SigningStrategyFactory.fromPemFile(Path.of("key.pem"));
 *
 * // Arquivo PEM com senha
 * SigningStrategy strategy = SigningStrategyFactory.fromPemFile(
 *     Path.of("key.pem"),
 *     "minha-senha".toCharArray());
 *
 * // HSM via PKCS#11
 * Provider pkcs11 = loadPkcs11Provider();
 * SigningStrategy strategy = SigningStrategyFactory.fromPkcs11(pkcs11, "key-alias", pin);
 * }</pre>
 *
 * @see SigningStrategy
 * @see PrivateKeySigningStrategy
 */
public final class SigningStrategyFactory {

    /** Comprimento do salt PSS (bytes) para PS256, igual ao digest SHA-256. */
    private static final int PSS_SALT_LEN_256 = 32;

    /** Comprimento do salt PSS (bytes) para PS384, igual ao digest SHA-384. */
    private static final int PSS_SALT_LEN_384 = 48;

    /** Comprimento do salt PSS (bytes) para PS512, igual ao digest SHA-512. */
    private static final int PSS_SALT_LEN_512 = 64;

    /** Trailer field padrão (0xBC) conforme PKCS#1 v2.1. */
    private static final int PSS_TRAILER_FIELD = 1;

    private SigningStrategyFactory() {
        // Factory não instanciável
    }

    /**
     * Cria estratégia a partir de chave privada já carregada em memória.
     *
     * <p>
     * Útil quando a chave foi obtida de outra fonte (ex: KeyStore, Vault API).
     * </p>
     *
     * @param privateKey chave privada RSA
     * @return estratégia de assinatura configurada
     * @throws NullPointerException se privateKey for null
     */
    public static SigningStrategy fromPrivateKey(final PrivateKey privateKey) {
        Objects.requireNonNull(privateKey, "privateKey não pode ser null");
        return new PrivateKeySigningStrategy(privateKey);
    }

    /**
     * Cria estratégia a partir de chave privada com algoritmo específico.
     *
     * @param privateKey chave privada
     * @param algorithm  algoritmo de assinatura (ex: "SHA256withRSA")
     * @return estratégia de assinatura configurada
     */
    public static SigningStrategy fromPrivateKey(final PrivateKey privateKey, final String algorithm) {
        Objects.requireNonNull(privateKey, "privateKey não pode ser null");
        Objects.requireNonNull(algorithm, "algorithm não pode ser null");
        return new PrivateKeySigningStrategy(privateKey, algorithm);
    }

    /**
     * Cria estratégia a partir de arquivo PEM sem senha.
     *
     * @param keyPath caminho para o arquivo PEM da chave privada
     * @return estratégia de assinatura configurada
     * @throws IOException se o arquivo não puder ser lido
     * @throws SmartTokenException se o formato não for válido
     */
    public static SigningStrategy fromPemFile(final Path keyPath) throws IOException {
        return fromPemFile(keyPath, null);
    }

    /**
     * Cria estratégia a partir de arquivo PEM com senha.
     *
     * <p>
     * Suporta chaves PKCS#8 criptografadas (BEGIN ENCRYPTED PRIVATE KEY)
     * e formato OpenSSL tradicional criptografado.
     * </p>
     *
     * @param keyPath  caminho para o arquivo PEM da chave privada
     * @param password senha para decriptar a chave (null se não criptografada)
     * @return estratégia de assinatura configurada
     * @throws IOException se o arquivo não puder ser lido
     * @throws SmartTokenException se a senha for incorreta ou formato inválido
     */
    @SuppressWarnings("PMD.UseVarargs") // char[] para senha é intencional - segurança
    public static SigningStrategy fromPemFile(final Path keyPath, final char[] password) throws IOException {
        Objects.requireNonNull(keyPath, "keyPath não pode ser null");
        final PrivateKey key = PemLoader.loadPrivateKey(keyPath, password);
        return new PrivateKeySigningStrategy(key);
    }

    /**
     * Cria estratégia a partir de conteúdo PEM em string.
     *
     * <p>
     * Útil quando o PEM é obtido de variável de ambiente ou secret manager.
     * </p>
     *
     * @param pemContent conteúdo PEM da chave privada
     * @param password   senha para decriptar (null se não criptografada)
     * @return estratégia de assinatura configurada
     * @throws IOException se o PEM não puder ser decodificado
     */
    @SuppressWarnings("PMD.UseVarargs") // char[] para senha é intencional - segurança
    public static SigningStrategy fromPemString(final String pemContent, final char[] password) throws IOException {
        Objects.requireNonNull(pemContent, "pemContent não pode ser null");
        final PrivateKey key = PemLoader.loadPrivateKeyFromString(pemContent, password, "<string>");
        return new PrivateKeySigningStrategy(key);
    }

    /**
     * Cria estratégia para HSM/Smart Token via PKCS#11.
     *
     * <p>
     * A chave privada <strong>nunca sai do hardware</strong>. O objeto
     * {@link PrivateKey} obtido é um handle que delega operações ao dispositivo.
     * </p>
     *
     * <h3>Configuração do Provider PKCS#11</h3>
     * <pre>{@code
     * // Via arquivo de configuração
     * String config = "--name=MyHSM\\nlibrary=/usr/lib/pkcs11/libsofthsm2.so";
     * Provider provider = Security.getProvider("SunPKCS11").configure(config);
     *
     * // Ou via configuração inline
     * Provider provider = configurePkcs11Provider("/path/to/config");
     * }</pre>
     *
     * @param pkcs11Provider provider PKCS#11 configurado
     * @param keyAlias       alias da chave no token
     * @param pin            PIN de acesso ao token; o array do chamador
     *                       <strong>não é modificado</strong> — uma cópia
     *                       defensiva é criada e zerada internamente. O
     *                       chamador permanece responsável por zerar o
     *                       array original após o uso
     * @return estratégia de assinatura que usa o HSM
     * @throws SmartTokenException se a chave não for encontrada ou PIN inválido
     */
    @SuppressWarnings("PMD.UseVarargs") // char[] para PIN é intencional - segurança
    public static SigningStrategy fromPkcs11(
            final Provider pkcs11Provider,
            final String keyAlias,
            final char[] pin) {
        Objects.requireNonNull(pkcs11Provider, "pkcs11Provider não pode ser null");
        Objects.requireNonNull(keyAlias, "keyAlias não pode ser null");
        Objects.requireNonNull(pin, "pin não pode ser null");

        // Cópia defensiva: o array do chamador permanece intacto (permite
        // reutilizar o mesmo PIN, ex.: em clientKeyStore(...) para mTLS)
        final char[] pinCopy = pin.clone();
        try {
            final KeyStore ks = KeyStore.getInstance("PKCS11", pkcs11Provider);
            ks.load(null, pinCopy);

            final PrivateKey handle = (PrivateKey) ks.getKey(keyAlias, pinCopy);
            if (handle == null) {
                throw new SmartTokenException("Chave não encontrada no token PKCS#11: " + keyAlias);
            }

            // Usa a mesma implementação - handle funciona como PrivateKey
            // mas assinatura é delegada ao hardware
            return new PrivateKeySigningStrategy(
                    handle,
                    pkcs11Provider,
                    PrivateKeySigningStrategy.DEFAULT_ALGORITHM);
        } catch (SmartTokenException e) {
            throw e;
        } catch (Exception e) {
            throw new SmartTokenException("Falha ao acessar chave PKCS#11: " + e.getMessage(), e);
        } finally {
            PemLoader.clearPassword(pinCopy);
        }
    }

    /**
     * Cria estratégia a partir de KeyStore (JKS, PKCS#12).
     *
     * <p>
     * O array de senha do chamador <strong>não é modificado</strong>: uma
     * cópia defensiva é criada e zerada internamente, em sucesso ou erro.
     * Isso permite reutilizar a mesma senha/PIN em chamadas subsequentes
     * (ex.: {@code SmartTokenClientBuilder.clientKeyStore(...)} para mTLS
     * com o mesmo material). O chamador permanece responsável por zerar o
     * array original após o uso.
     * </p>
     *
     * @param keyStore KeyStore carregado
     * @param alias    alias da chave privada
     * @param password senha da chave (null se o KeyStore não exigir);
     *                 o array do chamador não é modificado
     * @return estratégia de assinatura configurada
     * @throws SmartTokenException se a chave não for encontrada
     */
    @SuppressWarnings("PMD.UseVarargs") // char[] para senha é intencional - segurança
    public static SigningStrategy fromKeyStore(
            final KeyStore keyStore,
            final String alias,
            final char[] password) {
        Objects.requireNonNull(keyStore, "keyStore não pode ser null");
        Objects.requireNonNull(alias, "alias não pode ser null");

        // Cópia defensiva: o array do chamador permanece intacto
        final char[] passwordCopy = password == null ? null : password.clone();
        try {
            final PrivateKey key = (PrivateKey) keyStore.getKey(alias, passwordCopy);
            if (key == null) {
                throw new SmartTokenException("Chave não encontrada no KeyStore: " + alias);
            }
            return new PrivateKeySigningStrategy(key);
        } catch (SmartTokenException e) {
            throw e;
        } catch (Exception e) {
            throw new SmartTokenException("Falha ao obter chave do KeyStore: " + e.getMessage(), e);
        } finally {
            PemLoader.clearPassword(passwordCopy);
        }
    }

    /**
     * Configura e retorna um provider PKCS#11 a partir de arquivo de configuração.
     *
     * <p>
     * Este é um método auxiliar para facilitar a configuração do SunPKCS11.
     * </p>
     *
     * @param configPath caminho para o arquivo de configuração PKCS#11
     * @return provider configurado
     * @throws SmartTokenException se a configuração falhar
     */
    public static Provider configurePkcs11Provider(final String configPath) {
        Objects.requireNonNull(configPath, "configPath não pode ser null");
        try {
            final Provider prototype = Security.getProvider("SunPKCS11");
            if (prototype == null) {
                throw new SmartTokenException("Provider SunPKCS11 não disponível na JVM");
            }
            final Provider configured = prototype.configure(configPath);
            Security.addProvider(configured);
            return configured;
        } catch (SmartTokenException e) {
            throw e;
        } catch (Exception e) {
            throw new SmartTokenException("Falha ao configurar provider PKCS#11: " + e.getMessage(), e);
        }
    }

    /**
     * Converte um algoritmo JWT (JWA) para o nome do algoritmo de assinatura Java (JCA).
     *
     * <h3>Mapeamentos Suportados</h3>
     * <table>
     *   <tr><th>JWT (JWA)</th><th>Java (JCA)</th><th>Descrição</th></tr>
     *   <tr><td>RS256</td><td>SHA256withRSA</td><td>RSA PKCS#1 v1.5 + SHA-256</td></tr>
     *   <tr><td>RS384</td><td>SHA384withRSA</td><td>RSA PKCS#1 v1.5 + SHA-384</td></tr>
     *   <tr><td>RS512</td><td>SHA512withRSA</td><td>RSA PKCS#1 v1.5 + SHA-512</td></tr>
     *   <tr><td>PS256</td><td>RSASSA-PSS</td><td>RSA-PSS + SHA-256 (requer
     *       {@link PSSParameterSpec} — ver {@link #pssParameterSpecFor(String)})</td></tr>
     *   <tr><td>PS384</td><td>RSASSA-PSS</td><td>RSA-PSS + SHA-384 (requer
     *       {@link PSSParameterSpec})</td></tr>
     *   <tr><td>PS512</td><td>RSASSA-PSS</td><td>RSA-PSS + SHA-512 (requer
     *       {@link PSSParameterSpec})</td></tr>
     *   <tr><td>ES256</td><td>SHA256withECDSAinP1363Format</td><td>ECDSA P-256 + SHA-256,
     *       assinatura R||S conforme RFC 7518 §3.4</td></tr>
     *   <tr><td>ES384</td><td>SHA384withECDSAinP1363Format</td><td>ECDSA P-384 + SHA-384,
     *       assinatura R||S conforme RFC 7518 §3.4</td></tr>
     *   <tr><td>ES512</td><td>SHA512withECDSAinP1363Format</td><td>ECDSA P-521 + SHA-512,
     *       assinatura R||S conforme RFC 7518 §3.4</td></tr>
     * </table>
     *
     * <p>
     * <strong>Nota (ES*):</strong> a RFC 7518 §3.4 exige a concatenação crua
     * {@code R || S} na assinatura ECDSA de um JWS — e não a codificação DER
     * produzida por {@code SHAxxxwithECDSA}. Por isso o mapeamento usa as
     * variantes {@code inP1363Format} do JDK.
     * </p>
     *
     * <p>
     * <strong>Nota (PS*):</strong> o nome JCA padrão do JDK para RSA-PSS é
     * {@code RSASSA-PSS}, que exige parâmetros explícitos. Use
     * {@link #fromPrivateKeyForJwt(PrivateKey, String)} para obter uma
     * estratégia já configurada com o {@link PSSParameterSpec} correto.
     * </p>
     *
     * @param jwtAlgorithm algoritmo no formato JWT/JWA (ex: RS256, RS384, PS256)
     * @return algoritmo no formato Java/JCA (ex: SHA256withRSA, RSASSA-PSS)
     * @throws SmartTokenException se o algoritmo não for reconhecido
     */
    public static String jwtAlgorithmToJava(final String jwtAlgorithm) {
        Objects.requireNonNull(jwtAlgorithm, "jwtAlgorithm não pode ser null");
        return switch (jwtAlgorithm.toUpperCase(java.util.Locale.ROOT)) {
            // RSA PKCS#1 v1.5
            case "RS256" -> "SHA256withRSA";
            case "RS384" -> "SHA384withRSA";
            case "RS512" -> "SHA512withRSA";
            // RSA-PSS (parâmetros via PSSParameterSpec — ver pssParameterSpecFor)
            case "PS256", "PS384", "PS512" -> "RSASSA-PSS";
            // ECDSA em formato P1363 (R||S), conforme RFC 7518 §3.4
            case "ES256" -> "SHA256withECDSAinP1363Format";
            case "ES384" -> "SHA384withECDSAinP1363Format";
            case "ES512" -> "SHA512withECDSAinP1363Format";
            default -> throw new SmartTokenException(
                    "Algoritmo JWT não suportado: " + jwtAlgorithm
                            + ". Algoritmos válidos: RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512");
        };
    }

    /**
     * Retorna o {@link PSSParameterSpec} adequado para algoritmos JWT PS*.
     *
     * <p>
     * Conforme a RFC 7518 §3.5, o salt deve ter o mesmo comprimento do
     * digest e a MGF é MGF1 com o mesmo digest.
     * </p>
     *
     * @param jwtAlgorithm algoritmo JWT (ex: PS256)
     * @return parâmetros PSS para PS256/PS384/PS512; {@code null} para os demais
     */
    public static PSSParameterSpec pssParameterSpecFor(final String jwtAlgorithm) {
        Objects.requireNonNull(jwtAlgorithm, "jwtAlgorithm não pode ser null");
        return switch (jwtAlgorithm.toUpperCase(java.util.Locale.ROOT)) {
            case "PS256" -> new PSSParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                    PSS_SALT_LEN_256, PSS_TRAILER_FIELD);
            case "PS384" -> new PSSParameterSpec(
                    "SHA-384", "MGF1", MGF1ParameterSpec.SHA384,
                    PSS_SALT_LEN_384, PSS_TRAILER_FIELD);
            case "PS512" -> new PSSParameterSpec(
                    "SHA-512", "MGF1", MGF1ParameterSpec.SHA512,
                    PSS_SALT_LEN_512, PSS_TRAILER_FIELD);
            default -> null;
        };
    }

    /**
     * Cria estratégia de assinatura a partir de um algoritmo JWT (JWA).
     *
     * <p>
     * Converte o algoritmo JWT para o nome JCA correspondente e, quando
     * necessário (PS256/PS384/PS512), configura o {@link PSSParameterSpec}
     * exigido pelo algoritmo {@code RSASSA-PSS} do JDK.
     * </p>
     *
     * @param privateKey   chave privada compatível com o algoritmo
     * @param jwtAlgorithm algoritmo JWT (ex: RS256, PS256, ES256)
     * @return estratégia de assinatura configurada
     * @throws SmartTokenException se o algoritmo não for reconhecido
     */
    public static SigningStrategy fromPrivateKeyForJwt(
            final PrivateKey privateKey,
            final String jwtAlgorithm) {
        Objects.requireNonNull(privateKey, "privateKey não pode ser null");
        final String javaAlgorithm = jwtAlgorithmToJava(jwtAlgorithm);
        return new PrivateKeySigningStrategy(
                privateKey, null, javaAlgorithm, pssParameterSpecFor(jwtAlgorithm));
    }
}
