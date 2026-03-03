/*
 * Copyright (c) 2026 SES-GO / UFG
 * Todos os direitos reservados.
 */

package br.gov.go.saude.hubsaude.client;

import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
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
     * @param pin            PIN de acesso ao token
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

        try {
            final KeyStore ks = KeyStore.getInstance("PKCS11", pkcs11Provider);
            ks.load(null, pin);

            final PrivateKey handle = (PrivateKey) ks.getKey(keyAlias, pin);
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
        }
    }

    /**
     * Cria estratégia a partir de KeyStore (JKS, PKCS#12).
     *
     * @param keyStore KeyStore carregado
     * @param alias    alias da chave privada
     * @param password senha da chave
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

        try {
            final PrivateKey key = (PrivateKey) keyStore.getKey(alias, password);
            if (key == null) {
                throw new SmartTokenException("Chave não encontrada no KeyStore: " + alias);
            }
            return new PrivateKeySigningStrategy(key);
        } catch (SmartTokenException e) {
            throw e;
        } catch (Exception e) {
            throw new SmartTokenException("Falha ao obter chave do KeyStore: " + e.getMessage(), e);
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
}
