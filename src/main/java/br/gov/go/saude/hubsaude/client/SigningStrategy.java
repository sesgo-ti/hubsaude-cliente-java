/*
 * Copyright (c) 2026 SES-GO / UFG
 * Todos os direitos reservados.
 */

package br.gov.go.saude.hubsaude.client;

/**
 * Estratégia de assinatura digital que abstrai o mecanismo criptográfico.
 *
 * <p>
 * Esta interface permite desacoplar a operação de assinatura da fonte
 * do material criptográfico. Implementações podem utilizar:
 * </p>
 * <ul>
 *   <li>Chaves em memória (carregadas de arquivos PEM)</li>
 *   <li>HSM/Smart Tokens via PKCS#11 (chave nunca sai do hardware)</li>
 *   <li>Serviços remotos de assinatura (ex: HashiCorp Vault Transit)</li>
 * </ul>
 *
 * <h2>Design Pattern</h2>
 * <p>
 * Implementa o padrão Strategy, permitindo que diferentes algoritmos de
 * assinatura sejam intercambiáveis sem modificar o cliente.
 * </p>
 *
 * <h2>Segurança</h2>
 * <p>
 * Este design é especialmente importante para cenários enterprise onde
 * chaves privadas não podem ser exportadas do hardware de segurança (HSM).
 * A abstração na operação (não no acesso à chave) permite uso transparente
 * de handles PKCS#11 que delegam a assinatura ao dispositivo.
 * </p>
 *
 * @see PrivateKeySigningStrategy implementação padrão baseada em PrivateKey
 * @see SigningStrategyFactory factory methods para criação de estratégias
 */
@FunctionalInterface
public interface SigningStrategy {

    /**
     * Assina os dados fornecidos usando o mecanismo criptográfico configurado.
     *
     * <p>
     * A implementação é responsável por garantir que o algoritmo de assinatura
     * seja apropriado para o caso de uso. Para SMART Backend Services, o algoritmo
     * esperado é {@code SHA256withRSA} (RS256).
     * </p>
     *
     * @param data bytes a serem assinados (tipicamente o header.payload do JWT)
     * @return assinatura digital em formato raw (não Base64)
     * @throws SigningException se ocorrer erro durante a assinatura
     */
    byte[] sign(byte[] data);
}
