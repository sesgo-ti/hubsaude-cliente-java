/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.hubsaude.client;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Validações fail-fast de consistência entre o material de assinatura
 * (chave privada ou {@link SigningStrategy}) e o certificado X.509 do
 * cliente.
 *
 * <p>
 * A verificação realiza uma assinatura de teste e a confere com a chave
 * pública extraída do certificado. Assim, erros de configuração (arquivos
 * trocados, chave corrompida, certificado regenerado sem atualizar a
 * chave) são detectados na inicialização, e não apenas quando o
 * authorization server rejeitar o {@code client_assertion}.
 * </p>
 */
final class KeyCertificateConsistency {

    private static final Logger LOG = LoggerFactory.getLogger(KeyCertificateConsistency.class);

    /** Dados de desafio usados na assinatura de teste. */
    private static final byte[] CHALLENGE =
            "key-pair-consistency-check".getBytes(StandardCharsets.UTF_8);

    private KeyCertificateConsistency() {
    }

    /**
     * Verifica que a chave privada corresponde à chave pública do
     * certificado, assinando um desafio e conferindo a assinatura.
     *
     * @param privateKey  chave privada a validar
     * @param certificate certificado X.509 contendo a chave pública
     *                    correspondente
     * @throws SmartTokenException se a assinatura de teste falhar,
     *                             indicando que chave e certificado não
     *                             formam um par válido
     */
    static void verifyKeyPair(final PrivateKey privateKey, final X509Certificate certificate) {
        try {
            final String signatureAlgorithm = determineSignatureAlgorithm(privateKey);

            final Signature signer = Signature.getInstance(signatureAlgorithm);
            signer.initSign(privateKey);
            signer.update(CHALLENGE);
            final byte[] signature = signer.sign();

            verifySignature(certificate, signatureAlgorithm, signature);
            LOG.trace("Verificação de consistência key-cert concluída com sucesso");
        } catch (SmartTokenException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new SmartTokenException(
                    "Falha ao verificar consistência entre chave privada e certificado: "
                            + ex.getMessage(), ex);
        }
    }

    /**
     * Verifica que a estratégia de assinatura é consistente com o
     * certificado do cliente.
     *
     * <p>
     * A assinatura de teste é produzida pela própria estratégia (o que
     * funciona inclusive para HSM/PKCS#11, pois a assinatura é delegada ao
     * hardware) e verificada com a chave pública do certificado, usando o
     * mesmo algoritmo e parâmetros da estratégia.
     * </p>
     *
     * <p>
     * <strong>Limitação:</strong> a verificação só é possível quando a
     * estratégia é uma {@link PrivateKeySigningStrategy}, pois é necessário
     * conhecer o algoritmo JCA para verificar a assinatura. Estratégias
     * customizadas são aceitas sem validação.
     * </p>
     *
     * @param strategy    estratégia de assinatura a validar
     * @param certificate certificado X.509 com a chave pública correspondente
     * @throws SmartTokenException se a assinatura de teste não puder ser
     *                             verificada com a chave pública do
     *                             certificado
     */
    static void verifyStrategy(final SigningStrategy strategy, final X509Certificate certificate) {
        if (!(strategy instanceof PrivateKeySigningStrategy pkStrategy)) {
            LOG.debug("Estratégia de assinatura customizada: consistência com o"
                    + " certificado não pode ser verificada automaticamente");
            return;
        }
        try {
            final byte[] signature = pkStrategy.sign(CHALLENGE);

            final Signature verifier = Signature.getInstance(pkStrategy.getAlgorithm());
            if (pkStrategy.getParameterSpec() != null) {
                verifier.setParameter(pkStrategy.getParameterSpec());
            }
            verifier.initVerify(certificate.getPublicKey());
            verifier.update(CHALLENGE);
            if (!verifier.verify(signature)) {
                throw new SmartTokenException(
                        "Chave privada não corresponde ao certificado: assinatura inválida");
            }
            LOG.trace("Verificação de consistência estratégia-certificado concluída com sucesso");
        } catch (SmartTokenException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new SmartTokenException(
                    "Falha ao verificar consistência entre chave privada e certificado: "
                            + ex.getMessage(), ex);
        }
    }

    /**
     * Confere a assinatura de teste com a chave pública do certificado.
     */
    private static void verifySignature(
            final X509Certificate certificate,
            final String signatureAlgorithm,
            final byte[] signature) throws GeneralSecurityException {
        final Signature verifier = Signature.getInstance(signatureAlgorithm);
        verifier.initVerify(certificate.getPublicKey());
        verifier.update(CHALLENGE);
        if (!verifier.verify(signature)) {
            throw new SmartTokenException(
                    "Chave privada não corresponde ao certificado: assinatura inválida");
        }
    }

    /**
     * Determina o algoritmo de assinatura apropriado para o tipo de chave.
     */
    private static String determineSignatureAlgorithm(final PrivateKey privateKey) {
        final String keyAlgorithm = privateKey.getAlgorithm();
        return switch (keyAlgorithm) {
            case "RSA" -> "SHA256withRSA";
            case "EC" -> "SHA256withECDSA";
            case "Ed25519" -> "Ed25519";
            case "Ed448" -> "Ed448";
            default -> throw new SmartTokenException(
                    "Tipo de chave não suportado para validação: " + keyAlgorithm);
        };
    }
}
