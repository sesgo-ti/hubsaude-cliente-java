/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.hubsaude.client;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;

import javax.crypto.AEADBadTagException;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Testes da heurística {@link ErrorClassifier#isLikelyClientCertificateRejection(Throwable)},
 * usada para reconhecer falhas de TLS/mTLS que tipicamente ocorrem quando o
 * servidor de autorização rejeita o certificado do cliente (revogado,
 * expirado ou não confiável) sem produzir uma resposta HTTP de erro
 * adequada — observado em produção como {@code bad_record_mac} no peer
 * OpenSSL e {@link AEADBadTagException} no peer JSSE.
 *
 * <p>Reproduzir o cenário real exigiria um servidor TLS misbehaving;
 * estes testes validam apenas o reconhecimento das cadeias de exceções
 * que o {@link java.net.http.HttpClient} produz nesses casos.
 */
class SmartTokenClientCertRejectionTest {

    @Nested
    @DisplayName("Casos que DEVEM ser identificados como rejeição de certificado de cliente")
    class CasosPositivos {

        @Test
        @DisplayName("AEADBadTagException direto")
        void aeadDirect() {
            final Throwable ex = new AEADBadTagException("Tag mismatch");

            assertThat(ErrorClassifier.isLikelyClientCertificateRejection(ex)).isTrue();
        }

        @Test
        @DisplayName("AEADBadTagException encapsulada em IOException (caso real do HttpClient)")
        void aeadAninhada() {
            final Throwable cause = new AEADBadTagException("Tag mismatch");
            final Throwable wrapper = new SSLException("Tag mismatch!", cause);
            final Throwable ex = new IOException("Falha de leitura TLS", wrapper);

            assertThat(ErrorClassifier.isLikelyClientCertificateRejection(ex)).isTrue();
        }

        @Test
        @DisplayName("SSLHandshakeException — rejeição durante o handshake")
        void sslHandshake() {
            final Throwable ex = new SSLHandshakeException("Received fatal alert: certificate_revoked");

            assertThat(ErrorClassifier.isLikelyClientCertificateRejection(ex)).isTrue();
        }

        @Test
        @DisplayName("SSLException com mensagem bad_record_mac")
        void badRecordMac() {
            final Throwable ex = new SSLException("Received fatal alert: bad_record_mac");

            assertThat(ErrorClassifier.isLikelyClientCertificateRejection(ex)).isTrue();
        }

        @Test
        @DisplayName("SSLException com mensagem em maiúsculas (case-insensitive)")
        void badRecordMacCaseInsensitive() {
            final Throwable ex = new SSLException("RECEIVED FATAL ALERT: BAD_RECORD_MAC");

            assertThat(ErrorClassifier.isLikelyClientCertificateRejection(ex)).isTrue();
        }
    }

    @Nested
    @DisplayName("Casos que NÃO devem ser identificados (evitar falsos positivos)")
    class CasosNegativos {

        @Test
        @DisplayName("IOException genérica (ex: connection reset)")
        void ioGenerica() {
            final Throwable ex = new IOException("Connection reset");

            assertThat(ErrorClassifier.isLikelyClientCertificateRejection(ex)).isFalse();
        }

        @Test
        @DisplayName("SSLException sem mensagem específica")
        void sslGenerica() {
            final Throwable ex = new SSLException("Generic TLS failure");

            assertThat(ErrorClassifier.isLikelyClientCertificateRejection(ex)).isFalse();
        }

        @Test
        @DisplayName("SSLException com message null não causa NPE")
        void sslMessageNull() {
            final Throwable ex = new SSLException((String) null);

            assertThat(ErrorClassifier.isLikelyClientCertificateRejection(ex)).isFalse();
        }

        @Test
        @DisplayName("Causa null não causa NPE")
        void causaNull() {
            assertThat(ErrorClassifier.isLikelyClientCertificateRejection(null)).isFalse();
        }

        @Test
        @DisplayName("PKIX path building failed — cliente rejeitou o certificado do servidor")
        void pkixPathBuildingFailed() {
            // Cadeia real do JDK quando o trust anchor não valida o servidor
            final Throwable root = new java.security.cert.CertPathBuilderException(
                    "unable to find valid certification path to requested target");
            final Throwable validator = new java.security.cert.CertificateException(
                    "PKIX path building failed", root);
            final Throwable handshake = new SSLHandshakeException("PKIX path building failed");
            handshake.initCause(validator);
            final Throwable ex = new IOException("TLS failure", handshake);

            assertThat(ErrorClassifier.isLikelyClientCertificateRejection(ex)).isFalse();
        }

        @Test
        @DisplayName("Certificado do servidor expirado — validação local, não rejeição mTLS")
        void certificadoServidorExpirado() {
            final Throwable root = new java.security.cert.CertificateExpiredException(
                    "NotAfter: Wed Jan 01 00:00:00 BRT 2020");
            final Throwable handshake = new SSLHandshakeException("PKIX path validation failed");
            handshake.initCause(root);

            assertThat(ErrorClassifier.isLikelyClientCertificateRejection(handshake)).isFalse();
        }
    }
}
