/*
 * Copyright (c) 2026 SES-GO / UFG
 * Todos os direitos reservados.
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
 * Testes da heurística {@link SmartTokenClient#isLikelyClientCertificateRejection(Throwable)},
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

            assertThat(SmartTokenClient.isLikelyClientCertificateRejection(ex)).isTrue();
        }

        @Test
        @DisplayName("AEADBadTagException encapsulada em IOException (caso real do HttpClient)")
        void aeadAninhada() {
            final Throwable cause = new AEADBadTagException("Tag mismatch");
            final Throwable wrapper = new SSLException("Tag mismatch!", cause);
            final Throwable ex = new IOException("Falha de leitura TLS", wrapper);

            assertThat(SmartTokenClient.isLikelyClientCertificateRejection(ex)).isTrue();
        }

        @Test
        @DisplayName("SSLHandshakeException — rejeição durante o handshake")
        void sslHandshake() {
            final Throwable ex = new SSLHandshakeException("Received fatal alert: certificate_revoked");

            assertThat(SmartTokenClient.isLikelyClientCertificateRejection(ex)).isTrue();
        }

        @Test
        @DisplayName("SSLException com mensagem bad_record_mac")
        void badRecordMac() {
            final Throwable ex = new SSLException("Received fatal alert: bad_record_mac");

            assertThat(SmartTokenClient.isLikelyClientCertificateRejection(ex)).isTrue();
        }

        @Test
        @DisplayName("SSLException com mensagem em maiúsculas (case-insensitive)")
        void badRecordMacCaseInsensitive() {
            final Throwable ex = new SSLException("RECEIVED FATAL ALERT: BAD_RECORD_MAC");

            assertThat(SmartTokenClient.isLikelyClientCertificateRejection(ex)).isTrue();
        }
    }

    @Nested
    @DisplayName("Casos que NÃO devem ser identificados (evitar falsos positivos)")
    class CasosNegativos {

        @Test
        @DisplayName("IOException genérica (ex: connection reset)")
        void ioGenerica() {
            final Throwable ex = new IOException("Connection reset");

            assertThat(SmartTokenClient.isLikelyClientCertificateRejection(ex)).isFalse();
        }

        @Test
        @DisplayName("SSLException sem mensagem específica")
        void sslGenerica() {
            final Throwable ex = new SSLException("Generic TLS failure");

            assertThat(SmartTokenClient.isLikelyClientCertificateRejection(ex)).isFalse();
        }

        @Test
        @DisplayName("SSLException com message null não causa NPE")
        void sslMessageNull() {
            final Throwable ex = new SSLException((String) null);

            assertThat(SmartTokenClient.isLikelyClientCertificateRejection(ex)).isFalse();
        }

        @Test
        @DisplayName("Causa null não causa NPE")
        void causaNull() {
            assertThat(SmartTokenClient.isLikelyClientCertificateRejection(null)).isFalse();
        }
    }
}
