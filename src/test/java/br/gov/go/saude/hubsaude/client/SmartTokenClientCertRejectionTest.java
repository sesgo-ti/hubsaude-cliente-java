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

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;

import javax.crypto.AEADBadTagException;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import br.gov.go.saude.hubsaude.core.rastreabilidade.Requirement;
import br.gov.go.saude.hubsaude.core.rastreabilidade.Requirements;
import br.gov.go.saude.hubsaude.core.rastreabilidade.Hazard;

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
@Requirements({@Requirement("C1"), @Requirement("P5"), @Requirement("C11")})
@Hazard("H-SEC-004")
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
