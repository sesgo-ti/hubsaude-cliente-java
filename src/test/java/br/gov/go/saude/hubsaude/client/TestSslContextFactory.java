/*
 * Copyright (c) 2026 SES-GO / UFG
 * Todos os direitos reservados.
 */

package br.gov.go.saude.hubsaude.client;

import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Fábrica de {@link SSLContext} para uso exclusivo em testes.
 *
 * <p>
 * Esta classe contém métodos que <strong>NUNCA</strong> devem ser usados em produção,
 * por isso está localizada em {@code src/test/java} e não é incluída no artefato final.
 * </p>
 *
 * @see SslContextFactory para a implementação segura de produção
 */
public final class TestSslContextFactory {

    private static final Logger LOG = LoggerFactory.getLogger(TestSslContextFactory.class);

    private TestSslContextFactory() {
        // Utility class
    }

    /**
     * Cria um {@link SSLContext} que confia em todos os certificados.
     *
     * <p>
     * <strong>⚠️ ATENÇÃO: USO EXCLUSIVO PARA TESTES!</strong>
     * </p>
     *
     * <p>
     * Este método cria um contexto SSL que <strong>DESABILITA COMPLETAMENTE</strong>
     * a validação de certificados TLS, tornando a conexão vulnerável a:
     * </p>
     * <ul>
     *   <li>Ataques Man-in-the-Middle (MITM)</li>
     *   <li>Interceptação de tráfego</li>
     *   <li>Roubo de credenciais e tokens</li>
     *   <li>Violação de dados sensíveis de saúde</li>
     * </ul>
     *
     * <p>
     * Este método existe <strong>apenas</strong> em {@code src/test/java} e não é
     * incluído no artefato de produção, garantindo que não possa ser usado
     * acidentalmente em ambientes reais.
     * </p>
     *
     * @param tlsProtocol protocolo TLS (ex: "TLSv1.3", "TLSv1.2")
     * @return contexto SSL que aceita qualquer certificado (⚠️ INSEGURO)
     */
    public static SSLContext buildTrustAllSslContext(final String tlsProtocol) {
        LOG.warn("⚠️ Criando SSLContext trust-all ({}) - USO EXCLUSIVO PARA TESTES!", tlsProtocol);
        try {
            final TrustManager[] trustAll = {
                    new X509TrustManager() {
                        @Override
                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }

                        @Override
                        public void checkClientTrusted(
                                final X509Certificate[] c, final String a) {
                            // Trust all - não valida
                        }

                        @Override
                        public void checkServerTrusted(
                                final X509Certificate[] c, final String a) {
                            // Trust all - não valida
                        }
                    }
            };
            final SSLContext ctx = SSLContext.getInstance(tlsProtocol);
            ctx.init(null, trustAll, new SecureRandom());
            return ctx;
        } catch (Exception ex) {
            throw new SmartTokenException(
                    "Falha ao criar SSLContext trust-all com protocolo '" + tlsProtocol + "'", ex);
        }
    }
}
