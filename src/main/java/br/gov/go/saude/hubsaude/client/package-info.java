/*
 * Copyright (c) 2026 SES-GO / UFG
 * Todos os direitos reservados.
 */

/**
 * Biblioteca cliente Java do HubSaúde para obtenção de access tokens
 * SMART Backend Services ({@code client_credentials} +
 * {@code private_key_jwt}, RFC 7523).
 *
 * <p>O ponto de entrada é {@code SmartTokenClient} (construído por
 * {@code SmartTokenClientBuilder}), que assina o {@code client_assertion}
 * com o material criptográfico do estabelecimento e negocia o token no
 * authorization server. O pacote reúne os colaboradores dessa jornada:
 * estratégias de assinatura ({@code SigningStrategy} e sua factory),
 * carga e validação de material PEM ({@code PemLoader},
 * {@code KeyCertificateConsistency}), tolerância a falhas com retry
 * exponencial ({@code FaultToleranceConfig}, {@code RetryPolicy}),
 * salvaguardas de sanidade da resposta do token endpoint
 * ({@code TokenResponseGuard}, issue #730), fábrica de
 * {@code SSLContext} para mTLS e propagação de contexto de trace W3C
 * ({@code TraceContext}).</p>
 *
 * <p>A biblioteca é distribuída para consumidores externos ao
 * monorepo; seu contrato público segue compatibilidade
 * <em>forward</em> e as exceções de domínio ({@code SmartTokenException},
 * {@code SigningException}) não vazam detalhes de credenciais.</p>
 */
package br.gov.go.saude.hubsaude.client;
