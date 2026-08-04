# Changelog

Todas as mudanças notáveis neste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/),
e este projeto adere ao [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [Unreleased]

## [0.4.0] - 2026-08-04

### Removido
- **Mudança incompatível:** os sete construtores públicos de
  `SmartTokenClient` foram removidos. A criação do cliente passa a ocorrer
  exclusivamente por `SmartTokenClient.builder()` (#1959).

### Alterado
- Série promovida para `0.4.0` devido à mudança incompatível durante a fase
  pré-`1.0.0`; próximo ciclo avançado para `0.4.1-SNAPSHOT` após a release
  (#1959, #1962).
- JavaDoc passou a integrar o perfil `quality`, com doclint ativo e qualquer
  aviso tratado como falha; o mesmo gate foi aplicado aos artefatos de release
  (#1959).
- Fronteira da API pública e política de compatibilidade pré-`1.0.0`
  explicitadas no README e no guia de contribuição (#1959).

### Corrigido
- Versão estável do README alinhada à tag mais recente e distinção entre
  release publicada e o próximo `-SNAPSHOT` explicitada.
- Contratos de lifecycle, cache LRU, defaults tolerantes e erros
  sincronizados entre README, especificação e JavaDoc (#1956).
- Cabeçalho de `package-info.java`, limite de linhas para contribuição e
  caminho do plano de publicação alinhados às fontes normativas (#1956).

### Adicionado
- Guia de integração enterprise para ownership, fechamento, circuit
  breaker, métricas e observabilidade, retirando tutoriais de frameworks
  do JavaDoc da classe principal (#1956).

## [0.3.29] - 2026-08-04

### Alterado
- Dependências fora dos blocos soberanos Spring Boot/HAPI FHIR
  atualizadas após reconciliação dos alertas de segurança (#1937).
- Portfólio oficial de SDKs registrado, mantendo Java como implementação
  de referência do contrato comportamental (#1939).

## [0.3.28] - 2026-08-03

### Alterado
- `org.slf4j:slf4j-api` atualizado para 2.0.18 (#1891).

## [0.3.27] - 2026-08-03

### Alterado
- Release técnica de versionamento, sem alteração funcional em relação à
  0.3.26 (#1887).

## [0.3.26] - 2026-08-02

### Corrigido
- Cache LRU interno deixou de herdar comportamento de clonagem de
  `LinkedHashMap`, reduzindo superfície e estado desnecessários (#1871).

## [0.3.25] - 2026-08-02

### Adicionado
- Teto configurável do cache por scope (`tokenCacheMaxEntries`, padrão
  1.000) com descarte LRU, limitando memória em aplicações long-lived
  (#1843).

### Corrigido
- `close()` passou a coordenar operações em voo, invalidar o cache e
  rejeitar novas obtenções após o fechamento (#1843).
- Gates de rastreabilidade e testes deixaram de aceitar relatórios
  ausentes ou corrompidos como sucesso (#1846).

## [0.3.24] - 2026-08-02

### Alterado
- Gates de arquitetura, Checkstyle, PMD e plugins de build atualizados
  para os degraus de qualidade vigentes (#1712, #1749, #1788, #1796,
  #1797, #1801).
- Fixtures e clientes HTTP dos testes passaram a ser encerrados
  deterministicamente; charset, locale e filtros de artefatos foram
  tornados portáveis entre Linux e Windows (#1810, #1814).

## [0.3.23] - 2026-07-24

### Alterado
- Checkstyle e PMD do perfil `quality` passaram a consumir as
  configurações centrais do `hubsaude-build-tools`, eliminando cópias
  locais sujeitas a drift (#1603, #1638).
- `SmartTokenClient` foi decomposto em colaboradores internos para
  reduzir complexidade sem alterar a API pública (#1032, #1655).
- Workflows passaram a reutilizar pipelines comuns de CI, mutação e
  quarentena (#1653, #1656).

### Segurança
- `tools.jackson.core:jackson-databind` atualizado para 3.1.5 (#1633).

## [0.3.22] - 2026-07-21

### Alterado
- Bouncy Castle e Checkstyle atualizados; regras locais de PMD,
  Checkstyle e SpotBugs sincronizadas antes da centralização posterior
  (#1524, #1525, #1607, #1636).

## [0.3.21] - 2026-07-20

### Alterado
- Testes classificados pela convenção `@TesteN0` a `@TesteN5`, com
  relatório de orçamento por nível (#1404, #1459).

## [0.3.20] - 2026-07-15

### Adicionado
- Emissão de `traceparent` W3C no token endpoint e na descoberta
  `.well-known`, com novo trace-id por tentativa e correlação nos erros
  (#1298, #1377).

### Corrigido
- `keyAlias` passou a selecionar deterministicamente o certificado no
  handshake mTLS, inclusive em KeyStores com múltiplas entradas (#1411,
  #1418).

## [0.3.19] - 2026-07-12

### Segurança
- Chaves RSA menores que 2048 bits e EC menores que P-256 passaram a ser
  rejeitadas conforme NIST SP 800-57 (#727, #1318).
- PEM de chave privada deixou de ser materializado como `String`; buffers
  temporários passaram a ser zerados em todos os caminhos (#728, #1321).
- Senhas e PINs passaram a usar cópias defensivas internas, zeradas sem
  modificar o array pertencente ao chamador (#726, #1323).

### Corrigido
- `expires_in` passou a ser validado e o corpo da resposta do token
  endpoint recebeu limite seguro para diagnóstico (#1325).

## [0.3.18] - 2026-07-12

### Alterado
- Release técnica de versionamento, sem alteração funcional em relação à
  0.3.17 (#1306).

## [0.3.17] - 2026-07-11

### Segurança
- Actions externas dos workflows foram fixadas por SHA (#1000).

### Alterado
- Testes flaky passaram a usar quarentena explícita no merge gate
  (#1149, #1166).

## [0.3.16] - 2026-07-10

### Alterado
- Release técnica de versionamento, sem alteração funcional em relação à
  0.3.15.

## [0.3.15] - 2026-07-10

### Adicionado
- Claim `hub_ctx`, algoritmo padrão RS384, suporte a ES384/chaves EC e
  seleção opcional por `kid` no client assertion (#1109).
- Guia multi-plataforma de troubleshooting TLS (#1142).

### Corrigido
- Semântica normativa do `kid` alinhada entre especificação e
  implementação (#1147).

## [0.3.14] - 2026-07-09

### Corrigido
- Links, exemplos e inconsistências documentais de baixo risco
  corrigidos após revisão do projeto (#1006).

### Alterado
- Workflows de teste passaram a cancelar execuções sobrepostas; dívida de
  classes extensas foi registrada no backlog (#1021, #1037).

## [0.3.13] - 2026-07-07

### Segurança
- Certificados X.509 fornecidos em memória (construtores com
  `X509Certificate`, `loadCertificateFromString`, `buildSslContext` e
  `buildKeyManagers`) agora têm a validade temporal verificada
  (fail-fast em certificado expirado ou ainda não válido), como já
  ocorria para certificados carregados de arquivo (#748).
- As senhas fornecidas ao builder (`privateKeyPassword` e a senha de
  `clientKeyStore`) são consumidas — zeradas — ao final de `build()`,
  inclusive em caso de erro; `loadPrivateKeyFromString` zera a senha
  em todos os caminhos, mesmo quando a chave não é criptografada
  (RNF-03) (#748).
- `sanitizeErrorResponse` agora redige `access_token` **antes** de
  truncar o corpo da resposta, evitando vazamento de tokens em
  mensagens de erro longas (> 500 caracteres) (#725).
- `toString()` dos records `TokenResponse` e `CachedToken` mascara
  `accessToken` e `rawJson` (`[REDACTED]`), evitando exposição
  acidental de tokens em logs (#725).
- `tokenEndpoint`/`fhirBase` (e o `token_endpoint` descoberto via
  `.well-known`) agora exigem esquema `https`; `http` é aceito apenas
  para `localhost`/`127.0.0.1` (#725).

### Corrigido
- A heurística de rejeição de certificado de cliente (RF-08) não é
  mais acionada quando a falha decorre da validação do certificado do
  **servidor** pelo cliente (ex.: `PKIX path building failed`,
  certificado do servidor expirado) — a cadeia de causas com
  `CertificateException`/`CertPath*Exception` é excluída, evitando
  diagnóstico enganoso (#748).
- Javadocs corrigidos: construtor padrão de `PrivateKeySigningStrategy`
  documentava SHA384withRSA (o padrão é SHA256withRSA/RS256), nota de
  `jwtAlgorithm(String)` afirmava que o algoritmo afetava apenas o
  header do JWT, e `SCOPE_LOCK_STRIPES` descrevia memória O(N) em vez
  de O(1) (#748).
- `ESPECIFICACAO.md` atualizado: rastreabilidade RF-07 apontava método
  inexistente (`obtainTokenWithRetry()`), nota §9.3 afirmava que ES*
  produzia DER sem conversão (o código usa `...inP1363Format`),
  parâmetro `keyId` ausente do §8 e RF-01.2 não mencionava o `kid`
  opcional (#748).
- ES256/ES384/ES512 agora produzem assinaturas no formato R||S
  (P1363), conforme RFC 7518 §3.4 — antes era emitido DER (#725).
- PS256/PS384/PS512 agora usam `RSASSA-PSS` com `PSSParameterSpec`
  adequado por variante, disponível no JDK sem exigir o provider
  BouncyCastle registrado (#725).
- O parâmetro `certificate` do construtor de 9 argumentos deixou de
  ser ignorado: quando presente, a consistência entre chave privada e
  certificado é verificada de forma fail-fast (#725).
- `jwtAlgorithm` é validado no construtor com a mesma allowlist da
  fábrica de estratégias (rejeita `none`, `HS256` e valores
  arbitrários) (#725).
- Documentação corrigida: exemplo do README usava API inexistente
  (`certificate(cert)`), versões divergentes entre badge/exemplo/POM,
  referências incorretas a Maven Central em SECURITY.md e no POM, e
  comando de build inválido em CONTRIBUTING.md (#725).
- Testes flaky corrigidos: backoff verificado por injeção de `Sleeper`
  (sem medir tempo real) e teste de integração do JAR usa porta
  efêmera em vez da porta fixa 8443 (#725).
- JaCoCo: removida exclusão inócua `**/SigningStrategyFactory$*Pkcs11*`
  (JaCoCo filtra classes, não métodos; o padrão não casava nada) e
  adicionada execução `prepare-agent`, sem a qual o `jacoco:check` era
  pulado por ausência de `jacoco.exec` — o gate de 85% agora é
  efetivamente aplicado (#734).

### Adicionado
- Suporte opcional ao header `kid` no client assertion via
  `SmartTokenClientBuilder.keyId(String)` (#725).
- `SmartTokenClient` implementa `AutoCloseable`; `close()` idempotente
  encerra o `HttpClient` interno (#725).

### Alterado
- Retry automático restrito a falhas transitórias de rede (timeouts,
  recusa/queda de conexão TCP), conforme RF-07: respostas HTTP
  recebidas (429/5xx inclusive) **não** sofrem retry — a decisão de
  aguardar e reenviar é do chamador; o header `Retry-After`, quando
  presente, é incluído na mensagem de erro como diagnóstico (#748).
- `invalidateCache(scope)` agora loga em nível `info`, como a
  invalidação global (RNF-02.3) (#748).
- O backoff entre tentativas não dorme mais segurando o lock por
  escopo; a espera ocorre fora da seção crítica (#725).
- Header do JWT montado via Jackson (`ObjectNode`) em vez de
  concatenação de strings (#725).
- Projeto desacoplado: removido `<parent>` e import de BOM externo.
  POM publicado é auto-suficiente (`flatten-maven-plugin` modo `oss`).
- Versões das dependências declaradas explicitamente no próprio POM.

## [0.1.6 – 0.3.12]

> **Nota**: as releases entre 0.1.5 e 0.3.12 foram publicadas sem que
> este changelog fosse atualizado. O intervalo consolidou evoluções
> incrementais de empacotamento, publicação no GitHub Packages,
> qualidade de build (perfis `quality` e `security`) e ajustes de
> documentação. Detalhes por versão podem ser consultados no histórico
> de commits e tags do repositório.

## [0.1.5] - 2026-05-20

### Adicionado
- Classe `FaultToleranceConfig` para agrupar parâmetros de resiliência
- Testes unitários para `FaultToleranceConfig`
- Arquivo `.gitignore` com exclusões padrão para Java/Maven/IDEs
- Arquivo `CHANGELOG.md`

### Alterado
- `SmartTokenClient` refatorado para usar `FaultToleranceConfig`
- `SmartTokenClientBuilder` atualizado para construir `FaultToleranceConfig`
- Cabeçalho de licença dos arquivos `.java` alinhado ao Apache-2.0
  (SPDX-License-Identifier + texto Apache)

## [0.0.0-SNAPSHOT] - 2026-03-07

### Adicionado
- Implementação inicial do cliente SMART Backend Services
- `SmartTokenClient` - classe principal para obtenção de tokens
- `SmartTokenClientBuilder` - builder fluente para configuração
- `SigningStrategy` - interface para estratégias de assinatura
- `PrivateKeySigningStrategy` - implementação padrão com PrivateKey
- `SigningStrategyFactory` - factory para criação de estratégias
- `PemLoader` - utilitário para carregamento de arquivos PEM
- `SslContextFactory` - factory para construção de SSLContext
- Suporte a chaves PEM (PKCS#1, PKCS#8, criptografadas)
- Suporte a HSM via PKCS#11
- Suporte a KeyStore (JKS, PKCS#12)
- Cache de tokens thread-safe
- Retry com backoff exponencial
- Descoberta automática de token_endpoint via .well-known
- Validação de consistência chave-certificado
- TLS 1.3 por padrão
- Documentação completa com exemplos
- Guia de troubleshooting (`problemas.md`)
- Testes unitários com cobertura mínima de 85%
- Testes de integração com simulador

### Segurança
- Senhas tratadas como `char[]` com limpeza de memória
- Tokens sanitizados em logs de erro
- Validação de certificados expirados
- Suporte a trust anchors customizados

---

## Convenções de Versionamento

- **MAJOR**: Mudanças incompatíveis na API pública
- **MINOR**: Novas funcionalidades compatíveis com versões anteriores
- **PATCH**: Correções de bugs compatíveis com versões anteriores

## Links

- [Repositório](https://github.com/FabricaDeSoftwareINF/server-hubsaude)
- [Documentação SMART Backend Services](https://hl7.org/fhir/smart-app-launch/backend-services.html)
