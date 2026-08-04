# hubsaude-cliente-java

[![Version](https://img.shields.io/badge/Version-0.4.0-yellow)](https://github.com/FabricaDeSoftwareINF/server-hubsaude/tree/cliente-java-v0.4.0/hubsaude/projetos/hubsaude-cliente-java)
[![Java 21+](https://img.shields.io/badge/Java-21%2B-blue)](https://openjdk.org/)
[![Maven](https://img.shields.io/badge/Maven-3.9%2B-orange)](https://maven.apache.org/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

Cliente Java para obtenção de tokens de acesso ao HubSaúde via
[SMART Backend Services](https://hl7.org/fhir/smart-app-launch/backend-services.html)
(SMART-on-FHIR). Encapsula a montagem do JWT *client assertion*, sua
assinatura e a troca pelo *access token* no endpoint OAuth 2.0.

O contrato comportamental está em [`ESPECIFICACAO.md`](ESPECIFICACAO.md)
— requisitos normativos que refletem esta implementação e servem de
referência para o portfólio oficial de SDKs: Java, TypeScript/Node.js
(consumível também por JavaScript), C#/.NET e Python.

## Dependência Maven

```xml
<dependency>
    <groupId>br.gov.go.saude.hubsaude</groupId>
    <artifactId>hubsaude-cliente-java</artifactId>
    <version>0.4.0</version>
</dependency>
```

Publicado no GitHub Packages
(`maven.pkg.github.com/FabricaDeSoftwareINF/server-hubsaude`).
Autenticação requerida mesmo para leitura: configure `~/.m2/settings.xml`
com um Personal Access Token (escopo `read:packages`).

`0.4.0` é a última versão estável publicada. O `pom.xml` da branch
`develop` usa `0.4.1-SNAPSHOT` para o próximo ciclo de desenvolvimento;
esse snapshot não substitui a versão estável do snippet acima.

## Política da API pública

Enquanto a biblioteca estiver na série `0.x`, sua API é provisória:
versões `MINOR` podem introduzir mudanças incompatíveis e versões `PATCH`
preservam compatibilidade. A partir de `1.0.0`, a evolução seguirá
estritamente o
[Versionamento Semântico 2.0.0](https://semver.org/lang/pt-BR/).

Todos os tipos e membros declarados como `public` no pacote
`br.gov.go.saude.hubsaude.client` integram a API pública. Tipos e membros
com visibilidade de pacote ou `private` são detalhes internos e podem
mudar sem aviso. A criação de `SmartTokenClient` é feita
**exclusivamente** por `SmartTokenClient.builder()`; a classe não expõe
construtores públicos.

## Uso básico

```java
var client = SmartTokenClient.builder()
        .tokenEndpoint("https://hub.saude.go.gov.br/auth/token")
        .clientId("meu-sistema")
        .privateKeyPem(Path.of("chave-privada.pem"))
        .certificatePem(Path.of("certificado.pem"))
        .build();

String token = client.obtainToken("system/Patient.rs");
```

A instância é **thread-safe**, mantém cache do token (renovado conforme
margem de expiração) e executa *retries* com *backoff* exponencial.
Reutilize a mesma instância pelo ciclo de vida da aplicação e invoque
`close()` uma única vez no encerramento da aplicação.

## Ciclo de vida, cache e erros

`SmartTokenClient` implementa `AutoCloseable`. Seu `close()` é
idempotente, aguarda operações em voo, encerra o `HttpClient` interno e
invalida todo o cache. Após o fechamento, novas obtenções de token falham
com `IllegalStateException`. Em aplicações long-lived, registre a
instância como singleton no mecanismo de lifecycle do contêiner; use
*try-with-resources* apenas em CLIs, jobs curtos e testes.

As operações de token podem propagar:

| Tipo | Situação |
|------|----------|
| `IOException` | Falha de rede não recuperada pelos retries internos |
| `InterruptedException` | Interrupção durante requisição ou backoff; propague-a ou restaure o estado de interrupção |
| `SmartTokenException` | Configuração criptográfica inválida, resposta HTTP/JSON inválida ou algoritmo não suportado |
| `SigningException` | Falha da estratégia criptográfica ao assinar o `client_assertion` |

Após receber `401` ao usar um token em um endpoint FHIR, invalide a
entrada antes de obter um novo token:

```java
client.invalidateCache("system/Patient.rs");
String renewedToken = client.obtainToken("system/Patient.rs");
```

Não repita indefinidamente após um novo `401`: trate a recorrência como
falha de credencial, consentimento ou autorização. Consulte o
[guia de integração enterprise](docs/integracao-enterprise.md) para
lifecycle, circuit breaker, métricas e observabilidade.

## Fontes de chave (`SigningStrategy`)

A escolha de *onde* a chave privada reside é a decisão arquitetural
mais relevante para uma integração de produção:

| Fonte | Quando usar | Exposição da chave |
|-------|-------------|--------------------|
| PEM (PKCS#8) | Prototipação e testes | Arquivo em claro no disco |
| PEM com senha | Mitigação adicional quando PEM é inevitável | Cifrada em disco; senha em runtime |
| PKCS#12 direto | **Recomendado para produção** com chaves em software | Permanece dentro do `KeyStore` |
| HSM via PKCS#11 | Produção com chave não-exportável | Nunca sai do hardware |
| OpenBao (cofre) | Chave provisionada por cofre central | Buscada em runtime; nunca em disco |

### Tamanho mínimo de chave

Chaves fracas são rejeitadas no carregamento e na construção da
estratégia de assinatura (fail-fast, `IllegalArgumentException`),
conforme NIST SP 800-57:

| Algoritmo | Mínimo aceito |
|-----------|---------------|
| RSA | 2048 bits (módulo) |
| EC | P-256 (campo de 256 bits) |

Handles PKCS#11 opacos que não expõem os parâmetros da chave não são
validados (a política de tamanho fica a cargo do HSM).

### PKCS#12 direto

```java
KeyStore ks = KeyStore.getInstance("PKCS12");
try (var fis = new FileInputStream("certificado.pfx")) {
    ks.load(fis, "senha-pfx".toCharArray());
}

SigningStrategy strategy = SigningStrategyFactory.fromKeyStore(
        ks, "alias-da-chave", "senha-chave".toCharArray());

var client = SmartTokenClient.builder()
        .tokenEndpoint("https://hub.saude.go.gov.br/auth/token")
        .clientId("meu-sistema")
        .signingStrategy(strategy)
        // mTLS com a mesma chave/certificado do KeyStore (opcional)
        .clientKeyStore(ks, "alias-da-chave", "senha-chave".toCharArray())
        .build();
```

### HSM via PKCS#11

```java
Provider pkcs11 = SigningStrategyFactory.configurePkcs11Provider("/etc/pkcs11/hsm.cfg");
SigningStrategy strategy = SigningStrategyFactory.fromPkcs11(
        pkcs11, "alias-chave-hsm", "123456".toCharArray()); // PIN

var client = SmartTokenClient.builder()
        .signingStrategy(strategy)
        // ...
        .build();
```

### OpenBao / chave já carregada

```java
PrivateKey key = baoClient.getPrivateKey("secret/data/hubsaude/key");
SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(key);
```

### PEM com senha

```java
var client = SmartTokenClient.builder()
        .privateKeyPem(Path.of("chave-encrypted.pem"))
        .privateKeyPassword("minha-senha".toCharArray())
        // ...
        .build();
```

## Configuração avançada

```java
var client = SmartTokenClient.builder()
        .tokenEndpoint("https://hub.saude.go.gov.br/auth/token")
        .clientId("meu-sistema")
        .privateKeyPem(Path.of("chave-privada.pem"))
        .certificatePem(Path.of("certificado.pem"))
        .serverTrustAnchor(Path.of("ca-custom.pem"))  // simulador/homologação
        .tlsProtocol("TLSv1.2")                       // padrão: TLSv1.3
        .connectTimeout(Duration.ofSeconds(10))
        .requestTimeout(Duration.ofSeconds(30))
        .assertionTtlSeconds(120)                     // TTL do JWT
        .enableTokenCache(true)
        .tokenCacheMarginSeconds(30)                  // margem de renovação
        .tokenCacheMaxEntries(1_000)                 // teto LRU por scope
        .maxRetries(3)
        .jwtAlgorithm("RS384")                        // padrão: RS384 (HubSaúde aceita RS384/ES384)
        .keyId("minha-chave-2026")                    // kid no header do JWT (opcional)
        .hubContext("hemograma", "0.0.1")             // claim hub_ctx: IG e versão pretendidos
        .build();
```

O endpoint deve usar `https`; o esquema `http` é aceito apenas para
`localhost`/`127.0.0.1` (desenvolvimento e testes locais).

Valores menores ou iguais a zero em `assertionTtlSeconds`, `maxRetries`
e `tokenCacheMarginSeconds` são substituídos pelos padrões de 60 s, 3
tentativas totais e 30 s, respectivamente. `tokenCacheMaxEntries` deve
ser positivo; valor inválido faz `build()` falhar com
`IllegalArgumentException`.

### Contexto de Guia de Implementação (`hub_ctx`)

O claim proprietário `hub_ctx` declara o Guia de Implementação (IG) e a
versão pretendidos na sessão (concern `client-assertion-contexto-ig.md`
§3.4). Configure com `hubContext(ig, versao)`: o `ig` usa minúsculas,
dígitos e hífen (ex.: `hemograma`) e a `versao` é SemVer completo
`MAJOR.MINOR.PATCH` (ex.: `0.0.1`). Quando não configurado, o claim é
omitido — servidores que o exigem rejeitarão o assertion.

### Identificador de chave (`kid`)

Quando o servidor de autorização publica múltiplas chaves (JWKS), use
`keyId("...")` para incluir o header `kid` no *client assertion*,
permitindo que o servidor selecione a chave pública correta para
validar a assinatura. Se não configurado, o header contém apenas
`alg` e `typ`.

### Descoberta automática do endpoint

Em vez de fixar `tokenEndpoint`, informe a base FHIR — o cliente
resolve via `.well-known/smart-configuration`:

```java
.fhirBase("https://hub.saude.go.gov.br")
```

### `serverTrustAnchor` — quando usar

Em produção o HubSaúde usa CA já presente no trust store padrão da JVM.
Use `serverTrustAnchor` apenas em testes locais com o simulador,
homologação com CA interna, ou desenvolvimento com certificados ad hoc.

## Preparação de certificados PFX/P12 → PEM

Útil quando a chave precisa ser materializada em PEM. Se você usa
PKCS#12 direto ou HSM, ignore esta seção.

```bash
# Chave privada (atenção: -nodes salva em claro)
openssl pkcs12 -in certificado.pfx -nocerts -nodes -out chave-privada.pem

# Certificado público
openssl pkcs12 -in certificado.pfx -clcerts -nokeys -out certificado.pem

# (Opcional) Forçar PKCS#8
openssl pkcs8 -topk8 -nocrypt -in chave-privada.pem -out chave-pkcs8.pem

# (Opcional) Cifrar a chave em AES-256
openssl pkcs8 -topk8 -v2 aes-256-cbc -in chave-privada.pem -out chave-encrypted.pem
```

## Resiliência em produção

A biblioteca já cobre cache de token + *retries* com *backoff*. Para
proteção adicional contra falhas prolongadas do AS, combine com um
*circuit breaker* externo na camada de orquestração. O
[guia de integração enterprise](docs/integracao-enterprise.md) descreve
ownership, composição de resiliência e métricas sem acoplar o SDK a um
framework.

## Correlação e observabilidade (`traceparent`)

O HubSaúde ignora headers como `X-Correlation-Id` enviados pelo
cliente: a correlação é derivada **exclusivamente** do contexto de
trace W3C ([W3C Trace Context](https://www.w3.org/TR/trace-context/)).
Por isso, toda requisição HTTP desta biblioteca (token endpoint e
descoberta via `.well-known/smart-configuration`) envia o header
`traceparent` no formato `00-<trace-id>-<parent-id>-00`, com trace-id
(16 bytes) e span-id (8 bytes) gerados criptograficamente
(`SecureRandom`) **por requisição** — cada retry carrega um par novo.
Não há dependência do SDK OpenTelemetry.

A flag `sampled` é `00` (*not sampled*), coerente com a semântica do
W3C Trace Context §3.2.2.5.1: a biblioteca não grava spans.

**Como usar com o suporte**: em falhas, o trace-id enviado aparece nos
logs de erro/retry da biblioteca e nas mensagens de exceção
(`traceId=...`). Informe esse valor ao suporte do HubSaúde — ele
permite localizar, na plataforma, o `correlation-id` e os registros da
requisição correspondente, ligando o log do integrador ao da
plataforma.

Aplicações já instrumentadas com o OpenTelemetry Java Agent continuam
funcionando: a instrumentação automática do `HttpClient` sobrepõe o
header com o contexto do span ativo, e o trace-id efetivo passa a ser
o do agente.

## Troubleshooting

| Erro | Causa provável | Solução |
|------|----------------|---------|
| `PKCS8 key spec not recognized` | Chave em PKCS#1 (tradicional) | `openssl pkcs8 -topk8 -nocrypt -in key.pem -out key-pkcs8.pem` |
| `unable to find valid certification path` | CA do servidor não confiável | Use `.serverTrustAnchor()` (simulador/homologação) ou verifique conectividade |
| `signature verification failed` | Certificado não corresponde à chave | Compare *modulus*: `openssl x509 -noout -modulus -in cert.pem \| openssl md5` vs `openssl rsa -noout -modulus -in key.pem \| openssl md5` |
| `connection timed out` | Firewall ou endpoint incorreto | Verifique conectividade e URL |

Para diagnóstico aprofundado de **confiança de certificado SSL/TLS**
(erros `PKIX path building failed` / `SSL handshake failed`, com
snippets em Java, C#, Node.js e OpenSSL), consulte o
[guia de troubleshooting TLS](docs/troubleshooting.md).

Para experimentar o fluxo completo localmente sem ambiente de
homologação, use a ferramenta irmã
[`hubsaude-cliente-cli`](../hubsaude-cliente-cli/).

## Build e testes

```bash
mvn test       # unitários
mvn verify     # unitários + integração (sobe o hubsaude-simulador)
```

### Configurações de qualidade (perfil `quality`)

O perfil `quality` (`mvn -P quality verify`) executa Checkstyle, PMD,
SpotBugs (com FindSecBugs) e JavaDoc com doclint e avisos bloqueantes.
Desde a issue #1603, as configurações de
Checkstyle (`checkstyle/checkstyle.xml`, `checkstyle/checkstyle-tests.xml`)
e o ruleset do PMD (`pmd/pmd-rules.xml`) são as **centrais** do
[`hubsaude-build-tools`](../hubsaude-build-tools/), resolvidas do
classpath da versão pinada em `hubsaude-build-tools.version` no
`pom.xml` — não há mais cópias locais sujeitas a drift silencioso. O
projeto já resolvia artefatos internos do GitHub Packages
(`hubsaude-simulador`, escopo de teste), portanto essa dependência não
altera os pré-requisitos de build. Bumps da versão pinada chegam
automaticamente via Renovate.

Permanecem locais, **por decisão deliberada** (não são cópias e não
estão sujeitos a paridade com o central):

- [`checkstyle-formatacao.xml`](checkstyle-formatacao.xml) — módulos de
  formatação (tabs, newline final, trailing whitespace) removidos da
  configuração central pela REC-28 por redundância com o Spotless, que
  este projeto não usa;
- [`spotbugs-exclude.xml`](spotbugs-exclude.xml) — filtro de exclusão
  curado para esta biblioteca. Filtros SpotBugs têm semântica aditiva
  (cada exclusão reduz a cobertura); o filtro central importaria
  exclusões inaplicáveis aqui (ex.: `CRLF_INJECTION_LOGS`,
  `SPRING_ENDPOINT`) e enfraqueceria o gate de segurança.

Divergência deliberada futura em relação às configurações centrais deve
ser implementada em arquivo local próprio (não em cópia editada do
central), com racional registrado no próprio arquivo, nesta seção e no
`CHANGELOG.md`.

## Publicação de nova versão (release)

Publicação no GitHub Packages é disparada **exclusivamente por tag**
(ADR-36), no padrão `cliente-java-v<MAJOR>.<MINOR>.<PATCH>` (ADR-33):

```bash
git tag -a cliente-java-v0.1.8 -m "hubsaude-cliente-java 0.1.8"
git push origin cliente-java-v0.1.8
```

O workflow [`hubsaude-cliente-java-release.yml`](../../../.github/workflows/hubsaude-cliente-java-release.yml)
deriva a versão da tag (`versions:set`, sem commit) e executa
`mvn clean deploy -P release`, que só publica se Surefire, Failsafe e
JaCoCo (cobertura ≥ 85%) passarem. O perfil `release` agrega sources,
javadoc e SBOM CycloneDX.

## Referências

| Especificação | Descrição |
|---------------|-----------|
| [SMART Backend Services](https://hl7.org/fhir/smart-app-launch/backend-services.html) | Perfil HL7 FHIR para autenticação backend-to-backend |
| [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) | OAuth 2.0 (`client_credentials`) |
| [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) | JSON Web Token (JWT) |
| [RFC 7521](https://datatracker.ietf.org/doc/html/rfc7521) / [RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523) | Assertion Framework e JWT Bearer Assertion |

O [guia de integração enterprise](docs/integracao-enterprise.md)
complementa essas referências com lifecycle, resiliência, métricas e
integração com contêineres.

## Licença e contribuição

Apache License 2.0 — ver [`LICENSE`](LICENSE) e [`NOTICE`](NOTICE).
Copyright 2025 Estado de Goiás (SES-GO).

- [`CONTRIBUTING.md`](CONTRIBUTING.md) — fluxo e DCO
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) — Contributor Covenant 2.1
- [`SECURITY.md`](SECURITY.md) — divulgação responsável de vulnerabilidades
