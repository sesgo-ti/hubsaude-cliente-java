# hubsaude-cliente-java

[![Version](https://img.shields.io/badge/Version-0.3.14-yellow)](https://github.com/FabricaDeSoftwareINF/server-hubsaude)
[![Java 21+](https://img.shields.io/badge/Java-21%2B-blue)](https://openjdk.org/)
[![Maven](https://img.shields.io/badge/Maven-3.9%2B-orange)](https://maven.apache.org/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

Cliente Java para obtenção de tokens de acesso ao HubSaúde via
[SMART Backend Services](https://hl7.org/fhir/smart-app-launch/backend-services.html)
(SMART-on-FHIR). Encapsula a montagem do JWT *client assertion*, sua
assinatura e a troca pelo *access token* no endpoint OAuth 2.0.

O contrato comportamental está em [`ESPECIFICACAO.md`](ESPECIFICACAO.md)
— requisitos normativos que refletem esta implementação e servem de
referência para SDKs equivalentes em outras linguagens (Python,
JavaScript/TypeScript, C#).

## Dependência Maven

```xml
<dependency>
    <groupId>br.gov.go.saude.hubsaude</groupId>
    <artifactId>hubsaude-cliente-java</artifactId>
    <version>0.3.13</version>
</dependency>
```

Publicado no GitHub Packages
(`maven.pkg.github.com/FabricaDeSoftwareINF/server-hubsaude`).
Autenticação requerida mesmo para leitura: configure `~/.m2/settings.xml`
com um Personal Access Token (escopo `read:packages`).

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
Reutilize a mesma instância pelo ciclo de vida da aplicação.

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
        .maxRetries(3)
        .jwtAlgorithm("RS384")                        // padrão: RS384 (HubSaúde aceita RS384/ES384)
        .keyId("minha-chave-2026")                    // kid no header do JWT (opcional)
        .hubContext("hemograma", "0.0.1")             // claim hub_ctx: IG e versão pretendidos
        .build();
```

O endpoint deve usar `https`; o esquema `http` é aceito apenas para
`localhost`/`127.0.0.1` (desenvolvimento e testes locais).

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
*circuit breaker* externo (ex.: Resilience4j):

```java
CircuitBreaker cb = CircuitBreaker.of("hubsaude", CircuitBreakerConfig.custom()
        .failureRateThreshold(50)
        .waitDurationInOpenState(Duration.ofSeconds(30))
        .slidingWindowSize(10)
        .build());

String token = cb.executeSupplier(() -> client.obtainToken(scope));
```

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

## Licença e contribuição

Apache License 2.0 — ver [`LICENSE`](LICENSE) e [`NOTICE`](NOTICE).
Copyright 2025 Estado de Goiás (SES-GO).

- [`CONTRIBUTING.md`](CONTRIBUTING.md) — fluxo e DCO
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) — Contributor Covenant 2.1
- [`SECURITY.md`](SECURITY.md) — divulgação responsável de vulnerabilidades
