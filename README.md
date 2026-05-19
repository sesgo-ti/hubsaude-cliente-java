# hubsaude-cliente-java

[![Java 21+](https://img.shields.io/badge/Java-21%2B-blue)](https://openjdk.org/)
[![Maven](https://img.shields.io/badge/Maven-3.9%2B-orange)](https://maven.apache.org/)
[![Version](https://img.shields.io/badge/Version-0.1.5-yellow)](https://github.com/FabricaDeSoftwareINF/server-hubsaude)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

Biblioteca Java que facilita a obtenção de tokens de acesso ao HubSaúde via **SMART Backend Services** (SMART-on-FHIR), o fluxo de autenticação máquina-a-máquina (M2M) exigido pela plataforma. Encapsula a montagem do JWT de client assertion, a assinatura com a chave privada do credenciado e a requisição ao endpoint de token, expondo uma API simples para que aplicações consumidoras obtenham e renovem tokens sem reimplementar o protocolo.

## Visão geral

O HubSaúde adota o perfil **SMART Backend Services** (HL7 FHIR) para
autenticação máquina-a-máquina. O cliente:

1. monta um JWT (*client assertion*) com claims `iss`, `sub`, `aud`,
   `exp`, `iat`, `jti`;
2. assina o JWT em RS256 com sua chave privada (associada ao
   certificado registrado no credenciamento);
3. troca o JWT por um *access token* no endpoint OAuth 2.0
   (`grant_type=client_credentials`).

A biblioteca encapsula esses passos. A chamada equivalente em `curl`,
para fins didáticos:

```bash
curl -X POST https://hub.saude.go.gov.br/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=meu-sistema" \
  -d "scope=system/Patient.rs" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtZXUtc2lzdGVtYSIsInN1YiI6Im1ldS1zaXN0ZW1hIiwiYXVkIjoiaHR0cHM6Ly9odWIuc2F1ZGUuZ28uZ292LmJyL2F1dGgvdG9rZW4iLCJleHAiOjE3MDk3NDAwMDAsImlhdCI6MTcwOTczOTg4MCwianRpIjoiYTFiMmMzZDQtZTVmNi03ODkwLWFiY2QtZWYxMjM0NTY3ODkwIn0.ASSINATURA_RS256"
```

Estrutura do JWT (`header.payload.signature`):

- *header*
  ```json
  {
    "alg": "RS256",
    "typ": "JWT"
  }
  ```
- *payload*
  ```json
  {
    "iss" : "client_id",
    "sub" : "client_id",
    "aud" : "token_endpoint",
    "exp" : 1709740000,
    "iat" : 1709739880,
    "jti" : "uuid"
  }
  ```
- *signature*: RS256 (RSA + SHA-256) com a chave privada do credenciado.

**Resposta esperada:**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "system/Patient.rs"
}
```

---

## Dependência Maven

Publicado no **GitHub Packages do monorepo HubSaúde**
(`maven.pkg.github.com/FabricaDeSoftwareINF/server-hubsaude`).
A migração futura para o Maven Central está planejada em `plano.md`.

```xml
<dependency>
    <groupId>br.gov.go.saude.hubsaude</groupId>
    <artifactId>hubsaude-cliente-java</artifactId>
    <version>0.1.5</version>
</dependency>
```

> **Acesso ao GitHub Packages:** o repositório exige autenticação
> mesmo para leitura. Configure `~/.m2/settings.xml` com um
> Personal Access Token (escopo `read:packages`) e declare o
> repositório `https://maven.pkg.github.com/FabricaDeSoftwareINF/server-hubsaude`
> no seu `pom.xml`.

---

## Uso básico

Caminho mais curto entre uma chave privada/certificado em PEM e um
*access token* válido:

```java
var client = SmartTokenClient.builder()
        .tokenEndpoint("https://hub.saude.go.gov.br/auth/token")
        .clientId("meu-sistema")
        .privateKeyPem(Path.of("chave-privada.pem"))
        .certificatePem(Path.of("certificado.pem"))
        .build();

String token = client.obtainToken("system/Patient.rs");
```

A instância é **thread-safe** e mantém cache interno do token (válido
até a margem de renovação). Reutilize a mesma instância pelo
*lifecycle* da aplicação.

---

## Fontes de chave (SigningStrategy)

A escolha de **onde** a chave privada reside é a decisão arquitetural
mais relevante para uma integração de produção. A biblioteca abstrai
essa escolha por trás da interface `SigningStrategy`.

| Fonte | Quando usar | Exposição da chave |
|-------|-------------|--------------------|
| PEM (PKCS#8) | Prototipação e ambientes de teste | Arquivo em claro no disco |
| PEM com senha | Quando PEM é inevitável, mas se quer mitigação adicional | Cifrada em disco; senha em runtime |
| PKCS#12 direto | **Recomendado para produção** com chaves em software | Permanece dentro do `KeyStore` |
| HSM via PKCS#11 | Produção com exigência de não-exportabilidade da chave | Nunca sai do hardware |
| OpenBao (cofre) | Quando a chave é provisionada centralmente por um cofre | Buscada em runtime; nunca em disco |

### PEM (PKCS#8)

```java
var client = SmartTokenClient.builder()
        .tokenEndpoint("https://hub.saude.go.gov.br/auth/token")
        .clientId("meu-sistema")
        .privateKeyPem(Path.of("chave-privada.pem"))
        .certificatePem(Path.of("certificado.pem"))
        .build();
```

### PEM com senha (PKCS#8 cifrado)

```java
var client = SmartTokenClient.builder()
        .privateKeyPem(Path.of("chave-encrypted.pem"))
        .privateKeyPassword("minha-senha".toCharArray())
        // ...
        .build();
```

### PKCS#12 direto (sem conversão para PEM)

Recomendado para produção: a chave nunca é serializada como PEM em
disco e o arquivo permanece no formato distribuído por autoridades
ICP-Brasil.

```java
KeyStore ks = KeyStore.getInstance("PKCS12");
try (var fis = new FileInputStream("certificado.pfx")) {
    ks.load(fis, "senha-pfx".toCharArray());
}

SigningStrategy strategy = SigningStrategyFactory.fromKeyStore(
        ks, "alias-da-chave", "senha-chave".toCharArray());

X509Certificate cert = (X509Certificate) ks.getCertificate("alias-da-chave");

var client = SmartTokenClient.builder()
        .tokenEndpoint("https://hub.saude.go.gov.br/auth/token")
        .clientId("meu-sistema")
        .signingStrategy(strategy)
        .certificate(cert)
        .build();
```

> **Dica:** Use `keytool -list -keystore certificado.pfx -storetype PKCS12`
> para descobrir o alias.

### HSM via PKCS#11

```java
Provider pkcs11 = SigningStrategyFactory.configurePkcs11Provider("/etc/pkcs11/hsm.cfg");

SigningStrategy strategy = SigningStrategyFactory.fromPkcs11(
        pkcs11,
        "alias-chave-hsm",
        "123456".toCharArray());  // PIN

var client = SmartTokenClient.builder()
        .signingStrategy(strategy)  // Assinatura no hardware
        // ...
        .build();
```

### OpenBao

```java
PrivateKey baoKey = baoClient.getPrivateKey("secret/data/hubsaude/key");
SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(baoKey);

var client = SmartTokenClient.builder()
        .signingStrategy(strategy)
        // ...
        .build();
```

---

## Configuração avançada

### Builder completo

```java
var client = SmartTokenClient.builder()
        .tokenEndpoint("https://hub.saude.go.gov.br/auth/token")  // ou .fhirBase() para descoberta
        .clientId("meu-sistema")
        .privateKeyPem(Path.of("chave-privada.pem"))
        .certificatePem(Path.of("certificado.pem"))
        .serverTrustAnchor(Path.of("ca-custom.pem"))     // opcional: ver nota abaixo
        .tlsProtocol("TLSv1.2")                          // opcional: TLS 1.2 (padrão: TLSv1.3)
        .connectTimeout(Duration.ofSeconds(10))          // opcional
        .requestTimeout(Duration.ofSeconds(30))          // opcional
        .assertionTtlSeconds(120)                        // opcional: TTL do JWT
        .enableTokenCache(true)                          // opcional: cache habilitado
        .tokenCacheMarginSeconds(30)                     // opcional: margem de renovação
        .maxRetries(3)                                   // opcional: retries
        .build();
```

### Descoberta automática de endpoint

Em vez de fixar `tokenEndpoint`, informe a base FHIR e a biblioteca
resolve o token endpoint via `.well-known/smart-configuration`:

```java
var client = SmartTokenClient.builder()
        .fhirBase("https://hub.saude.go.gov.br")
        .clientId("meu-sistema")
        .privateKeyPem(Path.of("chave-privada.pem"))
        .certificatePem(Path.of("certificado.pem"))
        .build();
```

### Algoritmo de assinatura

O padrão é **RS256** (RSA PKCS#1 v1.5 + SHA-256) pela ampla
interoperabilidade:

| Critério | RS256 | RS384/RS512 | PS256/PS384 |
|----------|-------|-------------|-------------|
| **Keycloak** | ✅ Padrão | ⚠️ Requer config | ⚠️ Requer config |
| **SMART Backend Services** | ✅ Suportado | ✅ Suportado | ⚠️ Opcional |
| **ICP-Brasil (HSM)** | ✅ Universal | ✅ Universal | ⚠️ Parcial |
| **Interoperabilidade** | ✅ Máxima | ✅ Alta | ⚠️ Variável |

Outros algoritmos disponíveis:

- **RS384/RS512**: hash maior, segurança levemente superior.
- **PS256/PS384/PS512**: RSA-PSS, mais robusto contra ataques teóricos.
- **ES256/ES384/ES512**: ECDSA, requer chaves EC.

```java
var client = SmartTokenClient.builder()
        .jwtAlgorithm("RS384")  // ou RS512, PS256, ES256, etc.
        // ...
        .build();
```

> Verifique se o authorization server suporta o algoritmo escolhido.

### `serverTrustAnchor` — quando (não) usar

Em produção este parâmetro **não é necessário**: o HubSaúde usa
certificado emitido por CA já presente no trust store padrão da JVM.

Use `serverTrustAnchor` apenas em cenários específicos:

- **Testes locais** com o `hubsaude-simulador` (certificado autoassinado);
- **Homologação** com CA interna ausente do trust store da JVM;
- **Desenvolvimento** com certificados ad hoc.

---

## Preparação de certificados

Conversões úteis quando a chave privada precisa ser materializada em
arquivo PEM. Se você adota PKCS#12 direto ou HSM, esta seção é
opcional.

### PFX/P12 (ICP-Brasil) para PEM com openssl

```bash
# 1. Extrair chave privada (será solicitada a senha do PFX)
openssl pkcs12 -in certificado.pfx -nocerts -nodes -out chave-privada.pem

# 2. Extrair certificado (chave pública)
openssl pkcs12 -in certificado.pfx -clcerts -nokeys -out certificado.pem

# 3. (Opcional) Converter chave para PKCS#8 explícito
openssl pkcs8 -topk8 -nocrypt -in chave-privada.pem -out chave-pkcs8.pem
```

> **Segurança:** `-nodes` salva a chave em claro — use apenas em
> ambientes seguros. Para produção, prefira PKCS#12 direto ou HSM.

### PFX/P12 (ICP-Brasil) com keytool (JDK)

```bash
# 1. Listar aliases disponíveis no arquivo PFX/P12
keytool -list -keystore certificado.pfx -storetype PKCS12 -v

# 2. (Opcional) Importar PFX para um novo keystore JKS
keytool -importkeystore \
    -srckeystore certificado.pfx \
    -srcstoretype PKCS12 \
    -destkeystore meu-keystore.jks \
    -deststoretype JKS

# 3. Exportar apenas o certificado (formato DER)
keytool -exportcert \
    -keystore certificado.pfx \
    -storetype PKCS12 \
    -alias meu-alias \
    -file certificado.der

# 4. Converter certificado DER para PEM (requer openssl)
openssl x509 -inform DER -in certificado.der -out certificado.pem
```

> **Nota:** `keytool` não exporta chaves privadas para PEM. Para isso,
> use openssl ou carregue o PKCS#12 diretamente no código Java
> (ver *PKCS#12 direto* em **Fontes de chave**).

### Cifrar uma chave PEM existente

```bash
# PKCS#8 criptografado (AES-256)
openssl pkcs8 -topk8 -v2 aes-256-cbc -in chave-privada.pem -out chave-encrypted.pem
```

---

## Resiliência em produção

A biblioteca já implementa cache de token e retries com backoff. Para
proteger o sistema consumidor de falhas prolongadas do authorization
server, combine com um *circuit breaker* externo (ex.: Resilience4j):

```java
CircuitBreaker cb = CircuitBreaker.of("hubsaude", CircuitBreakerConfig.custom()
        .failureRateThreshold(50)
        .waitDurationInOpenState(Duration.ofSeconds(30))
        .slidingWindowSize(10)
        .build());

String token = cb.executeSupplier(() -> client.obtainToken(scope));
```

---

## Build e testes

A partir do diretório `projetos/hubsaude-cliente-java`:

```bash
mvn test       # unitários
mvn verify     # unitários + integração (sobe o hubsaude-simulador automaticamente)
```

| Modo  | Comando                                          | Pré-requisito | Tempo |
|-------|--------------------------------------------------|---------------|-------|
| JAR   | `mvn verify -Dit.test=SmartTokenClientJarIT`     | Java 21+      | ~5s   |
| Todos | `mvn verify`                                     | Java 21+      | ~5s   |

Os testes de integração baixam o `hubsaude-simulador` do GitHub
Packages via a execução `copy-simulator` do `maven-dependency-plugin`
(versão controlada pela property `hubsaude-simulador.version` do
`pom.xml`).

---

## Experimentação com o simulador local

Para validar manualmente o fluxo completo de credenciamento sem
depender de um ambiente de homologação/produção, use o
`hubsaude-simulador`. Os passos abaixo geram chaves de teste, sobem o
simulador, registram o cliente e obtêm um token.

> Para **apenas conferir** o credenciamento via linha de comando (sem
> escrever código), prefira a ferramenta
> [`hubsaude-cliente-cli`](../hubsaude-cliente-cli/) — projeto irmão
> que automatiza os passos abaixo.

### 1. Gerar par de chaves e certificado do cliente

```bash
# Par de chaves RSA 2048-bit
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out test-key.pem

# Certificado autoassinado (válido por 365 dias)
openssl req -new -x509 -key test-key.pem -out test-cert.pem -days 365 \
    -subj "/CN=meu-sistema/O=Desenvolvimento/C=BR"

# (Opcional) Verificar
openssl rsa -in test-key.pem -check -noout
openssl x509 -in test-cert.pem -text -noout | head -20
```

### 2. Iniciar o simulador

O JAR do `hubsaude-simulador` é publicado no GitHub Packages do
monorepo. Configure em `~/.m2/settings.xml` um `<server>` com
`id=github-hubsaude` (username = seu usuário GitHub, password = um
Personal Access Token com escopo `read:packages`).

A partir do diretório `projetos/hubsaude-cliente-java`:

```bash
mvn -DskipTests pre-integration-test
```

A execução `copy-simulator` baixa o artefato e o deposita em
`target/simulator/hubsaude-simulador.jar`. Inicie-o:

```bash
java -jar target/simulator/hubsaude-simulador.jar
```

Disponível em `https://localhost:8443`.

### 3. Extrair o certificado do simulador

```bash
# Em outro terminal, com o simulador rodando:
openssl s_client -connect localhost:8443 < /dev/null 2>/dev/null \
    | openssl x509 > simulador-server.pem
```

O simulador não expõe endpoint HTTP para download do certificado PEM;
extração via `openssl s_client` é a forma recomendada.

### 4. Registrar o cliente no simulador

```bash
curl -k -X POST https://localhost:8443/clients/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "meu-sistema",
    "certificate": "'"$(awk '{printf "%s\\n", $0}' test-cert.pem)"'",
    "allowed_scopes": "system/Patient.rs system/Observation.rs"
  }'
```

> `-k` ignora a validação do certificado do servidor apenas para o
> registro. Alternativamente, `--cacert simulador-server.pem`.

**Resposta esperada:**

```json
{"status":"registered","client_id":"meu-sistema"}
```

### 5. Obter token de acesso

```java
var client = SmartTokenClient.builder()
        .tokenEndpoint("https://localhost:8443/auth/token")
        .clientId("meu-sistema")
        .privateKeyPem(Path.of("test-key.pem"))
        .certificatePem(Path.of("test-cert.pem"))
        .serverTrustAnchor(Path.of("simulador-server.pem"))
        .build();

String token = client.obtainToken("system/Patient.rs");
System.out.println("Token obtido: " + token);
```

### Arquivos gerados nesta seção

| Arquivo | Descrição | Compartilhar? |
|---------|-----------|---------------|
| `test-key.pem` | Chave privada do cliente (assina o JWT) | ❌ **Nunca** |
| `test-cert.pem` | Certificado público do cliente | ✅ Registrar no simulador |
| `simulador-server.pem` | Certificado do simulador (trust anchor) | N/A (somente local) |

---

## Troubleshooting

| Erro | Causa Provável | Solução |
|------|----------------|---------|
| `PKCS8 key spec not recognized` | Chave em formato PKCS#1 (tradicional) | Converter: `openssl pkcs8 -topk8 -nocrypt -in key.pem -out key-pkcs8.pem` |
| `unable to find valid certification path` | CA do servidor não confiável | Para simulador/homologação: usar `.serverTrustAnchor()`; produção: verificar conectividade |
| `signature verification failed` | Certificado não corresponde à chave | Verificar: `openssl x509 -noout -modulus -in cert.pem \| openssl md5` vs `openssl rsa -noout -modulus -in key.pem \| openssl md5` |
| `connection timed out` | Firewall ou endpoint incorreto | Verificar conectividade e URL |

---

## Arquitetura

```
┌─────────────────────────────────────────────────────────────┐
│                     SmartTokenClient                        │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ TokenCache  │  │ RetryPolicy │  │ SigningStrategy     │  │
│  │ (thread-    │  │ (exp.       │  │ ┌─────────────────┐ │  │
│  │  safe)      │  │  backoff)   │  │ │ PEM │ P12 │ HSM │ │  │
│  └─────────────┘  └─────────────┘  │ └─────────────────┘ │  │
│                                     └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    POST /auth/token
                    (client_assertion JWT RS256)
```

---

## Referências

| Especificação | Descrição |
|---------------|-----------|
| [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) | OAuth 2.0 — define `client_credentials` grant para comunicação M2M (sem usuário) |
| [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) | JSON Web Signature (JWS) — estrutura e serialização de assinaturas digitais |
| [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) | JSON Web Token (JWT) — formato do token com claims `iss`, `sub`, `aud`, `exp`, `iat`, `jti` |
| [RFC 7521](https://datatracker.ietf.org/doc/html/rfc7521) | Assertion Framework — uso de assertions como credenciais de cliente |
| [RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523) | JWT Bearer Assertion — perfil específico para `client_assertion` com JWT assinado |
| [SMART Backend Services](https://hl7.org/fhir/smart-app-launch/backend-services.html) | Guia HL7 FHIR para autenticação backend-to-backend em sistemas de saúde |

---

## Release

A publicação no GitHub Packages é automatizada pelo workflow
[`hubsaude-cliente-java-release.yml`](../../.github/workflows/hubsaude-cliente-java-release.yml),
seguindo o padrão de tags definido na **ADR-33**
(`<artefato>-v<MAJOR>.<MINOR>.<PATCH>`).

**Fluxo padrão (recomendado) — via tag:**

```bash
# Da raiz do monorepo, com a versão desejada já no pom.xml
git tag -a cliente-java-v0.1.6 -m "hubsaude-cliente-java 0.1.6"
git push origin cliente-java-v0.1.6
```

O workflow é disparado pelo push da tag, faz `mvn versions:set` para
a versão derivada da tag e roda `mvn clean deploy -P release` (que
inclui sources, javadoc e SBOM CycloneDX).

**Disparo manual (apenas para emergência/teste):** via aba *Actions*
do GitHub, escolhendo o workflow e informando a versão no input
`version`.



Copyright 2025 Estado de Goiás, por meio da Secretaria de Estado da
Saúde de Goiás (SES-GO).

Licenciado sob a **Apache License, Version 2.0** (a "Licença"). Você
pode obter uma cópia da Licença em
<https://www.apache.org/licenses/LICENSE-2.0>.

A menos que exigido por lei aplicável ou acordado por escrito, o
software distribuído sob a Licença é distribuído "NO ESTADO EM QUE SE
ENCONTRA", SEM GARANTIAS OU CONDIÇÕES DE QUALQUER TIPO, expressas ou
implícitas. Consulte a Licença para o idioma específico que rege
permissões e limitações sob a Licença.

Veja [`LICENSE`](LICENSE) para o texto integral e [`NOTICE`](NOTICE)
para atribuições adicionais.

## Como contribuir

Contribuições são bem-vindas. Consulte:

- [`CONTRIBUTING.md`](CONTRIBUTING.md) — fluxo de contribuição, DCO
  (Developer Certificate of Origin) e padrões técnicos
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) — Contributor Covenant 2.1
- [`SECURITY.md`](SECURITY.md) — canal de divulgação responsável para
  vulnerabilidades
