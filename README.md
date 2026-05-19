# hubsaude-cliente-java

[![Java 21+](https://img.shields.io/badge/Java-21%2B-blue)](https://openjdk.org/)
[![Maven](https://img.shields.io/badge/Maven-3.9%2B-orange)](https://maven.apache.org/)
[![Version](https://img.shields.io/badge/Version-0.1.5-yellow)](https://github.com/FabricaDeSoftwareINF/server-hubsaude)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

Biblioteca Java que facilita a obtenção de tokens de acesso ao HubSaúde via **SMART Backend Services** (SMART-on-FHIR), o fluxo de autenticação máquina-a-máquina (M2M) exigido pela plataforma. Encapsula a montagem do JWT de client assertion, a assinatura com a chave privada do credenciado e a requisição ao endpoint de token, expondo uma API simples para que aplicações consumidoras obtenham e renovem tokens sem reimplementar o protocolo.

## Dependência Maven

O `hubsaude-cliente-java` é publicado no **GitHub Packages do monorepo HubSaúde**
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


## Inicio rápido

Siga os passos abaixo para testar a biblioteca localmente com o `hubsaude-simulador`.

### 1. Gerar par de chaves e certificado do cliente

```bash
# Gerar par de chaves RSA 2048-bit
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out test-key.pem

# Gerar certificado autoassinado (válido por 365 dias)
openssl req -new -x509 -key test-key.pem -out test-cert.pem -days 365 \
    -subj "/CN=meu-sistema/O=Desenvolvimento/C=BR"

# (Opcional) Verificar arquivos gerados
openssl rsa -in test-key.pem -check -noout
openssl x509 -in test-cert.pem -text -noout | head -20
```

### 2. Iniciar o simulador

O JAR do `hubsaude-simulador` é publicado no GitHub Packages do
monorepo (`maven.pkg.github.com/FabricaDeSoftwareINF/server-hubsaude`),
que exige autenticação. Antes de baixá-lo, configure em
`~/.m2/settings.xml` um `<server>` com `id=github-hubsaude`
(username = seu usuário GitHub, password = um Personal Access Token
com escopo `read:packages`).

A partir do diretório `projetos/hubsaude-cliente-java`, rode:

```bash
mvn -DskipTests pre-integration-test
```

A execução `copy-simulator` do `maven-dependency-plugin` baixa o
artefato (versão controlada pela property `hubsaude-simulador.version`
do `pom.xml`) e o deposita em `target/simulator/hubsaude-simulador.jar`.

Inicie o simulador:

```bash
java -jar target/simulator/hubsaude-simulador.jar
```

O simulador estará disponível em `https://localhost:8443`.

### 3. Extrair o certificado do simulador

Como o simulador usa certificado autoassinado, é necessário extraí-lo para que o cliente confie na conexão TLS:

```bash
# Em outro terminal (com o simulador rodando):
openssl s_client -connect localhost:8443 < /dev/null 2>/dev/null | openssl x509 > simulador-server.pem
```

### 4. Registrar o cliente no simulador

O simulador exige que o cliente seja registrado antes de solicitar tokens. Isso é feito pelo registro do certificado correspondente via API:

```bash
# Registrar o cliente com seu certificado e scopes permitidos
curl -k -X POST https://localhost:8443/clients/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "meu-sistema",
    "certificate": "'"$(awk '{printf "%s\\n", $0}' test-cert.pem)"'",
    "allowed_scopes": "system/Patient.rs system/Observation.rs"
  }'
```

> **Nota:** O `-k` ignora a validação do certificado do servidor apenas para o registro. Alternativamente, use `--cacert simulador-server.pem`.

**Resposta esperada:**
```json
{"status":"registered","client_id":"meu-sistema"}
```

### 5. Obter token de acesso

Com os arquivos `test-key.pem`, `test-cert.pem` e `simulador-server.pem`, o cliente pode ser usado:

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

### Resumo dos arquivos

| Arquivo | Descrição | Compartilhar? |
|---------|-----------|---------------|
| `test-key.pem` | Chave privada do cliente (assina JWT) | ❌ **Nunca** |
| `test-cert.pem` | Certificado público do cliente | ✅ Registrar no simulador |
| `simulador-server.pem` | Certificado do simulador (trust anchor) | N/A (apenas para testes locais) |

> **Nota:** O método `serverTrustAnchor` é necessário apenas para o simulador local, que usa certificado autoassinado. Nos ambientes de homologação e produção do HubSaúde, os certificados são emitidos por autoridade certificadora confiável, já presente no trust store padrão da JVM — portanto essa chamada deve ser omitida.

> **Verificação pós-credenciamento:** para conferir, via linha de comando, que o credenciamento está funcionando, use a ferramenta `hubsaude-cliente-cli` (projeto irmão `projetos/hubsaude-cliente-cli`).

---

## Como funciona (curl)

A biblioteca abstrai a seguinte requisição HTTPs:

```bash
curl -X POST https://hub.saude.go.gov.br/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=meu-sistema" \
  -d "scope=system/Patient.rs" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtZXUtc2lzdGVtYSIsInN1YiI6Im1ldS1zaXN0ZW1hIiwiYXVkIjoiaHR0cHM6Ly9odWIuc2F1ZGUuZ28uZ292LmJyL2F1dGgvdG9rZW4iLCJleHAiOjE3MDk3NDAwMDAsImlhdCI6MTcwOTczOTg4MCwianRpIjoiYTFiMmMzZDQtZTVmNi03ODkwLWFiY2QtZWYxMjM0NTY3ODkwIn0.ASSINATURA_RS256"
```

Estrutura do JWT (`client_assertion`), ou seja, `header.payload.signature` onde:

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
- *signature*: RS256 (RSA + SHA-256) com chave privada

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

## Preparação de certificados

### Converter PFX/P12 (ICP-Brasil) para PEM

Certificados ICP-Brasil geralmente são distribuídos em formato PKCS#12 (`.pfx` ou `.p12`). Para extrair chave e certificado em PEM:

```bash
# 1. Extrair chave privada (será solicitada a senha do PFX)
openssl pkcs12 -in certificado.pfx -nocerts -nodes -out chave-privada.pem

# 2. Extrair certificado (chave pública)
openssl pkcs12 -in certificado.pfx -clcerts -nokeys -out certificado.pem

# 3. (Opcional) Converter chave para PKCS#8 explícito
openssl pkcs8 -topk8 -nocrypt -in chave-privada.pem -out chave-pkcs8.pem
```

> **Segurança:** Use `-nodes` apenas em ambientes seguros. Para produção, considere manter a chave criptografada ou usar HSM.

### Converter PFX/P12 (ICP-Brasil) para PEM com keytool

Alternativamente ao openssl, é possível usar o `keytool` (incluído no JDK) combinado com comandos Java:

```bash
# 1. Listar aliases disponíveis no arquivo PFX/P12
keytool -list -keystore certificado.pfx -storetype PKCS12 -v

# 2. Importar PFX para um novo keystore JKS (opcional, para integração Java nativa)
keytool -importkeystore \
    -srckeystore certificado.pfx \
    -srcstoretype PKCS12 \
    -destkeystore meu-keystore.jks \
    -deststoretype JKS

# 3. Exportar apenas o certificado para arquivo (formato DER)
keytool -exportcert \
    -keystore certificado.pfx \
    -storetype PKCS12 \
    -alias meu-alias \
    -file certificado.der

# 4. Converter certificado DER para PEM (requer openssl)
openssl x509 -inform DER -in certificado.der -out certificado.pem
```

> **Nota:** O `keytool` não exporta chaves privadas diretamente para PEM. Para extrair a chave privada, use openssl ou carregue o PKCS#12 diretamente no código Java (ver seção "PKCS#12 Direto").

**Usando PKCS#12 diretamente no Java (sem conversão):**

```java
// Carregar o arquivo PFX/P12 diretamente, sem conversão para PEM
KeyStore ks = KeyStore.getInstance("PKCS12");
try (var fis = new FileInputStream("certificado.pfx")) {
    ks.load(fis, "senha-pfx".toCharArray());
}

// Descobrir o alias (se não souber)
String alias = ks.aliases().nextElement();
System.out.println("Alias encontrado: " + alias);

// Criar o cliente usando o KeyStore
SigningStrategy strategy = SigningStrategyFactory.fromKeyStore(
        ks, alias, "senha-chave".toCharArray());

X509Certificate cert = (X509Certificate) ks.getCertificate(alias);

var client = SmartTokenClient.builder()
        .tokenEndpoint("https://hub.saude.go.gov.br/auth/token")
        .clientId("meu-sistema")
        .signingStrategy(strategy)
        .certificate(cert)
        .build();
```

Esta abordagem é **recomendada para produção** pois evita expor a chave privada em arquivo PEM.

### Chave privada com Senha

```bash
# Converter para PKCS#8 criptografado (AES-256)
openssl pkcs8 -topk8 -v2 aes-256-cbc -in chave-privada.pem -out chave-encrypted.pem
```

```java
var client = SmartTokenClient.builder()
        .privateKeyPem(Path.of("chave-encrypted.pem"))
        .privateKeyPassword("minha-senha".toCharArray())
        // ...
        .build();
```


## Configuração completa

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

> **Nota sobre `serverTrustAnchor`:** Este parâmetro **não é necessário para produção**. O servidor de produção utiliza certificado Let's Encrypt, que já está na cadeia de confiança padrão da JVM.
>
> Use `serverTrustAnchor` apenas em cenários específicos:
> - **Testes locais:** Ao usar o `hubsaude-simulador` com certificado autoassinado
> - **Homologação:** Se o ambiente usa CA interna não presente no trust store da JVM
> - **Desenvolvimento:** Para aceitar certificados de desenvolvimento
>
> **Extraindo o certificado do simulador:**
>
> O `hubsaude-simulador` usa certificado autoassinado gerado dinamicamente. Para extraí-lo:
> ```bash
> # Inicie o simulador primeiro: java -jar hubsaude-simulador.jar
> # Em outro terminal, extraia o certificado SSL:
> openssl s_client -connect localhost:8443 < /dev/null 2>/dev/null | openssl x509 > simulador-cert.pem
> ```
>
> Exemplo de uso com o certificado extraído:
> ```java
> var client = SmartTokenClient.builder()
>         .tokenEndpoint("https://localhost:8443/auth/token")
>         .serverTrustAnchor(Path.of("simulador-cert.pem"))
>         // ...demais configurações
>         .build();
> ```

> **Nota**  
> O simulador não expõe endpoint HTTP para download do certificado PEM. A extração via `openssl s_client` é a forma recomendada.

### Descoberta automática de endpoint

```java
var client = SmartTokenClient.builder()
        .fhirBase("https://hub.saude.go.gov.br")  // Descobre via .well-known/smart-configuration
        .clientId("meu-sistema")
        .privateKeyPem(Path.of("chave-privada.pem"))
        .certificatePem(Path.of("certificado.pem"))
        .build();
```

---

## Fontes de Chave Alternativas

### PKCS#12 Direto (sem conversão para PEM)

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
        .certificatePem(Path.of("certificado.pem"))
        .build();
```

> **Dica:** Use `keytool -list -keystore certificado.pfx -storetype PKCS12` para descobrir o alias.

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

### HashiCorp Vault

```java
PrivateKey vaultKey = vaultClient.getPrivateKey("secret/data/hubsaude/key");
SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(vaultKey);

var client = SmartTokenClient.builder()
        .signingStrategy(strategy)
        // ...
        .build();
```

---

## Resiliência em produção

### Integração com Resilience4j

```java
CircuitBreaker cb = CircuitBreaker.of("hubsaude", CircuitBreakerConfig.custom()
        .failureRateThreshold(50)
        .waitDurationInOpenState(Duration.ofSeconds(30))
        .slidingWindowSize(10)
        .build());

String token = cb.executeSupplier(() -> client.obtainToken(scope));
```

---

## Testes

### Unitários

```bash
mvn test
```

### Integração

| Modo     | Comando                                          | Pré-requisito | Tempo |
|----------|--------------------------------------------------|---------------|-------|
| JAR      | `mvn verify -Dit.test=SmartTokenClientJarIT`     | Java 21+      | ~5s   |
| Todos    | `mvn verify`                                     | Java 21+      | ~5s   |

Os testes de integração utilizam o `hubsaude-simulador` automaticamente.

---

## Troubleshooting

| Erro | Causa Provável | Solução |
|------|----------------|---------|
| `PKCS8 key spec not recognized` | Chave em formato PKCS#1 (tradicional) | Converter: `openssl pkcs8 -topk8 -nocrypt -in key.pem -out key-pkcs8.pem` |
| `unable to find valid certification path` | CA do servidor não confiável | Para simulador/homologação: usar `.serverTrustAnchor()`; produção: verificar conectividade |
| `signature verification failed` | Certificado não corresponde à chave | Verificar: `openssl x509 -noout -modulus -in cert.pem \| openssl md5` vs `openssl rsa -noout -modulus -in key.pem \| openssl md5` |
| `connection timed out` | Firewall ou endpoint incorreto | Verificar conectividade e URL |

---

## Notas Técnicas

### Algoritmo de Assinatura

O algoritmo padrão é **RS256** (RSA PKCS#1 v1.5 + SHA-256) por ser o mais amplamente suportado:

| Critério | RS256 | RS384/RS512 | PS256/PS384 |
|----------|-------|-------------|-------------|
| **Keycloak** | ✅ Padrão | ⚠️ Requer config | ⚠️ Requer config |
| **SMART Backend Services** | ✅ Suportado | ✅ Suportado | ⚠️ Opcional |
| **ICP-Brasil (HSM)** | ✅ Universal | ✅ Universal | ⚠️ Parcial |
| **Interoperabilidade** | ✅ Máxima | ✅ Alta | ⚠️ Variável |

**Outros algoritmos disponíveis:**
- **RS384/RS512**: Maior tamanho de hash, segurança levemente superior
- **PS256/PS384/PS512**: RSA-PSS, mais robusto contra ataques teóricos
- **ES256/ES384/ES512**: ECDSA, requer chaves EC

Para usar um algoritmo diferente:

```java
var client = SmartTokenClient.builder()
        .jwtAlgorithm("RS384")  // ou RS512, PS256, ES256, etc.
        // ...
        .build();
```

> **Nota:** Verifique se o authorization server suporta o algoritmo escolhido.

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

## Licença

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
