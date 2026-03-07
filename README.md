# HubSaúde Cliente Java

[![Java 21+](https://img.shields.io/badge/Java-21%2B-blue)](https://openjdk.org/)
[![Maven](https://img.shields.io/badge/Maven-3.9%2B-orange)](https://maven.apache.org/)
[![Version](https://img.shields.io/badge/Version-0.0.0--SNAPSHOT-yellow)](https://github.com/FabricaDeSoftwareINF/server-hubsaude)
[![License](https://img.shields.io/badge/License-SES--GO%2FUFG-green)](#licença)

Biblioteca Java de conveniência para autenticação no HubSaúde.
A classe principal, `SmartTokenClient`, facilita a obtenção de tokens de acesso
em conformidade com o **SMART Backend Services**, implementando OAuth 2.0 com
JWT Bearer Assertion (RFCs 6749, 7521, 7523). A assinatura (client_assertion)
pode ser gerada a partir de arquivo local (PEM ou PKCS#12) ou 
por dispositivo criptográfico via PKCS#11 (HSM). Dessa forma,
contempla tanto certificados autoassinados para testes quanto
certificados ICP-Brasil para produção (A1 em arquivo, A3/A4 via HSM).


## Dependência Maven

```xml
<dependency>
    <groupId>br.gov.go.saude.hubsaude</groupId>
    <artifactId>hubsaude-cliente-java</artifactId>
    <version>0.0.0-SNAPSHOT</version>
</dependency>
```

**Requisitos:** Java 21+, Maven 3.9+

## Início rápido

```java
var client = SmartTokenClient.builder()
        .tokenEndpoint("https://hub.saude.go.gov.br/auth/token")
        .clientId("meu-sistema")
        .privateKeyPem(Path.of("chave-privada.pem"))
        .certificatePem(Path.of("certificado.pem"))
        .build();

String token = client.obtainToken("system/Patient.rs");
```

---

## Verificação pós-credenciamento

Após ter o credenciamento aprovado, use a ferramenta de verificação para confirmar que o acesso está funcionando:

```bash
# Verificação básica
java -cp hubsaude-cliente-java.jar \
    br.gov.go.saude.hubsaude.client.cli.VerificarAcesso \
    --client-id=hs-12345678 \
    --key=minha-chave.pem \
    --cert=meu-certificado.pem

# Com detalhes do token
java -cp hubsaude-cliente-java.jar \
    br.gov.go.saude.hubsaude.client.cli.VerificarAcesso \
    --client-id=hs-12345678 \
    --key=minha-chave.pem \
    --cert=meu-certificado.pem \
    --verbose
```

**Saída esperada (sucesso):**
```
╔═══════════════════════════════════════════════════════════╗
║     HubSaúde - Verificador de Acesso (Pós-Credenciamento) ║
╚═══════════════════════════════════════════════════════════╝

ℹ Configuração:
  Client ID:  hs-12345678
  Chave:      minha-chave.pem
  Certificado:meu-certificado.pem
  Scope:      system/Patient.rs
  TLS:        TLSv1.3
  FHIR Base:  https://fhir.saude.go.gov.br (descoberta automática)

ℹ Obtendo token de acesso...
✓ Token obtido com sucesso!

  Tempo de resposta: 245ms
  Token (primeiros 50 chars): eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOi...

✓ Credenciamento verificado. Acesso ao HubSaúde está funcionando.
```

**Parâmetros disponíveis:**

| Parâmetro | Descrição | Obrigatório |
|-----------|-----------|-------------|
| `--client-id` | ID do cliente (fornecido no credenciamento) | Sim |
| `--key` | Caminho para a chave privada PEM | Sim |
| `--cert` | Caminho para o certificado PEM | Sim |
| `--endpoint` | URL do token endpoint (desabilita descoberta) | Não |
| `--fhir-base` | URL base FHIR (padrão: https://fhir.saude.go.gov.br) | Não |
| `--scope` | Scope a solicitar (padrão: system/Patient.rs) | Não |
| `--password` | Senha da chave privada (se criptografada) | Não |
| `--tls` | Protocolo TLS: TLSv1.3 ou TLSv1.2 (padrão: TLSv1.3) | Não |
| `--verbose` | Mostra detalhes do token obtido | Não |

---

## Como funciona (curl)

A biblioteca abstrai a seguinte requisição HTTPs:

```bash
curl -X POST https://hub.saude.go.gov.br/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "scope=system/Patient.rs" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlELi4uIl19.eyJpc3MiOiJtZXUtc2lzdGVtYSIsInN1YiI6Im1ldS1zaXN0ZW1hIiwiYXVkIjoiaHR0cHM6Ly9odWIuc2F1ZGUuZ28uZ292LmJyL2F1dGgvdG9rZW4iLCJleHAiOjE3MDk3NDAwMDAsImlhdCI6MTcwOTczOTg4MCwianRpIjoiYTFiMmMzZDQtZTVmNi03ODkwLWFiY2QtZWYxMjM0NTY3ODkwIn0.ASSINATURA_RS384"
```

Estrutura do JWT (`client_assertion`), ou seja, `header.payload.signature` onde:

- *header* 
```json
{  
  "alg" : "RS384",
  "typ" : "JWT",
  "x5c" : [ "cert-base64" ]
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
- *signature*: RS384 (RSA + SHA-384) com chave privada ICP-Brasil

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

# 2. Extrair certificado
openssl pkcs12 -in certificado.pfx -clcerts -nokeys -out certificado.pem

# 3. (Opcional) Converter chave para PKCS#8 explícito
openssl pkcs8 -topk8 -nocrypt -in chave-privada.pem -out chave-pkcs8.pem
```

> **Segurança:** Use `-nodes` apenas em ambientes seguros. Para produção, considere manter a chave criptografada ou usar HSM.

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

### Gerar certificados de teste (para hubsaude-simulador)

Para desenvolvimento e testes locais com o `hubsaude-simulador`:

```bash
# Gerar par de chaves RSA 2048-bit
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out test-key.pem

# Gerar certificado autoassinado (válido por 365 dias)
openssl req -new -x509 -key test-key.pem -out test-cert.pem -days 365 \
    -subj "/CN=teste-local/O=Desenvolvimento/C=BR"

# (Opcional) Verificar arquivos gerados
openssl rsa -in test-key.pem -check -noout
openssl x509 -in test-cert.pem -text -noout | head -20
```

Os arquivos `test-key.pem` e `test-cert.pem` podem ser usados diretamente com o cliente.

---

## Configuração completa

```java
var client = SmartTokenClient.builder()
        .tokenEndpoint("https://hub.saude.go.gov.br/auth/token")  // ou .fhirBase() para descoberta
        .clientId("meu-sistema")
        .privateKeyPem(Path.of("chave-privada.pem"))
        .certificatePem(Path.of("certificado.pem"))
        .serverTrustAnchor(Path.of("ca-hubsaude.pem"))  // opcional: CA customizada
        .tlsProtocol("TLSv1.2")                         // opcional: TLS 1.2 (padrão: TLSv1.3)
        .connectTimeout(Duration.ofSeconds(10))          // opcional
        .requestTimeout(Duration.ofSeconds(30))          // opcional
        .assertionTtlSeconds(120)                        // opcional: TTL do JWT
        .enableTokenCache(true)                          // opcional: cache habilitado
        .tokenCacheMarginSeconds(30)                     // opcional: margem de renovação
        .maxRetries(3)                                   // opcional: retries
        .build();
```

### Descoberta automática de endpoint

```java
var client = SmartTokenClient.builder()
        .fhirBase("https://hub.saude.go.gov.br")  // Descobre via .well-known
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
| `unable to find valid certification path` | CA do servidor não confiável | Configurar `.serverTrustAnchor()` ou importar CA no truststore |
| `signature verification failed` | Certificado não corresponde à chave | Verificar: `openssl x509 -noout -modulus -in cert.pem \| openssl md5` vs `openssl rsa -noout -modulus -in key.pem \| openssl md5` |
| `connection timed out` | Firewall ou endpoint incorreto | Verificar conectividade e URL |

---

## Notas Técnicas

### Por que RS384 (e não PS384)?

O algoritmo padrão é **RS384** (RSA PKCS#1 v1.5 + SHA-384) pelos seguintes motivos:

| Critério | RS384 | PS384 (RSA-PSS) |
|----------|-------|-----------------|
| **SMART Backend Services** | ✅ Obrigatório | ⚠️ Opcional |
| **ICP-Brasil (HSM)** | ✅ Universal | ⚠️ Parcial (HSMs antigos) |
| **Interoperabilidade** | ✅ Máxima | ⚠️ Variável |
| **Segurança** | ✅ Adequada | ✅ Superior |

Embora PS384 seja tecnicamente mais robusto contra ataques teóricos de padding oracle, RS384:
- É **obrigatório** pela especificação SMART Backend Services
- É **universalmente suportado** por HSMs e tokens ICP-Brasil
- Oferece segurança **adequada** para o caso de uso (comunicação M2M com TLS 1.3)

**Se precisar usar PS384**, configure manualmente:

```java
SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(
        privateKey, 
        "SHA384withRSAandMGF1"  // PS384
);

var client = SmartTokenClient.builder()
        .signingStrategy(strategy)
        // ...
        .build();
```

> **Nota:** Verifique se o authorization server suporta PS384 antes de usar.

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
                    (client_assertion JWT RS384)
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

Copyright (c) 2026 SES-GO / UFG. Todos os direitos reservados.
