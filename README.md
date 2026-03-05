# hubsaude-cliente-java

Cliente Java para obtenção de token de acesso exigido para 
usufruir dos serviços oferecidos pelo HubSaúde.

## Descrição

Este módulo fornece a classe `SmartTokenClient` que abstrai os detalhes do fluxo de autenticação SMART Backend Services (RFC 7523). Isso inclui:

- Leitura de chaves privadas e certificados PEM
- Montagem do `client_assertion` JWT (RS384)
- Comunicação HTTPS com o endpoint `/auth/token`
- Cache de tokens com renovação proativa
- Retry com backoff exponencial para resiliência
- Thread-safety para uso concorrente

## Dados necessários 

Para acesso ao HubSaúde é preciso obter o token de acesso, o que exige:
- URL do endpoint onde o token é emitido (ex.: `https://hub.saude.go.gov.br/auth/token`). Esta URL pode ser obtida pelo endpoint `[base]/.well-known/smart-configuration` do HubSaúde. Em particular, o campo `token_endpoint` deste endpoint contém a URL necessária para configuração do `SmartTokenClient`.
- `client_id` fornecido pela SES-GO no momento do credenciamento (ex.: `meu-sistema`)
- Chave privada usada para assinar o JWT de client assertion (em formato PEM, PKCS#8 ou via HSM)
- Certificado ICP-Brasil correspondente à chave privada (em formato PEM)
- Vários outros parâmetros podem ser fornecidos para controle de timeouts, cache, retries e validação de certificados.


## Uso básico
```java
var tokenClient = new SmartTokenClient(
        "https://hub.saude.go.gov.br/auth/token",
        "meu-sistema",
        Path.of("chave-privada.pem"),
        Path.of("certificado.pem"));

String accessToken = tokenClient.obtainToken("system/Patient.rs");
```

## Uso com Builder

```java
var tokenClient = SmartTokenClient.builder()
        .tokenEndpoint("https://hub.saude.go.gov.br/auth/token")
        .clientId("meu-sistema")
        .privateKeyPem(Path.of("chave-privada.pem"))
        .certificatePem(Path.of("certificado.pem"))
        .serverTrustAnchor(Path.of("ca-hubsaude.pem"))  // Opcional
        .connectTimeout(Duration.ofSeconds(10))
        .requestTimeout(Duration.ofSeconds(30))
        .assertionTtlSeconds(120)
        .enableTokenCache(true)
        .tokenCacheMarginSeconds(30)
        .maxRetries(3)
        .build();
```

### Chave Privada com Senha (PKCS#8 Criptografada)

```java
var tokenClient = SmartTokenClient.builder()
        .tokenEndpoint("https://hub.saude.go.gov.br/auth/token")
        .clientId("meu-sistema")
        .privateKeyPem(Path.of("chave-privada-encrypted.pem"))
        .privateKeyPassword("minha-senha".toCharArray())  // Senha da chave
        .certificatePem(Path.of("certificado.pem"))
        .build();
```

### HSM via PKCS#11 (Chave Nunca Sai do Hardware)

```java
// Configurar provider PKCS#11
Provider pkcs11Provider = SigningStrategyFactory.configurePkcs11Provider("/etc/pkcs11/hsm.cfg");

// Criar estratégia de assinatura que delega ao HSM
SigningStrategy hsmStrategy = SigningStrategyFactory.fromPkcs11(
        pkcs11Provider,
        "minha-chave-alias",
        "123456".toCharArray());  // PIN do token

var tokenClient = SmartTokenClient.builder()
        .tokenEndpoint("https://hub.saude.go.gov.br/auth/token")
        .clientId("meu-sistema")
        .signingStrategy(hsmStrategy)  // Usa HSM em vez de arquivo PEM
        .certificatePem(Path.of("certificado.pem"))
        .build();
```

### KeyStore (JKS/PKCS#12)

```java
KeyStore ks = KeyStore.getInstance("PKCS12");
ks.load(new FileInputStream("keystore.p12"), "senha-keystore".toCharArray());

SigningStrategy strategy = SigningStrategyFactory.fromKeyStore(
        ks, 
        "alias-da-chave", 
        "senha-da-chave".toCharArray());

var tokenClient = SmartTokenClient.builder()
        .tokenEndpoint("https://hub.saude.go.gov.br/auth/token")
        .clientId("meu-sistema")
        .signingStrategy(strategy)
        .certificatePem(Path.of("certificado.pem"))
        .build();
```

### HashiCorp Vault (via API)

```java
// Obter chave do Vault (exemplo simplificado)
PrivateKey vaultKey = vaultClient.getPrivateKey("secret/data/hubsaude/key");

SigningStrategy strategy = SigningStrategyFactory.fromPrivateKey(vaultKey);

var tokenClient = SmartTokenClient.builder()
        .tokenEndpoint("https://hub.saude.go.gov.br/auth/token")
        .clientId("meu-sistema")
        .signingStrategy(strategy)
        .certificatePem(Path.of("certificado.pem"))
        .build();
```

## Observações

| Recurso                   | Descrição                                                       |
| ------------------------- | --------------------------------------------------------------- |
| **Cache de tokens**       | Tokens são reutilizados até próximo de expiração                |
| **Retry com backoff**     | Falhas transitórias tratadas com backoff exponencial (1s→2s→4s) |
| **Thread-safe**           | Locks por scope evitam renovações duplicadas                    |
| **Logs sanitizados**      | Tokens nunca aparecem em logs                                   |
| **Validação de key-cert** | Verifica correspondência entre chave e certificado              |
| **HSM/PKCS#11**           | Assinatura delegada ao hardware (chave nunca sai do HSM)        |
| **Chaves criptografadas** | Suporte a PKCS#8 e OpenSSL encrypted PEM                        |
| **KeyStore**              | Integração com JKS, PKCS#12 e keystores customizados            |

## Arquitetura: SigningStrategy

O padrão **Strategy** permite flexibilidade na fonte de material criptográfico:

```
┌─────────────────────┐
│  SmartTokenClient   │
│  ─────────────────  │
│  signingStrategy ───┼──► SigningStrategy.sign(byte[])
└─────────────────────┘              │
                                     ▼
                    ┌────────────────────────────────┐
                    │   PrivateKeySigningStrategy    │
                    │   ────────────────────────────│
                    │   - Chave em memória (PEM)     │
                    │   - Handle PKCS#11 (HSM)       │
                    │   - KeyStore (JKS/PKCS#12)     │
                    └────────────────────────────────┘
```

**Classes principais:**

| Classe                      | Responsabilidade                                    |
| --------------------------- | --------------------------------------------------- |
| `SigningStrategy`           | Interface funcional `sign(byte[]) → byte[]`         |
| `PrivateKeySigningStrategy` | Implementação com `java.security.Signature`         |
| `SigningStrategyFactory`    | Factory para criar estratégias de diferentes fontes |
| `PemLoader`                 | Utilitário para carregar PEM (com suporte a senha)  |

## Dependência Maven

```xml
<dependency>
    <groupId>br.gov.go.saude.hubsaude</groupId>
    <artifactId>hubsaude-cliente-java</artifactId>
    <version>0.0.0-SNAPSHOT</version>
</dependency>
```

## Integração com Circuit Breaker

Para cenários de produção, recomenda-se decorar com Resilience4j:

```java
CircuitBreaker circuitBreaker = CircuitBreaker.of("smartToken", CircuitBreakerConfig.custom()
    .failureRateThreshold(50)
    .waitDurationInOpenState(Duration.ofSeconds(30))
    .slidingWindowSize(10)
    .build());

String token = circuitBreaker.executeSupplier(() -> {
    try {
        return tokenClient.obtainToken(scope);
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
});
```

## Testes

### Testes Unitários

Os testes unitários são autocontidos e não dependem de serviços externos:

```bash
mvn test
```

### Testes de Integração

Os testes de integração usam arquitetura **Template Method** com duas implementações independentes:

| Classe                     | Infraestrutura | Tempo | Uso Recomendado             |
| -------------------------- | -------------- | ----- | --------------------------- |
| `SmartTokenClientJarIT`    | ProcessBuilder | ~5s   | Desenvolvimento local       |
| `SmartTokenClientDockerIT` | Testcontainers | ~9s   | CI/CD, builds reproduzíveis |

#### Executar Testes JAR (mais rápido)

```bash
mvn verify -Dit.test=SmartTokenClientJarIT
```

**Pré-requisitos:** Java 21+ instalado

#### Executar Testes Docker

```bash
mvn verify -Dit.test=SmartTokenClientDockerIT
```

**Pré-requisitos:** Docker instalado e em execução

#### Executar Todos os Testes de Integração

```bash
mvn verify
```

> **Arquitetura:** Os testes estão em `SmartTokenClientIntegrationTestBase` (classe abstrata).
> Cada implementação (`*JarIT`, `*DockerIT`) apenas define como iniciar/parar o simulador.

## Licença

Copyright (c) 2026 SES-GO / UFG. Todos os direitos reservados.
