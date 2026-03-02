# hubsaude-cliente-java

Cliente Java enterprise-grade para autenticação SMART Backend Services junto ao HubSaúde.

## Descrição

Este módulo fornece a classe `SmartTokenClient` que abstrai toda a complexidade do fluxo de autenticação SMART Backend Services (RFC 7523):

- Leitura de chaves privadas e certificados PEM
- Montagem do `client_assertion` JWT (RS384)
- Comunicação HTTP com o endpoint `/auth/token`
- Cache de tokens com renovação proativa
- Retry com backoff exponencial para resiliência
- Thread-safety para uso concorrente

## Uso Rápido

```java
// Uso básico
var tokenClient = new SmartTokenClient(
        "https://hub.saude.go.gov.br/auth/token",
        "meu-sistema",
        Path.of("chave-privada.pem"),
        Path.of("certificado.pem"));

String accessToken = tokenClient.obtainToken("system/Patient.rs");
```

## Uso Avançado (Builder)

```java
var tokenClient = SmartTokenClient.builder()
        .tokenEndpoint("https://hub.saude.go.gov.br/auth/token")
        .clientId("meu-sistema")
        .privateKeyPem(Path.of("chave-privada.pem"))
        .certificatePem(Path.of("certificado.pem"))
        .serverCertificatePem(Path.of("ca-hubsaude.pem"))  // Opcional: trust anchor
        .connectTimeout(Duration.ofSeconds(10))
        .requestTimeout(Duration.ofSeconds(30))
        .assertionTtlSeconds(120)
        .enableTokenCache(true)
        .tokenCacheMarginSeconds(30)
        .maxRetries(3)
        .build();
```

## Recursos Enterprise

| Recurso | Descrição |
|---------|-----------|
| **Cache de tokens** | Tokens são reutilizados até próximo de expiração |
| **Retry com backoff** | Falhas transitórias tratadas com backoff exponencial (1s→2s→4s) |
| **Thread-safe** | Locks por scope evitam renovações duplicadas |
| **Logs sanitizados** | Tokens nunca aparecem em logs |
| **Validação de key-cert** | Verifica correspondência entre chave e certificado |

## Dependência Maven

```xml
<dependency>
    <groupId>br.gov.go.saude.hubsaude</groupId>
    <artifactId>hubsaude-cliente-java</artifactId>
    <version>1.0.0-SNAPSHOT</version>
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

| Classe | Infraestrutura | Tempo | Uso Recomendado |
|--------|----------------|-------|-----------------|
| `SmartTokenClientJarIT` | ProcessBuilder | ~5s | Desenvolvimento local |
| `SmartTokenClientDockerIT` | Testcontainers | ~9s | CI/CD, builds reproduzíveis |

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
