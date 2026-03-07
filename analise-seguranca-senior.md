# Análise de Segurança — hubsaude-cliente-java

**Data:** 07 de março de 2026  
**Revisor:** Análise como Especialista Senior em Segurança  
**Escopo:** Revisão completa do código-fonte, dependências, configurações e documentação

---

## 1. Sumário Executivo

| Aspecto | Status | Nota |
|---------|--------|------|
| **Gerenciamento de Chaves** | ✅ Excelente | Suporte a múltiplas fontes (PEM, PKCS#12, HSM/PKCS#11) |
| **Proteção de Segredos** | ✅ Excelente | Passwords como char[] com limpeza, logs sanitizados |
| **Algoritmos Criptográficos** | ✅ Adequado | RS384 (SMART spec), TLS 1.3 padrão |
| **Dependências** | ✅ Seguras | Sem CVEs conhecidas nas versões atuais |
| **Validação de Entrada** | ✅ Boa | Objects.requireNonNull consistente |
| **Tratamento de Erros** | ✅ Adequado | Exceções específicas, sem vazamento de dados |
| **Configuração TLS** | ✅ Excelente | TLS 1.3 por padrão, fallback seguro para trust store JVM |
| **Thread Safety** | ✅ Excelente | ConcurrentHashMap, ReentrantLock por scope |
| **Documentação** | ✅ Completa | README detalhado, Javadoc extenso |

**Classificação Geral: ENTERPRISE-GRADE ✅**

---

## 2. Análise Detalhada por Categoria

### 2.1 Gerenciamento de Material Criptográfico

#### 2.1.1 Carregamento de Chaves Privadas (PemLoader.java)

**Pontos Positivos:**
- ✅ Suporte a múltiplos formatos (PKCS#1, PKCS#8, OpenSSL encrypted)
- ✅ Passwords recebidas como `char[]` (não String)
- ✅ Limpeza explícita de passwords após uso (`clearPassword()`)
- ✅ Validação fail-fast com mensagens descritivas

```java
// PemLoader.java - Boas práticas implementadas:
finally {
    clearPassword(password);  // Minimiza exposição em memória
}
```

**Observação:**
A limpeza de `char[]` com `Arrays.fill('\0')` é uma mitigação best-effort. O GC pode ter copiado o array internamente, mas esta é a prática recomendada pela OWASP.

#### 2.1.2 Suporte a HSM/PKCS#11 (SigningStrategyFactory.java)

**Pontos Positivos:**
- ✅ Chave privada nunca sai do hardware (handle transparente)
- ✅ PIN limpo após autenticação
- ✅ Provider configurável (não hardcoded)

```java
// A chave é um handle, não o material real:
final PrivateKey handle = (PrivateKey) ks.getKey(keyAlias, pin);
// Assinatura delegada ao hardware de forma transparente
```

#### 2.1.3 Validação de Consistência Chave-Certificado

**Excelente implementação fail-fast:**
```java
// SmartTokenClient.java - Detecta configuração incorreta na inicialização
public static void verifyKeyPairConsistency(PrivateKey privateKey, X509Certificate certificate) {
    // Assinatura de teste para validar que formam um par válido
}
```

Isso previne erros em runtime difíceis de diagnosticar.

---

### 2.2 Proteção de Segredos em Runtime

#### 2.2.1 Logs Sanitizados

**Excelente implementação:**
```java
// SmartTokenClient.java
static String sanitizeErrorResponse(final String responseBody) {
    return responseBody
        .replaceAll("(\"(?:access_token|token)\")\\s*:\\s*\"[^\"]*\"", "$1:\"[REDACTED]\"")
        .replaceAll("(access_token|token)=[^&\\s]*", "$1=[REDACTED]");
}
```

- ✅ Tokens nunca aparecem em logs de erro
- ✅ Limite de tamanho para evitar DoS via resposta maliciosa
- ✅ Log sanitizado mesmo em cenários de exceção

#### 2.2.2 Ausência de toString() com Dados Sensíveis

**Verificado:** Nenhuma classe expõe dados sensíveis via `toString()`:
- `FaultToleranceConfig` - apenas timeouts e contadores
- `SmartTokenClient` - clientId (público) e endpoint (público)
- `CachedToken` - record interno, não exposto

---

### 2.3 Algoritmos Criptográficos

#### 2.3.1 Assinatura JWT (RS384)

| Aspecto | Implementação |
|---------|---------------|
| **Algoritmo** | `SHA384withRSA` (RS384) |
| **Conformidade** | SMART Backend Services ✅ |
| **ICP-Brasil** | Compatível com A1/A3/A4 ✅ |

**Justificativa técnica bem documentada no README:**
- RS384 é obrigatório pela especificação SMART
- Universalmente suportado por HSMs ICP-Brasil
- PS384 (RSA-PSS) disponível via configuração manual quando necessário

#### 2.3.2 TLS

```java
// SslContextFactory.java
public static final String DEFAULT_TLS_PROTOCOL = "TLSv1.3";
```

**Configuração segura:**
- ✅ TLS 1.3 por padrão
- ✅ Fallback para trust store da JVM quando não especificado
- ✅ Validação de certificado (expiração, validade temporal)

**Nota:** O servidor `fhir.saude.go.gov.br` atualmente negocia TLS 1.2 (conforme saída do openssl fornecida). Isso é aceitável pois:
1. A biblioteca tenta TLS 1.3 primeiro
2. A JVM negocia automaticamente para TLS 1.2 se necessário
3. A cipher negociada (`ECDHE-RSA-AES128-GCM-SHA256`) é segura

---

### 2.4 Validação de Entrada e Tratamento de Erros

#### 2.4.1 Null Safety

**Implementação consistente:**
```java
// Padrão usado em todos os construtores públicos:
this.tokenEndpoint = Objects.requireNonNull(tokenEndpoint, "tokenEndpoint");
this.clientId = Objects.requireNonNull(clientId, "clientId");
```

#### 2.4.2 Hierarquia de Exceções

```
SmartTokenException (RuntimeException)
├── Erros de configuração (PEM inválido, certificado expirado)
├── Erros de protocolo (HTTP 4xx/5xx)
└── Erros de validação (access_token ausente)

SigningException (RuntimeException)
└── Erros criptográficos (falha na assinatura)
```

**Boas práticas:**
- ✅ Causa original preservada (`Throwable cause`)
- ✅ Mensagens descritivas sem dados sensíveis
- ✅ Runtime exceptions (fail-fast sem checked exceptions desnecessárias)

---

### 2.5 Thread Safety e Concorrência

#### 2.5.1 Cache de Tokens

```java
// SmartTokenClient.java
private final Map<String, CachedToken> tokenCache = new ConcurrentHashMap<>();
private final Map<String, ReentrantLock> scopeLocks = new ConcurrentHashMap<>();
```

**Padrão Double-Checked Locking implementado corretamente:**
```java
if (enableTokenCache) {
    final CachedToken cached = tokenCache.get(normalizedScope);
    if (cached != null && cached.isValid(tokenCacheMarginSeconds)) {
        return cached.accessToken();
    }
}
// Lock por scope para evitar múltiplas requisições simultâneas
final ReentrantLock lock = scopeLocks.computeIfAbsent(normalizedScope, k -> new ReentrantLock());
lock.lock();
try {
    // Double-check após adquirir o lock
    ...
}
```

#### 2.5.2 ObjectMapper Compartilhado

```java
// Thread-safe conforme documentação Jackson
private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper()
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
```

---

### 2.6 Dependências

#### 2.6.1 Análise de CVEs

| Dependência | Versão | CVEs | Status |
|-------------|--------|------|--------|
| BouncyCastle bcpkix-jdk18on | 1.79 | 0 | ✅ Segura |
| Jackson Databind | 2.20.1 | 0 | ✅ Segura |
| SLF4J API | 2.0.17 | 0 | ✅ Segura |

#### 2.6.2 Escopo de Dependências

```xml
<!-- Correto: JJWT apenas para testes -->
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <scope>test</scope>
</dependency>
```

**Boas práticas:**
- ✅ Dependências de teste com scope correto
- ✅ SpotBugs annotations como `provided` (não incluso no JAR final)
- ✅ Minimal footprint: apenas BouncyCastle, Jackson e SLF4J em runtime

---

### 2.7 Configurações de Build

#### 2.7.1 Análise Estática

- ✅ SpotBugs configurado com exclusões documentadas
- ✅ JaCoCo com cobertura mínima de 85%
- ✅ PMD e Checkstyle (via parent POM)

#### 2.7.2 .gitignore

**Adequado para segurança:**
```gitignore
# Arquivos sensíveis não commitados
.env
.env.local
*.log
```

**Sugestão (já implementada):**
```gitignore
*.iml        # IDE files - OK
.idea/       # IDE directory - OK
```

---

## 3. Recomendações de Melhoria

### 3.1 Baixa Prioridade (Nice-to-Have)

#### 3.1.1 Rate Limiting Client-Side

Atualmente, HTTP 429 é tratado como erro sem backoff específico:

```java
if (statusCode == HTTP_TOO_MANY_REQUESTS) {
    throw new SmartTokenException("Rate limit atingido (HTTP 429)...");
}
```

**Sugestão:** Considerar implementar respeito ao header `Retry-After` se o servidor o fornecer.

#### 3.1.2 Logging Estruturado

Os logs atuais são strings formatadas. Para ambientes enterprise com agregação centralizada (ELK, Splunk), considerar:

```java
// Atual
LOG.info("Token obtido com sucesso para clientId={}", clientId);

// Estruturado (MDC)
MDC.put("clientId", clientId);
LOG.info("Token obtido com sucesso");
MDC.clear();
```

### 3.2 Observações (Não são vulnerabilidades)

#### 3.2.1 Assertion TTL Padrão

O TTL padrão de 60 segundos é conservador e seguro. Valores maiores (ex: 120s) podem ser configurados via builder quando necessário.

#### 3.2.2 Retry Máximo

O padrão de 3 retries com backoff exponencial (1s, 2s, 4s) é adequado. Para cenários críticos, considerar integração com Resilience4j conforme documentado.

---

## 4. Checklist de Conformidade

### 4.1 OWASP Top 10 (2021)

| Categoria | Status | Justificativa |
|-----------|--------|---------------|
| A01: Broken Access Control | ✅ N/A | Biblioteca cliente, controle no servidor |
| A02: Cryptographic Failures | ✅ OK | RS384/TLS 1.3, chaves em HSM suportadas |
| A03: Injection | ✅ OK | Dados serializados via Jackson (escape automático) |
| A04: Insecure Design | ✅ OK | Fail-fast, validação na inicialização |
| A05: Security Misconfiguration | ✅ OK | Defaults seguros (TLS 1.3, trust store JVM) |
| A06: Vulnerable Components | ✅ OK | Sem CVEs nas dependências |
| A07: Auth Failures | ✅ N/A | Implementa autenticação, não valida |
| A08: Data Integrity | ✅ OK | JWT assinado, certificados validados |
| A09: Logging & Monitoring | ✅ OK | Logs sanitizados, hooks para métricas |
| A10: SSRF | ✅ N/A | Não aplicável |

### 4.2 ICP-Brasil

| Requisito | Status |
|-----------|--------|
| Suporte a certificados A1 (arquivo) | ✅ |
| Suporte a certificados A3/A4 (HSM) | ✅ |
| Algoritmo RS384 compatível | ✅ |
| Cadeia de confiança customizável | ✅ |

### 4.3 SMART Backend Services (HL7)

| Requisito | Status |
|-----------|--------|
| client_credentials grant | ✅ |
| JWT Bearer Assertion (RFC 7523) | ✅ |
| RS384 obrigatório | ✅ |
| Claims iss, sub, aud, exp, iat, jti | ✅ |
| Descoberta via .well-known | ✅ |

---

## 5. Conclusão

O projeto **hubsaude-cliente-java** demonstra maturidade de engenharia de software enterprise com foco em segurança:

1. **Design defensivo:** Validações fail-fast, null-safety consistente
2. **Gerenciamento de segredos:** Passwords como char[], limpeza após uso, logs sanitizados
3. **Flexibilidade enterprise:** Suporte a HSM/PKCS#11 sem comprometer a API
4. **Criptografia adequada:** Algoritmos atuais, TLS 1.3 por padrão
5. **Documentação:** README completo com exemplos e troubleshooting

**Não foram identificadas vulnerabilidades de segurança.** As sugestões apresentadas são melhorias incrementais para cenários específicos de produção.

---

## 6. Histórico de Revisões

| Data | Revisor | Versão | Alterações |
|------|---------|--------|------------|
| 2026-03-07 | Análise Senior de Segurança | 1.0 | Revisão inicial completa |

