# Backlog — hubsaude-cliente-java

Itens identificados em revisão de prontidão para liberação (mai/2026)
que **não são bloqueadores** para a distribuição interna atual, mas
devem ser considerados oportunamente no caminho até a versão `1.0.0`.

A numeração preserva a ordem da revisão original; entradas marcadas
com prioridade indicam o quanto pesam para o marco `1.0`:

- **A** — desejável antes de `1.0.0`
- **B** — bom ter, pode ficar para `1.x`
- **C** — opcional / depende de demanda real

---

## 7. Documentar política de compatibilidade de API — **A**

Hoje o projeto está em `0.x` deliberadamente (API ainda em
consolidação). Antes do `1.0.0`:

- declarar explicitamente no `README.md` (ou em `COMPATIBILITY.md`) o
  que é considerado API pública vs. interna;
- definir política de versionamento pós-`1.0` (SemVer estrito);
- estabilizar nomes e assinaturas dos métodos do `SmartTokenClient` e
  do `SmartTokenClientBuilder` antes do corte.

## 8. `module-info.java` e segregação de pacotes — **A**

Hoje todos os 10 arquivos vivem em `br.gov.go.saude.hubsaude.client`.
Para uma biblioteca pública em Java 21:

- introduzir `module-info.java` com `exports` restritos;
- mover utilitários (`PemLoader`, `SslContextFactory`,
  `FaultToleranceConfig`) para subpacote `internal` (ou torná-los
  package-private), evitando que consumidores dependam de classes
  internas;
- `requires transitive` apenas onde tipos aparecem em assinaturas
  públicas (ex.: `java.net.http`).

## 9. Auditoria do tratamento de `char[]` — **A**

Garantir, para todos os pontos do builder que recebem senha/PIN
(`privateKeyPassword`, `clientKeyPassword`, PIN do PKCS#11):

- a referência não é retida indefinidamente após `build()`;
- há `Arrays.fill(senha, '\0')` ao final do uso (em `build()` ou no
  `SigningStrategy`);
- o builder não vaza a referência para o cliente após construção.

## 10. Robustez do JWT (claims `jti`, `iat`, `exp`) — **A**

- confirmar `jti` UUIDv4 e único por assertion;
- `iat`/`exp` em `Instant.now()` truncado a segundos (evita problemas
  com servidores que exigem epoch inteiro);
- aceitar tolerância configurável de clock skew;
- considerar refresh automático quando o servidor responde
  `invalid_grant` por skew detectável.

## 11. Retry policy com jitter — **A**

Backoff atual (1s, 2s, 4s) é determinístico e sujeito a *thundering
herd*. Adicionar:

- *jitter* aleatório (full jitter ou equal jitter);
- política de idempotência: retry apenas em timeouts/5xx, nunca em
  4xx (especialmente `invalid_client`, `invalid_grant`);
- expor a política como `RetryPolicy` injetável (extensibilidade).

## 12. Observabilidade — **B**

A biblioteca já usa SLF4J. Para uso em produção:

- expor métricas opcionais via `Micrometer` (`MeterRegistry`
  injetável) — counters de sucesso/erro, histograma de latência;
- *hooks* de tracing (atributos OpenTelemetry no span da request
  HTTP);
- manter zero deps obrigatórias para quem não usa observabilidade.

## 13. Hostname verification em TLS — **A**

Confirmar que, mesmo com `serverTrustAnchor` custom, o `HttpClient`
mantém `SSLParameters.setEndpointIdentificationAlgorithm("HTTPS")`.
Adicionar teste explícito de regressão.

## 14. Sanitização de mensagens de exceção — **A**

Auditar `SmartTokenException` e `SigningException`:

- nenhum body HTTP integral é propagado em `getMessage()` (alguns
  servidores ecoam parâmetros enviados, incluindo `client_assertion`);
- erros de assinatura não vazam fragmentos da chave ou do PIN;
- testes específicos garantindo o contrato.

## 15. Validação explícita em `build()` — **B**

`tokenEndpoint` e `fhirBase` são mutuamente exclusivos. Garantir:

- mensagem clara e cedo em `build()` (não NPE tardio);
- mesma higiene para combinações inválidas de `signingStrategy`,
  `privateKeyPem`, `clientKeyStore`.

## 16. Reduzir acoplamento com BouncyCastle — **C**

BC como dependência `compile` pode atrapalhar consumidores em
ambientes regulados (FIPS). Alternativas:

- avaliar parser PEM apenas com APIs do JDK 21;
- ou expor SPI para que o consumidor forneça o `PemLoader`;
- decisão guiada por demanda real — não fazer preemptivamente.

## 17. Decisão sobre exceção checada vs. runtime — **A**

Definir e documentar explicitamente no Javadoc:

- `SmartTokenException` é checada ou runtime?
- racional da decisão (tendência atual: runtime para libs públicas);
- impacto em consumidores que envolvem em Resilience4j / Spring
  Retry.

## 18. Cobertura JaCoCo mais granular — **B**

Substituir gate único de 85% no `BUNDLE` por:

- gate por `CLASS` ou `INSTRUCTION` com piso definido;
- exclusões explícitas e justificadas (apenas PKCS#11, hoje);
- revisão periódica do `target/site/jacoco`.

## 19. Mutation testing (PIT) — **B**

85% de linhas + AssertJ não garante qualidade de assertion em
biblioteca de segurança. Investir em:

- `pitest-maven` no perfil `quality`;
- gate inicial baixo (ex.: 60% mutation coverage) com aumento gradual.

## 20. Organização de arquivos na raiz — **C**

`problemas.md` e `plano.md` na raiz misturam documentação operacional
com docs de release. Sugestão:

- mover para `docs/troubleshooting.md` e `docs/plano-maven-central.md`;
- linkar a partir do `README.md`;
- manter na raiz apenas: `README.md`, `LICENSE`, `NOTICE`,
  `CHANGELOG.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  `SECURITY.md`, `backlog.md`.

---

## Higiene adicional pré-1.0

Itens menores mencionados na revisão, para checklist de release `1.0`:

- validar artefato consumido em projeto vazio (`mvn dependency:tree`)
  para detectar leak de dependências `provided`/`test`;
- adotar `revapi` ou `japicmp` no CI para detectar quebras acidentais
  entre patches;
- configurar `dependabot.yml` ou Renovate específico para o repo;
- habilitar `--release 21` no `maven-compiler-plugin` (não apenas
  `source`/`target`), evitando uso acidental de APIs introduzidas em
  versões posteriores.
