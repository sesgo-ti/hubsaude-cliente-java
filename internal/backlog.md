# Backlog — hubsaude-cliente-java

Itens identificados em revisão de prontidão para liberação (mai/2026)
que **não são bloqueadores** para a distribuição interna atual, mas
devem ser considerados oportunamente no caminho até a versão `1.0.0`.

A numeração preserva a ordem da revisão original; entradas marcadas
com prioridade indicam o quanto pesam para o marco `1.0`:

- **A** — desejável antes de `1.0.0`
- **B** — bom ter, pode ficar para `1.x`
- **C** — opcional / depende de demanda real

Cada item registra também um **Status** (última reconciliação com o
código em 2026-07-06, issue #737):

- **Aberto** — nenhuma ação realizada;
- **Parcial** — parte do item já implementada (detalhes no item);
- **Concluído** — implementado; referência a commit/arquivo incluída.

## Disposição dos itens 1–6

Os itens 1–6 da revisão original (mai/2026) eram os **bloqueadores**
para a distribuição interna e foram resolvidos antes do primeiro
registro deste arquivo no repositório (commit `8b31ab2`, 2026-05-20).
Por isso não constam aqui: este backlog preservou apenas os itens
não-bloqueadores (7–20), mantendo a numeração original para
rastreabilidade com a revisão.

## Processo de manutenção deste backlog

Para manter este documento sincronizado com o código:

1. Todo PR que resolver (total ou parcialmente) um item deve
   atualizar a linha **Status** do item, com referência ao PR/commit.
2. Itens removidos devem ter a disposição registrada (não apagar
   silenciosamente).
3. A cada release, revisar os status como parte do checklist.
4. Alternativa em avaliação: migrar itens abertos para issues do
   GitHub, mantendo este arquivo apenas como índice.

---

## 7. Documentar política de compatibilidade de API — **A**

**Status: Parcial** — SemVer estrito já documentado no
`CONTRIBUTING.md` (seção de versionamento). Pendente: declarar API
pública vs. interna e estabilizar assinaturas antes do corte.

Hoje o projeto está em `0.x` deliberadamente (API ainda em
consolidação). Antes do `1.0.0`:

- declarar explicitamente no `README.md` (ou em `COMPATIBILITY.md`) o
  que é considerado API pública vs. interna;
- definir política de versionamento pós-`1.0` (SemVer estrito);
- estabilizar nomes e assinaturas dos métodos do `SmartTokenClient` e
  do `SmartTokenClientBuilder` antes do corte.

## 8. `module-info.java` e segregação de pacotes — **A**

**Status: Aberto** — sem `module-info.java`; utilitários seguem no
pacote raiz `br.gov.go.saude.hubsaude.client`.

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

**Status: Parcial** — `Arrays.fill(password, '\0')` presente em
`PemLoader`. Pendente auditar os demais pontos do builder
(`clientKeyPassword`, PIN do PKCS#11) e a retenção pós-`build()`.

Garantir, para todos os pontos do builder que recebem senha/PIN
(`privateKeyPassword`, `clientKeyPassword`, PIN do PKCS#11):

- a referência não é retida indefinidamente após `build()`;
- há `Arrays.fill(senha, '\0')` ao final do uso (em `build()` ou no
  `SigningStrategy`);
- o builder não vaza a referência para o cliente após construção.

## 10. Robustez do JWT (claims `jti`, `iat`, `exp`) — **A**

**Status: Parcial** — `jti` UUIDv4 único por assertion implementado
(`SmartTokenClient`). Pendentes: tolerância configurável de clock
skew e refresh em `invalid_grant` por skew.

- confirmar `jti` UUIDv4 e único por assertion;
- `iat`/`exp` em `Instant.now()` truncado a segundos (evita problemas
  com servidores que exigem epoch inteiro);
- aceitar tolerância configurável de clock skew;
- considerar refresh automático quando o servidor responde
  `invalid_grant` por skew detectável.

## 11. Retry policy com jitter — **A**

**Status: Aberto** — backoff segue determinístico, sem jitter nem
`RetryPolicy` injetável.

Backoff atual (1s, 2s, 4s) é determinístico e sujeito a *thundering
herd*. Adicionar:

- *jitter* aleatório (full jitter ou equal jitter);
- política de idempotência: retry apenas em timeouts/5xx, nunca em
  4xx (especialmente `invalid_client`, `invalid_grant`);
- expor a política como `RetryPolicy` injetável (extensibilidade).

## 12. Observabilidade — **B**

**Status: Aberto.**

A biblioteca já usa SLF4J. Para uso em produção:

- expor métricas opcionais via `Micrometer` (`MeterRegistry`
  injetável) — counters de sucesso/erro, histograma de latência;
- *hooks* de tracing (atributos OpenTelemetry no span da request
  HTTP);
- manter zero deps obrigatórias para quem não usa observabilidade.

## 13. Hostname verification em TLS — **A**

**Status: Aberto** — sem teste explícito de regressão; nenhuma
chamada a `setEndpointIdentificationAlgorithm` no código.

Confirmar que, mesmo com `serverTrustAnchor` custom, o `HttpClient`
mantém `SSLParameters.setEndpointIdentificationAlgorithm("HTTPS")`.
Adicionar teste explícito de regressão.

## 14. Sanitização de mensagens de exceção — **A**

**Status: Aberto** — auditoria e testes de contrato ainda não
realizados.

Auditar `SmartTokenException` e `SigningException`:

- nenhum body HTTP integral é propagado em `getMessage()` (alguns
  servidores ecoam parâmetros enviados, incluindo `client_assertion`);
- erros de assinatura não vazam fragmentos da chave ou do PIN;
- testes específicos garantindo o contrato.

## 15. Validação explícita em `build()` — **B**

**Status: Parcial** — exclusividade `tokenEndpoint`/`fhirBase` já
validada com `IllegalStateException` e mensagem clara em `build()`
(`SmartTokenClientBuilder`). Pendente: revisar combinações de
`signingStrategy`, `privateKeyPem`, `clientKeyStore`.

`tokenEndpoint` e `fhirBase` são mutuamente exclusivos. Garantir:

- mensagem clara e cedo em `build()` (não NPE tardio);
- mesma higiene para combinações inválidas de `signingStrategy`,
  `privateKeyPem`, `clientKeyStore`.

## 16. Reduzir acoplamento com BouncyCastle — **C**

**Status: Aberto** — aguardando demanda real, conforme previsto.

BC como dependência `compile` pode atrapalhar consumidores em
ambientes regulados (FIPS). Alternativas:

- avaliar parser PEM apenas com APIs do JDK 21;
- ou expor SPI para que o consumidor forneça o `PemLoader`;
- decisão guiada por demanda real — não fazer preemptivamente.

## 17. Decisão sobre exceção checada vs. runtime — **A**

**Status: Parcial** — decisão tomada e implementada:
`SmartTokenException` e `SigningException` estendem
`RuntimeException`. Pendente: documentar o racional no Javadoc e o
impacto em consumidores (Resilience4j / Spring Retry).

Definir e documentar explicitamente no Javadoc:

- `SmartTokenException` é checada ou runtime?
- racional da decisão (tendência atual: runtime para libs públicas);
- impacto em consumidores que envolvem em Resilience4j / Spring
  Retry.

## 18. Cobertura JaCoCo mais granular — **B**

**Status: Aberto.**

Substituir gate único de 85% no `BUNDLE` por:

- gate por `CLASS` ou `INSTRUCTION` com piso definido;
- exclusões explícitas e justificadas (apenas PKCS#11, hoje);
- revisão periódica do `target/site/jacoco`.

## 19. Mutation testing (PIT) — **B**

**Status: Aberto.**

85% de linhas + AssertJ não garante qualidade de assertion em
biblioteca de segurança. Investir em:

- `pitest-maven` no perfil `quality`;
- gate inicial baixo (ex.: 60% mutation coverage) com aumento gradual.

## 20. Organização de arquivos na raiz — **C**

**Status: Concluído** (disposição alternativa) — `backlog.md`,
`plano.md` e `problemas.md` foram movidos para `internal/`
(commit `f7d9b16`, 2026-05-22), em vez de `docs/` como sugerido.
A raiz mantém apenas os arquivos de release.

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

- **[Aberto]** validar artefato consumido em projeto vazio
  (`mvn dependency:tree`) para detectar leak de dependências
  `provided`/`test`;
- **[Aberto]** adotar `revapi` ou `japicmp` no CI para detectar
  quebras acidentais entre patches;
- **[Aberto]** configurar `dependabot.yml` ou Renovate específico
  para o repo;
- **[Concluído]** habilitar `--release 21` no `maven-compiler-plugin`
  (não apenas `source`/`target`) — implementado via
  `<maven.compiler.release>` no `pom.xml`.
