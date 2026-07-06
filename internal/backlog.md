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
código em 2026-07-06; segunda passada no mesmo dia corrigiu estados
que a issue #737 registrou incorretamente — itens 10, 11 e 14):

- **Aberto** — nenhuma ação realizada;
- **Parcial** — parte do item já implementada (detalhes no item);
- **Concluído** — implementado; referência a commit/arquivo incluída.

## Recalibração de expectativas (2026-07-06)

A régua original assumia biblioteca pública no Maven Central. A
publicação no Central está **adiada** (ver `plano.md`); a
distribuição real é o GitHub Packages do monorepo, com autenticação
e consumidores internos conhecidos. Consequências aplicadas nesta
revisão:

- infraestrutura de qualidade adicional (itens 12, 18, 19) rebaixada
  para **C** — o projeto já roda Checkstyle, PMD, SpotBugs, JaCoCo
  (85%), OWASP dependency-check e ArchUnit sobre ~11 classes; o
  custo marginal supera o benefício sem demanda concreta;
- item 8 reescopado para o caminho barato (`Automatic-Module-Name`
  no manifest + utilitários package-private); JPMS completo fica
  condicionado a demanda;
- itens atrelados a consumo externo amplo (parte do 7; higiene
  revapi/japicmp) condicionados ao destravamento do Maven Central;
- permanecem **A** os itens de segurança de custo baixo e valor
  real: 9 (`char[]`), 13 (hostname verification), 14 (restante da
  sanitização) e 17 (Javadoc das exceções).

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
A formalização completa (documento de compatibilidade, verificação
automatizada) fica condicionada ao destravamento do Maven Central;
enquanto a distribuição for interna, basta a declaração no
`README.md`.

Hoje o projeto está em `0.x` deliberadamente (API ainda em
consolidação). Antes do `1.0.0`:

- declarar explicitamente no `README.md` (ou em `COMPATIBILITY.md`) o
  que é considerado API pública vs. interna;
- definir política de versionamento pós-`1.0` (SemVer estrito);
- estabilizar nomes e assinaturas dos métodos do `SmartTokenClient` e
  do `SmartTokenClientBuilder` antes do corte.

## 8. Encapsulamento do pacote e `Automatic-Module-Name` — **A**

*(reescopado em 2026-07-06; JPMS completo rebaixado para C)*

**Status: Aberto** — sem `Automatic-Module-Name` no manifest;
utilitários seguem públicos no pacote raiz.

Escopo recomendado (barato, resolve o essencial):

- adicionar `Automatic-Module-Name`
  (`br.gov.go.saude.hubsaude.client`) ao manifest do JAR, reservando
  o nome do módulo;
- auditar quais utilitários podem ser package-private — candidatos:
  `PemLoader`, `SslContextFactory` (`RetryPolicy` já é
  package-private; `FaultToleranceConfig` é construído pelo builder
  e pode não precisar ser público).

`module-info.java` completo (`exports` restritos, `requires
transitive`) fica condicionado a demanda real de consumidores
modulares — não fazer preemptivamente.

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

## 10. Robustez do JWT (claims `jti`, `iat`, `exp`) — **B**

*(rebaixado de A em 2026-07-06)*

**Status: Parcial** — `jti` UUIDv4 único por assertion implementado;
`iat`/`exp` já emitidos como epoch inteiro (`getEpochSecond` em
`SmartTokenClient` — a reconciliação anterior não registrou).
Pendente apenas: tolerância configurável de clock skew, sem relato
de problema real — implementar sob demanda.

- ~~confirmar `jti` UUIDv4 e único por assertion~~ — feito;
- ~~`iat`/`exp` truncados a segundos~~ — feito (`getEpochSecond`);
- aceitar tolerância configurável de clock skew — pendente;
- ~~refresh automático quando o servidor responde `invalid_grant`
  por skew detectável~~ — **descartado** (2026-07-06): contraria a
  política do item 11 (nunca retry em 4xx) e dependeria de
  heurística frágil sobre a resposta do servidor.

## 11. Retry policy com jitter — **A**

**Status: Parcial** — corrigido em 2026-07-06: a reconciliação
anterior registrou "Aberto" indevidamente. `RetryPolicy`
(package-private) já existe: retry restrito a 429/500/502/503/504 —
exatamente a política de idempotência pedida abaixo — e
`Retry-After` honrado com teto de 60s. Pendente apenas: jitter.

- *jitter* aleatório (full jitter ou equal jitter) — **pendente**;
- ~~política de idempotência: retry apenas em timeouts/5xx, nunca em
  4xx (especialmente `invalid_client`, `invalid_grant`)~~ — feito
  (`RetryPolicy.isRetriableStatus`);
- expor a política como `RetryPolicy` injetável — rebaixado para
  **C** (guiado por demanda real; não fazer preemptivamente).

## 12. Observabilidade — **C**

*(rebaixado de B em 2026-07-06)*

**Status: Aberto** — guiado por demanda real. O cliente mantém cache
de token: o volume de chamadas ao endpoint é baixo por natureza e o
consumidor pode instrumentar por fora (latência/erros de
`obtainToken`).

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

**Status: Parcial** — corrigido em 2026-07-06: a reconciliação
anterior registrou "Aberto" indevidamente. `sanitizeErrorResponse`
já implementado, aplicado aos erros HTTP de `SmartTokenClient` e
testado (truncamento em 500 chars, null-safe). Pendente: auditar
`SigningException` (não vazar fragmentos de chave/PIN) e testes de
contrato para esse caso.

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

## 18. Cobertura JaCoCo mais granular — **C**

*(rebaixado de B em 2026-07-06)*

**Status: Aberto** — gate de 85% no `BUNDLE` sobre ~11 classes já é
apertado; granularidade extra só sob evidência de classe crítica
descoberta.

Substituir gate único de 85% no `BUNDLE` por:

- gate por `CLASS` ou `INSTRUCTION` com piso definido;
- exclusões explícitas e justificadas (apenas PKCS#11, hoje);
- revisão periódica do `target/site/jacoco`.

## 19. Mutation testing (PIT) — **C**

*(rebaixado de B em 2026-07-06)*

**Status: Aberto** — rendimento decrescente para o porte atual: 11
classes (~3,8 mil linhas), razão teste:código ≈ 1,5:1 e pipeline já
com Checkstyle, PMD, SpotBugs, JaCoCo 85%, OWASP dependency-check e
ArchUnit. Reavaliar apenas se surgirem defeitos que os gates atuais
não capturam.

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
- **[Aberto — condicionado ao Maven Central]** adotar `revapi` ou
  `japicmp` no CI para detectar quebras acidentais entre patches
  (só se justifica com consumidores externos; ver `plano.md`);
- **[Aberto]** configurar `dependabot.yml` ou Renovate específico
  para o repo;
- **[Concluído]** habilitar `--release 21` no `maven-compiler-plugin`
  (não apenas `source`/`target`) — implementado via
  `<maven.compiler.release>` no `pom.xml`.
