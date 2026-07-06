# Plano: Publicação de `hubsaude-cliente-java` no Maven Central

> **Status (2026-05-17): ADIADO.** A publicação do `hubsaude-cliente-java`
> ocorre hoje no **GitHub Packages do monorepo**, conforme os demais
> módulos. Este plano permanece como referência para a migração futura
> ao Maven Central, condicionada à disponibilidade dos pré-requisitos
> administrativos (verificação do namespace `br.gov.go.saude` via DNS
> TXT na zona `saude.go.gov.br` e custodia institucional de chave GPG).
>
> Quando esses pré-requisitos estiverem atendidos, este plano volta a
> ser executável — será necessário reintroduzir no `pom.xml`:
> `<distributionManagement>` apontando para o Central Portal, override
> do `<groupId>` para `br.gov.go.saude`, e re-incluir no perfil
> `release` os plugins `flatten-maven-plugin`, `maven-gpg-plugin` e
> `central-publishing-maven-plugin` (removidos na simplificação de
> 2026-05-17).

> Documento de planejamento operacional. Após a primeira publicação
> bem-sucedida, este arquivo passa a ser histórico — consulte o
> `CHANGELOG.md` para a trilha de releases.

## 1. Contexto e justificativa

`hubsaude-cliente-java` é o artefato público destinado a sistemas de
informação em saúde (públicos e privados) que precisam se autenticar
no HubSaúde via SMART-on-FHIR Backend Services. Diferentemente dos
demais módulos do monorepo — publicados no **GitHub Packages** (que
exige autenticação para consumir) — o cliente Java deve ser publicado
no **Maven Central** para zero-friction de adoção: nenhum
`settings.xml` extra, nenhum PAT, nenhum servidor configurado.

A publicação será feita via **Sonatype Central Portal** (sucessor do
OSSRH), usando o `central-publishing-maven-plugin` já configurado no
perfil `release` do `pom.xml`.

## 2. Pré-condições (one-time setup)

Itens que precisam ser feitos **uma única vez**, antes do primeiro
release. São tarefas fora do código (administrativas/operacionais).

### 2.1 Conta e namespace no Central Portal

- [ ] Criar conta institucional em https://central.sonatype.com
      (preferencialmente vinculada a e-mail do domínio
      `saude.go.gov.br` para facilitar verificação de namespace).
- [ ] Solicitar o namespace `br.gov.go.saude`. A verificação pode
      ocorrer por dois caminhos:
      - **DNS TXT** na zona `saude.go.gov.br` (recomendado): o Portal
        gera um código aleatório; o operador da SES-GO adiciona como
        registro TXT na raiz; o Portal valida automaticamente.
      - Alternativa: namespace `io.github.fabricadesoftwareinf`
        (auto-verificado pelo GitHub), mas obriga renomear o
        `groupId` do artefato — **descartado** porque rompe a
        identidade institucional.
- [ ] Gerar **User Token** no Portal (Account → Generate User Token).
      Esse token é usado como `username`/`password` para upload.

### 2.2 Chave GPG de assinatura

Maven Central exige que todos os artefatos (`jar`, `sources.jar`,
`javadoc.jar`, `pom`, `cyclonedx.json`) sejam assinados com GPG.

- [ ] Gerar par de chaves GPG dedicado para releases:
      ```bash
      gpg --full-generate-key       # ed25519 ou RSA 4096; expiração 2 anos
      ```
      Usar e-mail institucional (ex.: `releases@saude.go.gov.br`)
      como UID principal.
- [ ] Publicar a **chave pública** em keyservers públicos:
      ```bash
      gpg --send-keys KEYID \
          --keyserver hkps://keys.openpgp.org
      gpg --send-keys KEYID \
          --keyserver hkps://keyserver.ubuntu.com
      ```
- [ ] Exportar a **chave privada** em formato ASCII-armored:
      ```bash
      gpg --armor --export-secret-keys KEYID > release-key.asc
      ```
- [ ] Anotar a **passphrase** em local seguro (gerente de senhas
      institucional). Esta passphrase é independente das senhas
      pessoais dos desenvolvedores.
- [ ] Guardar a chave privada original em local seguro (offline,
      cofre digital institucional). **Nunca** versionar.

### 2.3 Secrets no repositório GitHub

Configurar em `Settings → Secrets and variables → Actions`:

| Secret               | Origem                                              |
| -------------------- | --------------------------------------------------- |
| `CENTRAL_USERNAME`   | User Token (item 2.1)                               |
| `CENTRAL_PASSWORD`   | User Token (item 2.1, par do username)              |
| `GPG_PRIVATE_KEY`    | Conteúdo do `release-key.asc` (item 2.2)            |
| `GPG_PASSPHRASE`     | Passphrase definida em 2.2                          |

- [ ] Restringir o acesso aos secrets ao branch protegido (`main`)
      e à environment `release` (a criar) com revisão obrigatória.

### 2.4 Validação local da configuração (dry-run)

Antes do primeiro tag, validar localmente que o perfil `release`
funciona ponta-a-ponta **sem** chamar deploy:

- [ ] Em uma máquina com GPG instalado e a chave 2.2 importada:
      ```powershell
      cd hubsaude\projetos\hubsaude-cliente-java
      mvn -B -ntp clean verify -P release `
          -Dgpg.keyname=KEYID `
          -Dgpg.passphrase=PASSPHRASE
      ```
- [ ] Conferir em `target/`:
      - `hubsaude-cliente-java-X.Y.Z.jar`
      - `hubsaude-cliente-java-X.Y.Z.pom`
      - `hubsaude-cliente-java-X.Y.Z-sources.jar`
      - `hubsaude-cliente-java-X.Y.Z-javadoc.jar`
      - `hubsaude-cliente-java-X.Y.Z-cyclonedx.json`
      - Para cada um dos acima, um `.asc` correspondente.
- [ ] Validar uma assinatura aleatória:
      `gpg --verify target\hubsaude-cliente-java-X.Y.Z.jar.asc target\hubsaude-cliente-java-X.Y.Z.jar`

## 3. Pré-condições no código

Itens que dependem de mudanças no repositório.

### 3.1 Verificar metadados obrigatórios no `pom.xml`

O Central rejeita o upload se faltar qualquer um destes campos.
Conferência rápida (já existem hoje no POM, mas revisar antes do
release):

- [x] `<name>`, `<description>`, `<url>` preenchidos
- [x] `<licenses>` com pelo menos uma licença e `<url>`
- [x] `<developers>` com pelo menos um entry (`name`, `url`)
- [x] `<scm>` com `<connection>`, `<developerConnection>`, `<url>`
- [x] `<organization>` (boa prática)
- [x] `<issueManagement>` (boa prática)

### 3.2 Workflow de release

- [x] `.github/workflows/hubsaude-cliente-java-release.yml` criado
      (disparado por tag `cliente-java-v*.*.*`).
- [ ] **Smoke test do workflow:** disparar uma vez via
      `workflow_dispatch` com `version=0.1.3-test` apenas para
      validar setup de credenciais/GPG sem promover a release
      pública. **Cancelar/expirar** o release no Portal após
      validação (estado `validated` sem `publish`).
- [ ] (Futuro) Criar GitHub Environment `maven-central-release`
      com revisor obrigatório e mover os secrets para essa
      environment.

### 3.3 Garantir que dependências do HubSaúde estejam publicadas

> Atualizado em 2026-07-06 (issue #737): as dependências
> `hubsaude-core` e `hubsaude-arch-rules`, citadas na versão
> original deste plano, foram removidas do POM na simplificação de
> 2026-05-17 (desacoplamento do monorepo).

`hubsaude-cliente-java` declara hoje uma única dependência interna:

- `br.gov.go.saude.hubsaude:hubsaude-simulador` (test scope)

Maven Central **rejeita** artefatos cujas dependências `compile`/
`runtime` não estejam no Central. Como a dependência acima é
`test`, **não bloqueia** o upload. Mas é importante garantir que:

- [ ] O `flatten-maven-plugin` (modo `oss`) está removendo
      corretamente o `<parent>` interno e resolvendo `${revision}`.
      Validar inspecionando `target/.flattened-pom.xml` após o
      dry-run de 2.4.
- [ ] Confirmar que nenhuma dependência `compile`/`runtime` aponta
      para `br.gov.go.saude.hubsaude:*` (groupId interno). Comando:
      ```powershell
      mvn dependency:list -DexcludeScope=test | Select-String "br.gov.go.saude"
      ```
      Esperado: apenas `br.gov.go.saude:hubsaude-cliente-java`
      (o próprio artefato).

## 4. Execução do primeiro release

Sequência exata para promover `0.1.3` (ou versão vigente):

1. [ ] **Confirmar baseline verde:**
       - Último run de `hubsaude-cliente-java-tests.yml` em `main`
         com status `success`.
       - `mvn -P release verify` local (item 2.4) sem erros.
2. [ ] **Atualizar `CHANGELOG.md`** com a seção da versão (data,
       breaking changes, novos recursos, fixes).
3. [ ] **Bump de versão** se necessário (`mvn versions:set
       -DnewVersion=0.1.3 -DgenerateBackupPoms=false`) e commit/PR.
4. [ ] **Merge para `main`** após review.
5. [ ] **Criar e enviar tag**:
       ```bash
       git checkout main && git pull
       git tag -s cliente-java-v0.1.3 \
               -m "Release hubsaude-cliente-java 0.1.3"
       git push origin cliente-java-v0.1.3
       ```
       A tag deve ser **anotada e assinada** (`-s`) com a chave GPG
       do desenvolvedor (não a chave de release).
6. [ ] **Monitorar o workflow** `hubsaude-cliente-java-release` em
       Actions. Em sucesso: ~5–8 min até `BUILD SUCCESS`.
7. [ ] **Promover o release no Portal:**
       - Acessar https://central.sonatype.com → Deployments
       - Localizar o deployment em estado `VALIDATED`
       - Clicar **Publish**
       - Aguardar propagação (10–30 min) para
         `https://repo.maven.apache.org/maven2/br/gov/go/saude/hubsaude-cliente-java/0.1.3/`
8. [ ] **Verificação final** (consumidor):
       ```powershell
       cd $env:TEMP; mkdir test-central; cd test-central
       mvn archetype:generate -DgroupId=test -DartifactId=test `
           -DarchetypeArtifactId=maven-archetype-quickstart `
           -DinteractiveMode=false
       cd test
       # Adicionar dependência ao pom.xml e rodar:
       mvn dependency:get `
           -Dartifact=br.gov.go.saude:hubsaude-cliente-java:0.1.3
       ```
       Resolve sem servidor extra configurado → ✅.

## 5. Atualização do `README.md`

Após sucesso da etapa 4, atualizar o `README.md` para refletir que
o artefato está disponível no Maven Central:

### 5.1 Badge da versão

- [ ] Substituir o badge atual (linha 5):
      ```
      [![Version](https://img.shields.io/badge/Version-0.1.0--SNAPSHOT-yellow)]
      ```
      por badge dinâmico que reflete a última versão publicada:
      ```
      [![Maven Central](https://img.shields.io/maven-central/v/br.gov.go.saude/hubsaude-cliente-java?logo=apachemaven&label=Maven%20Central)](https://central.sonatype.com/artifact/br.gov.go.saude/hubsaude-cliente-java)
      ```
- [ ] Adicionar badge de assinatura/SBOM:
      ```
      [![SBOM](https://img.shields.io/badge/SBOM-CycloneDX-success)](#)
      [![Signed](https://img.shields.io/badge/Artifacts-GPG%20signed-success)](#)
      ```

### 5.2 Seção "Dependência Maven"

> **Atenção (issue #737):** os trechos abaixo usam o groupId
> `br.gov.go.saude`, que é o groupId **futuro**, a ser adotado
> apenas na migração para o Maven Central (ver override citado no
> cabeçalho deste plano). O groupId **atual** do artefato, publicado
> no GitHub Packages, é `br.gov.go.saude.hubsaude`. Não usar os
> snippets abaixo enquanto a migração não ocorrer.

Substituir o bloco atual (linhas 11–25) por algo equivalente a:

```markdown
## Como obter

O `hubsaude-cliente-java` é publicado no **Maven Central**. Não é
necessário configurar repositórios adicionais nem credenciais.

### Maven

\`\`\`xml
<dependency>
    <groupId>br.gov.go.saude</groupId>
    <artifactId>hubsaude-cliente-java</artifactId>
    <version>0.1.3</version>
</dependency>
\`\`\`

### Gradle (Kotlin DSL)

\`\`\`kotlin
implementation("br.gov.go.saude:hubsaude-cliente-java:0.1.3")
\`\`\`

### Gradle (Groovy)

\`\`\`groovy
implementation 'br.gov.go.saude:hubsaude-cliente-java:0.1.3'
\`\`\`

> **Snapshots:** ainda não há workflow que publique builds
> `-SNAPSHOT` automaticamente em `central-snapshots`. Quando esse
> job for criado (push em `develop`), esta seção deve documentar
> o repositório `https://central.sonatype.com/repository/maven-snapshots/`
> e o bloco `<repositories>` correspondente.

### Verificação de integridade

Todos os artefatos são assinados com GPG. A chave pública está em
`keys.openpgp.org` (KEY ID: **TODO-publicar-keyid**). Para verificar:

\`\`\`bash
gpg --recv-keys TODO-KEYID
mvn dependency:get \
    -Dartifact=br.gov.go.saude:hubsaude-cliente-java:0.1.3
gpg --verify ~/.m2/repository/br/gov/go/saude/hubsaude-cliente-java/0.1.3/hubsaude-cliente-java-0.1.3.jar.asc
\`\`\`

O SBOM (CycloneDX 1.5) é anexado como classificador `cyclonedx`:

\`\`\`xml
<dependency>
    <groupId>br.gov.go.saude</groupId>
    <artifactId>hubsaude-cliente-java</artifactId>
    <version>0.1.3</version>
    <classifier>cyclonedx</classifier>
    <type>json</type>
</dependency>
\`\`\`
```

### 5.3 Atualizar `CHANGELOG.md`

- [ ] Trocar versão `0.1.3-SNAPSHOT` por `0.1.3` na entrada do
      changelog e adicionar a data de publicação.
- [ ] Incluir link para o release no GitHub e para o artefato no
      Portal.

## 6. Pós-release: hardening e automação contínua

Itens que podem ser feitos após o primeiro release funcionar.

- [ ] **`autoPublish=true`** no `central-publishing-maven-plugin`
      (bloco `<configuration>` do perfil `release` no `pom.xml`):
      elimina o passo manual de clicar "Publish" no Portal. Ativar
      somente após 2–3 releases bem-sucedidos com publish manual.
- [ ] **GitHub Environment `maven-central-release`** com
      `required_reviewers`: protege os secrets de exposição
      acidental por workflows não-release.
- [ ] **Renovação de chave GPG:** marcar lembrete de renovação
      antes do `expires` (item 2.2). Quando renovar, publicar
      a nova pública nos keyservers e adicionar uma assinatura
      cruzada da antiga sobre a nova.
- [ ] **Documentar política de versionamento** em
      `CONTRIBUTING.md`: semver estrito,
      `0.x → instável (pode quebrar API)`, `≥1.0 → estável`.
- [ ] **Site / Javadoc online:** publicar Javadoc em GitHub Pages
      a partir do `javadoc.jar` gerado (workflow separado).
- [ ] **Smoke test pós-release** (futuro): workflow agendado que,
      ao detectar nova versão no Central, executa um projeto de
      consumo mínimo e reporta sucesso.

## 7. Riscos e mitigações

| Risco                                  | Mitigação                                          |
| -------------------------------------- | -------------------------------------------------- |
| Namespace `br.gov.go.saude` não aprovado | Plano B: usar `io.github.fabricadesoftwareinf`     |
| Chave GPG perdida/comprometida          | Backup offline + chave de revogação pré-gerada     |
| Validação no Portal falha por metadados | Item 3.1; dry-run 2.4 captura antes do tag         |
| `autoPublish=true` libera bug grave    | Manter `false` até pipeline estável; `2–3` releases |
| Tag criada por engano                   | Workflow valida regex `^[0-9]+\.[0-9]+\.[0-9]+(-SNAPSHOT)?$` |
| Dependência interna no Central        | Item 3.3 garante todas `test` antes do release     |

## 8. Definição de pronto (DoD)

Este plano é considerado executado quando:

1. ✅ Artefato `br.gov.go.saude:hubsaude-cliente-java:0.1.3`
   resolvível via `mvn dependency:get` **sem** `settings.xml`.
2. ✅ Assinatura GPG verificável com chave pública em keyserver.
3. ✅ `README.md` reflete o novo método de consumo
   (seção 5 deste plano aplicada).
4. ✅ `CHANGELOG.md` lista a versão como publicada.
5. ✅ Workflow `hubsaude-cliente-java-release.yml` documentado e
   testado em pelo menos um release real.
6. ✅ Secrets institucionais (GPG, Central) sob custódia
   documentada (não na máquina pessoal de um único dev).
