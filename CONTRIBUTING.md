# Como contribuir com hubsaude-cliente-java

Obrigado pelo interesse em contribuir! Este documento descreve o processo
padronizado de contribuição.

## Código de conduta

Toda interação está sujeita ao [Código de Conduta](CODE_OF_CONDUCT.md),
baseado no Contributor Covenant 2.1.

## Licença das contribuições

Ao submeter um Pull Request, você concorda em licenciar sua contribuição
sob a **Apache License 2.0**, a mesma licença deste projeto. Veja
[LICENSE](LICENSE).

## Developer Certificate of Origin (DCO)

Este projeto adota o [Developer Certificate of Origin 1.1](https://developercertificate.org/).
Toda contribuição precisa ter `Signed-off-by:` em cada commit.

Assine automaticamente:

```bash
git commit -s -m "feat: minha alteração"
```

Isso adiciona ao corpo da mensagem:

```
Signed-off-by: Seu Nome <seu@email.com>
```

Esse trailer atesta que você tem direito de submeter o trabalho sob a
licença do projeto, conforme o texto integral do DCO. Commits sem
`Signed-off-by:` serão bloqueados pelo CI.

## Fluxo de contribuição

1. **Issue primeiro**: abra ou comente em uma issue descrevendo o problema
   ou a feature.
2. **Fork e branch**: trabalhe em branch dedicado a partir de `develop`.
   Nome sugerido: `feat/curto-descritivo`, `fix/issue-123`, `docs/...`.
3. **Conventional Commits**:
   - `feat:` nova funcionalidade
   - `fix:` correção de bug
   - `docs:` documentação
   - `refactor:`, `test:`, `chore:`, `perf:`, `build:`, `ci:`
4. **Testes obrigatórios**: toda mudança de comportamento exige teste novo
   ou atualização do existente. Cobertura é monitorada via JaCoCo
   (mínimo de 85% no `hubsaude-cliente-java`).
5. **Build verde** localmente antes de abrir PR:
   ```bash
   cd hubsaude/projetos/hubsaude-cliente-java && mvn verify
   ```
   O projeto não participa de um POM agregador na raiz do repositório —
   o build deve ser executado dentro do diretório do projeto.
   Opcionalmente, execute também os perfis do `pom.xml`:
   `mvn verify -Pquality` (Checkstyle, PMD, SpotBugs, JaCoCo) e
   `mvn verify -Psecurity` (OWASP Dependency-Check).
6. **PR pequeno e focado**: prefira PRs de até ~400 linhas modificadas.
7. **Descrição do PR**: explique *o quê*, *por quê* e *como testar*.
   Referencie issues com `Closes #123`.

## Padrões técnicos

- **Java 21** (LTS). Build com **Maven 3.9+**.
- **Linhas**: preferencialmente curtas, máximo de 120 caracteres
  conforme o Checkstyle central.
- **JavaDoc** em pt-BR para a API pública.
- **Sem `System.out.println`**: use SLF4J.
- **Imutabilidade** preferida (records, `final`, coleções imutáveis).
- **ArchUnit** (`ClientArchRules` em
  `src/test/java/.../client/archrules/`) — regras arquiteturais são
  bloqueantes. As regras são mantidas localmente para preservar a
  independência total do cliente (sem dependência do monorepo
  HubSaúde).

## Política de versionamento

[Semantic Versioning 2.0.0](https://semver.org/lang/pt-BR/):

- durante a série `0.x`, **MINOR** pode incluir mudanças incompatíveis e
  **PATCH** preserva compatibilidade;
- a partir de `1.0.0`, **MAJOR** indica quebra na API pública, **MINOR**
  adiciona funcionalidade compatível e **PATCH** contém correções compatíveis.

Apenas a MAJOR mais recente recebe correções de segurança
(ver [SECURITY.md](SECURITY.md)).

## Política de segurança

Vulnerabilidades **não** devem ser reportadas como issues públicas. Veja
[SECURITY.md](SECURITY.md) para o canal apropriado.

## Dúvidas

Abra uma [Discussion](https://github.com/sesgo-ti/hubsaude-cliente-java/discussions)
ou contate os mantenedores via issue.
