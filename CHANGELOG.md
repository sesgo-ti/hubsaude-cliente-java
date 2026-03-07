# Changelog

Todas as mudanças notáveis neste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/),
e este projeto adere ao [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [Unreleased]

### Adicionado
- Classe `FaultToleranceConfig` para agrupar parâmetros de resiliência
- Testes unitários para `FaultToleranceConfig`
- Arquivo `.gitignore` com exclusões padrão para Java/Maven/IDEs
- Este arquivo CHANGELOG.md

### Alterado
- `SmartTokenClient` refatorado para usar `FaultToleranceConfig`
- `SmartTokenClientBuilder` atualizado para construir `FaultToleranceConfig`
- Documentação do OpenSSL em `problemas.md` clarificada sobre `verify return:1`

## [0.0.0-SNAPSHOT] - 2026-03-07

### Adicionado
- Implementação inicial do cliente SMART Backend Services
- `SmartTokenClient` - classe principal para obtenção de tokens
- `SmartTokenClientBuilder` - builder fluente para configuração
- `SigningStrategy` - interface para estratégias de assinatura
- `PrivateKeySigningStrategy` - implementação padrão com PrivateKey
- `SigningStrategyFactory` - factory para criação de estratégias
- `PemLoader` - utilitário para carregamento de arquivos PEM
- `SslContextFactory` - factory para construção de SSLContext
- Suporte a chaves PEM (PKCS#1, PKCS#8, criptografadas)
- Suporte a HSM via PKCS#11
- Suporte a KeyStore (JKS, PKCS#12)
- Cache de tokens thread-safe
- Retry com backoff exponencial
- Descoberta automática de token_endpoint via .well-known
- Validação de consistência chave-certificado
- TLS 1.3 por padrão
- Documentação completa com exemplos
- Guia de troubleshooting (`problemas.md`)
- Testes unitários com cobertura mínima de 85%
- Testes de integração com simulador

### Segurança
- Senhas tratadas como `char[]` com limpeza de memória
- Tokens sanitizados em logs de erro
- Validação de certificados expirados
- Suporte a trust anchors customizados

---

## Convenções de Versionamento

- **MAJOR**: Mudanças incompatíveis na API pública
- **MINOR**: Novas funcionalidades compatíveis com versões anteriores
- **PATCH**: Correções de bugs compatíveis com versões anteriores

## Links

- [Repositório](https://github.com/FabricaDeSoftwareINF/server-hubsaude)
- [Documentação SMART Backend Services](https://hl7.org/fhir/smart-app-launch/backend-services.html)

