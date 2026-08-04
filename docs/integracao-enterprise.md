# Integração enterprise

Este guia complementa o contrato da API do `hubsaude-cliente-java` com
decisões de integração que pertencem à aplicação consumidora. O SDK não
depende de Spring, Resilience4j, Micrometer ou OpenTelemetry.

## Ownership e ciclo de vida

`SmartTokenClient` é thread-safe e deve ser uma instância única por
configuração de credencial. A aplicação é proprietária da instância e
deve fechá-la durante o encerramento:

- aplicações long-lived: registre-a no lifecycle do contêiner;
- CLIs, jobs curtos e testes: use *try-with-resources*;
- não feche a instância após cada token, pois isso descarta conexões e
  cache compartilhados.

Em Spring, declare o método de destruição explicitamente:

```java
@Bean(destroyMethod = "close")
SmartTokenClient hubSaudeTokenClient() throws IOException {
    return SmartTokenClient.builder()
            .tokenEndpoint(tokenEndpoint)
            .clientId(clientId)
            .privateKeyPem(privateKeyPath)
            .certificatePem(certificatePath)
            .build();
}
```

O `close()` é idempotente, aguarda operações em voo, encerra o
`HttpClient` interno e invalida o cache. Chamadas de token posteriores
falham com `IllegalStateException`.

## Composição de resiliência

O SDK repete apenas falhas transitórias de rede, com backoff exponencial.
Respostas HTTP, inclusive `429` e `5xx`, não são repetidas
automaticamente. Um circuit breaker externo deve envolver a operação na
camada de orquestração, sem criar outro retry automático sobre o SDK.

Ao configurar a política:

1. conte `IOException` e `SmartTokenException` como falhas;
2. não converta `InterruptedException` em sucesso nem a absorva — propague
   a interrupção ou restaure `Thread.currentThread().interrupt()`;
3. trate `429` conforme `Retry-After` e a política operacional, fora do
   retry interno;
4. limite qualquer nova tentativa após `401` a uma renovação de token:
   invalide o scope, obtenha um token novo e, se o erro persistir,
   interrompa o fluxo para diagnóstico de credencial/autorização.

## Métricas

Instrumente a fachada da aplicação, não o SDK. Para Prometheus, siga a
ADR-40:

| Finalidade | Nome recomendado |
|------------|------------------|
| Total de solicitações | `hubsaude_<servico>_token_request_total` |
| Duração | `hubsaude_<servico>_token_request_duration_seconds` |
| Falhas | `hubsaude_<servico>_token_error_total` |

Use labels de baixa cardinalidade, como `outcome` e uma categoria fechada
de erro. Não use `scope`, `client_id`, token, trace-id, CPF, CNS ou outro
identificador pessoal como label: scopes livres e identificadores criam
cardinalidade não limitada; tokens e dados pessoais também violam o
contrato de segredo e a LGPD.

Os labels de identidade de serviço e ambiente devem ser `service` e
`env`, conforme ADR-58.

## Trace e diagnóstico

Cada requisição HTTP envia `traceparent` W3C. O trace-id efetivo aparece
em mensagens de erro e logs de retry; informe-o ao suporte para
correlacionar o integrador com a plataforma. Quando o OpenTelemetry Java
Agent instrumenta o `HttpClient`, o agente pode substituir o header pelo
contexto do span ativo.

Nunca registre `access_token`, `client_assertion`, chave privada, senha,
PIN ou o corpo bruto não sanitizado de uma resposta.

## Referências

- [README do SDK](../README.md)
- [Contrato comportamental](../ESPECIFICACAO.md)
- [ADR-40 — naming de métricas](../../../docs/design/adrs/adr-40-naming-metricas-observabilidade.md)
- [ADR-58 — labels canônicos](../../../docs/design/adrs/adr-58-labels-canonicos-observabilidade.md)
- [W3C Trace Context](https://www.w3.org/TR/trace-context/)
