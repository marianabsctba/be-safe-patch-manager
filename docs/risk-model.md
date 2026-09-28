# Be Safe Risk Model

Este documento descreve o modelo de risco implementado no Be Safe Patch Manager v0.18.

O objetivo não é substituir CVSS, EPSS, CISA KEV ou a evidência do scanner. O modelo usa esses sinais como entradas para priorização operacional e mantém cada fonte separada e auditável.

## Camadas

O modelo possui quatro camadas independentes:

1. **Finding Detection Risk** — risco contextual de uma vulnerabilidade individual, em escala de 1 a 100.
2. **Asset Context** — criticidade, exposição e controles compensatórios do endpoint.
3. **Be Safe Asset Risk** — risco agregado do ativo, em escala de 0 a 1000.
4. **Remediation Priority** — combina Asset/Finding Risk com SLA e elegibilidade de campanha.

Nenhum desses scores marca uma vulnerabilidade como remediada. O fechamento continua dependendo da evidência pós-patch e do rescan.

## 1. Finding Detection Risk

Escala: **1–100**.

Fórmula implementada:

```text
Finding Risk =
    CVSS * 6
  + EPSS * 20
  + 15 se CISA KEV
  + 10 se houver uso conhecido por ransomware
  + idade
```

A idade adiciona até 10 pontos:

```text
age_points = min(10, age_days / 9)
```

O score final é limitado a 100.

Faixas:

| Score | Nível |
|---:|---|
| 90–100 | critical |
| 70–89.9 | high |
| 40–69.9 | medium |
| 1–39.9 | low |

### Fatores retornados

Cada cálculo retorna os fatores separadamente:

- `cvss`
- `epss`
- `known_exploited`
- `ransomware`
- `age`

Isso permite explicar por que dois findings com o mesmo CVSS podem ter prioridades diferentes.

## 2. Criticidade do ativo

Escala: **1–5**.

A criticidade é derivada das tags conhecidas do endpoint. Quando várias tags possuem valor, prevalece a maior criticidade.

| Tag | Criticidade |
|---|---:|
| tier0 | 5 |
| mission-critical | 5 |
| critical | 5 |
| domain-controller | 5 |
| identity | 5 |
| prod / production | 4 |
| database | 4 |
| internet-facing | 4 |
| public | 4 |
| dmz | 4 |
| staging | 2 |
| dev / development | 1 |
| lab | 1 |

Quando nenhuma tag conhecida está presente, o default é **2**.

A origem da criticidade é retornada como `tags` ou `default`.

## 2.1. Perfil de risco explícito

Além das tags, cada endpoint pode possuir um `AssetRiskProfile` persistente.

O perfil permite definir explicitamente:

- criticidade `1–5`;
- exposição `externo` ou `interno`;
- controles compensatórios;
- motivo da alteração;
- ator responsável;
- data/hora da última atualização.

A precedência é:

```text
perfil explícito > tags > default
```

Campos individuais podem permanecer em modo automático. Isso significa que é possível, por exemplo, fixar somente a criticidade e continuar derivando exposição e controles por tags.

### Semântica de auto

- `criticality = null`: usa tags/default;
- `external = null`: usa tags/default;
- `compensating_controls = null`: usa tags;
- `compensating_controls = []`: override explícito sem controles reconhecidos.

Essa distinção entre `null` e lista vazia é intencional.

### Governança

Somente `admin` pode alterar o perfil.

Toda alteração:

- exige motivo;
- registra o ator;
- gera evento de auditoria `asset_risk.profile.updated`;
- registra estado anterior e posterior;
- recalcula o contexto efetivo;
- cria snapshot de Asset Risk.

Leitura é permitida para `viewer`.

APIs:

```http
GET /api/admin/agents/{agent_id}/risk-profile
PUT /api/admin/agents/{agent_id}/risk-profile
```

Exemplo:

```json
{
  "criticality": 5,
  "external": true,
  "compensating_controls": [
    "segmented",
    "edr-protected"
  ],
  "reason": "Ativo Tier 0 exposto externamente"
}
```

Para devolver um campo ao modo automático, envie `null`.

### Normalização de Threat Intelligence

Valores externos são normalizados antes de entrar no score.

EPSS aceita:

- número entre `0` e `1`;
- string decimal entre `0` e `1`;
- percentual como `90%`.

Valores fora da faixa são ignorados em vez de serem convertidos artificialmente para `0` ou `1`.

Flags booleanas de KEV/ransomware também são interpretadas explicitamente. Strings como `"false"`, `"0"` e `"unknown"` não são consideradas verdadeiras.

### Separação entre criticidade e exposição

Tags de exposição (`internet-facing`, `public`, `dmz`) não aumentam mais a criticidade do ativo.

Elas afetam apenas o componente de exposição.

Isso evita contabilizar o mesmo contexto duas vezes no Asset Risk.

## 3. Exposição

Tags reconhecidas como exposição externa:

- `internet-facing`
- `public`
- `dmz`
- `external`

Ativos externos recebem multiplicador:

```text
external multiplier = 1.2
internal multiplier = 1.0
```

O modelo não infere exposição apenas pelo IP. Isso evita classificar NAT, ranges privados ou topologias incompletas de forma incorreta.

## 4. Controles compensatórios

Controles reconhecidos atualmente:

| Tag | Multiplicador |
|---|---:|
| segmented | 0.90 |
| edr-protected | 0.90 |
| restricted-egress | 0.95 |

Eles são multiplicativos e possuem piso agregado de **0.60**.

Exemplo:

```text
segmented + edr-protected
= 0.90 * 0.90
= 0.81
```

O controle reduz o risco calculado, mas nunca altera o finding original, CVSS, EPSS ou estado do scanner.

## 5. Agregação por severidade

Os findings abertos são agrupados por severidade.

Pesos atuais:

| Severidade | Peso |
|---|---:|
| critical | 2.0 |
| high | 1.5 |
| medium | 1.0 |
| low | 0.5 |
| unknown | 0.5 |

Para cada bucket:

```text
average_detection_risk = média dos Finding Detection Risks
count_factor = count ^ 0.01
bucket_contribution =
    average_detection_risk
    * count_factor
    * severity_weight
```

O expoente baixo evita que quantidade pura domine completamente o risco.

## 6. Be Safe Asset Risk

Escala: **0–1000**.

```text
weighted_findings = soma das contribuições dos buckets

Asset Risk =
    asset_criticality
  * exposure_multiplier
  * weighted_findings
  * compensating_multiplier
```

O resultado é limitado a 1000.

Faixas:

| Score | Nível |
|---:|---|
| 850–1000 | critical |
| 700–849.9 | high |
| 500–699.9 | medium |
| 0–499.9 | low |

## 7. Risk Appetite

Configuração:

```dotenv
ASSET_RISK_APPETITE=700
```

A console mostra:

- quantidade de ativos acima do appetite;
- média de risco dos ativos;
- ativos critical/high;
- ranking decrescente.

O appetite não altera o score. Ele funciona apenas como limite operacional.

## 7.1. Risk Appetite Policies por tag

Além do appetite global, o Be Safe permite políticas específicas por grupo de ativos.

Cada `AssetRiskPolicy` possui:

- nome;
- tag alvo;
- risk appetite `1–1000`;
- prioridade;
- status habilitada/desabilitada;
- motivo;
- criador e último editor;
- timestamps.

Exemplo:

```text
Tier 0
tag: tier0
appetite: 500
priority: 500

Production
tag: prod
appetite: 650
priority: 100

Lab
tag: lab
appetite: 850
priority: 50
```

Se um ativo possuir múltiplas tags com políticas aplicáveis, vence a política habilitada com maior prioridade.

```text
maior priority > menor priority > appetite global
```

Empates de prioridade são resolvidos deterministicamente pelo nome da política.

Se nenhuma política habilitada casar com as tags do ativo, vale:

```dotenv
ASSET_RISK_APPETITE=700
```

A política altera apenas o limite usado para classificar o ativo como `above_risk_appetite`. Ela não altera o score do Asset Risk.

Isso é importante porque dois ativos podem ter o mesmo score e posturas operacionais diferentes.

Exemplo:

```text
DC-01
Asset Risk: 620
policy: Tier 0
appetite: 500
resultado: acima do appetite

LAB-01
Asset Risk: 620
policy: Lab
appetite: 850
resultado: dentro do appetite
```

### APIs

```http
GET  /api/admin/risk-policies
POST /api/admin/risk-policies
PUT  /api/admin/risk-policies/{policy_id}
```

Criação e alteração exigem `admin` e motivo.

Eventos de auditoria:

- `asset_risk.policy.created`
- `asset_risk.policy.updated`

A resposta do relatório de Asset Risk inclui para cada ativo:

- `risk_policy.source`: `policy` ou `global`;
- `risk_policy.policy`: política efetiva quando existir;
- `risk.risk_appetite`;
- `risk.above_risk_appetite`.

## 7.2. Asset Risk Acceptance

Aceitação de risco é uma decisão de governança temporária para um ativo cujo score permanece acima do appetite efetivo.

Ela **não altera o Asset Risk**.

O ativo continua exibindo:

- score original;
- contributors originais;
- policy efetiva;
- appetite efetivo;
- estado `above_risk_appetite = true`.

A aceitação altera somente o estado de governança:

```text
within_appetite
above_appetite
accepted
```

Uma aceitação possui:

- motivo;
- aprovador;
- validade;
- data de criação;
- revogação opcional;
- autor da revogação;
- motivo da revogação.

Regras:

- somente `admin` pode criar ou revogar;
- validade precisa estar no futuro;
- validade máxima: 365 dias;
- só pode existir uma aceitação ativa por ativo;
- expiração é calculada em leitura, sem scheduler;
- aceitação expirada deixa de valer automaticamente;
- revogação é auditada;
- score e evidência permanecem intactos.

APIs:

```http
GET  /api/admin/agents/{agent_id}/risk-acceptances
POST /api/admin/agents/{agent_id}/risk-acceptances
POST /api/admin/agents/{agent_id}/risk-acceptances/{acceptance_id}/revoke
```

Eventos:

- `asset_risk.acceptance.created`
- `asset_risk.acceptance.revoked`

Exemplo operacional:

```text
DC-01
Asset Risk: 780
Appetite efetivo: 500
Governance: accepted
Aceite válido até: 2026-10-27
Motivo: migração do sistema legado em andamento
```

O risco continua sendo 780. O sistema apenas registra que a organização decidiu aceitar temporariamente esse risco.

## 7.3. Risk Treatment Plan

Treatment Plan representa a decisão de **reduzir ou remover o risco**, diferente de aceitá-lo temporariamente.

Um plano possui:

- owner;
- ação planejada;
- prazo;
- status;
- criador e último editor;
- evidência de conclusão;
- data de conclusão.

Status suportados:

```text
planned
in_progress
completed
cancelled
```

Enquanto o ativo estiver acima do appetite e possuir plano ativo, o estado de governança é:

```text
in_treatment
```

Se o prazo vencer com status `planned` ou `in_progress`:

```text
treatment_overdue
```

Conclusão exige evidência textual. Um plano concluído não pode ser reaberto.

Somente um plano ativo é permitido por ativo.

APIs:

```http
GET  /api/admin/agents/{agent_id}/risk-treatments
POST /api/admin/agents/{agent_id}/risk-treatments
PUT  /api/admin/agents/{agent_id}/risk-treatments/{treatment_id}
```

Eventos:

- `asset_risk.treatment.created`
- `asset_risk.treatment.updated`

### Tratamento x aceitação

```text
Risk Treatment  -> existe ação para reduzir/remover o risco
Risk Acceptance -> organização aceita temporariamente o risco existente
```

Nenhum dos dois altera artificialmente o Asset Risk.

A precedência de governança para um ativo acima do appetite é:

```text
accepted
treatment_overdue / in_treatment
above_appetite
```

Se houver aceite e plano ativos simultaneamente, o estado principal exibido é `accepted`, mas o plano continua registrado e consultável.

## 7.4. Risk Reduction Simulation

A simulação estima o impacto da remediação de um ou mais findings no Asset Risk sem alterar nenhum dado real.

Entrada:

```json
{
  "finding_ids": ["finding-id-1", "finding-id-2"]
}
```

Endpoint:

```http
POST /api/admin/agents/{agent_id}/risk-simulation
```

A resposta inclui:

- score antes;
- score projetado;
- quantidade de findings antes/depois;
- delta absoluto;
- percentual de redução;
- appetite efetivo;
- indicação de cruzamento abaixo do appetite;
- policy efetiva.

A simulação usa o mesmo `asset_risk_score` da produção. Os findings informados são removidos apenas do conjunto temporário usado no cálculo.

Ela **não**:

- muda status do finding;
- altera evidência;
- cria campanha;
- grava snapshot;
- altera histórico;
- fecha vulnerabilidade.

Exemplo:

```text
score atual: 812
score projetado: 641
redução: 171 (21.1%)
appetite: 700
cruza abaixo do appetite: sim
```

A intenção é apoiar priorização de remediação antes da execução.

## 8. Decomposição do Asset Risk

O endpoint de Asset Risk retorna `decomposition`.

Contributors positivos:

- `findings:critical`
- `findings:high`
- `findings:medium`
- `findings:low`
- `asset_criticality`
- `external_exposure`

Contributor negativo:

- `compensating_controls`

Cada item contém:

- `name`
- `category`
- `raw`
- `percent`

O percentual é calculado sobre os contributors positivos. Controles compensatórios aparecem como redução negativa e não são usados no denominador positivo.

Isso permite respostas como:

```text
Asset Risk: 884

Principais contributors:
- asset_criticality: 39.2%
- findings:critical: 34.8%
- external_exposure: 16.4%
- findings:high: 9.6%

Risk reduction:
- compensating_controls: -92.3
```

## 9. Top Risk Contributors

O relatório agrega contributors positivos de todos os ativos e retorna os dez maiores em `top_contributors`.

Isso mostra o que mais pressiona o risco global do ambiente, por exemplo:

```text
1. asset_criticality
2. findings:critical
3. external_exposure
4. findings:high
```

A finalidade é apoiar decisões como:

- corrigir vulnerabilidades críticas;
- reduzir exposição;
- rever classificação de ativos;
- implementar controles compensatórios;
- priorizar campanhas por impacto global.

## 10. Histórico e tendência

Snapshots persistentes ficam em `asset_risk_snapshots`.

São criados:

- após sync Greenbone;
- após sync de Threat Intel;
- manualmente pela console.

Snapshots automáticos possuem intervalo mínimo de uma hora para reduzir ruído.

A tendência do score é:

- `up` — risco atual maior que o último snapshot;
- `down` — risco atual menor;
- `flat` — sem alteração;
- `new` — ainda não há baseline.

Exemplo:

```text
Asset Risk 742
Trend ↑ +86.4
Previous 655.6
```

## 11. SLA e Remediation Priority

SLA não faz parte diretamente da fórmula do Asset Risk.

Isso é intencional:

- **Risk** responde "quão perigoso é?"
- **SLA** responde "quanto tempo ainda temos?"
- **Remediation Queue** responde "o que fazer primeiro?"

A fila de remediação combina os dois.

Recomendações possíveis:

- `patch_now`
- `schedule_patch`
- `plan_patch`
- `scan_or_manual_triage`
- `correlate_asset`
- `exception_active`

Uma exceção de SLA não reduz o Asset Risk.

## 12. APIs

### Asset Risk

```http
GET /api/admin/reports/asset-risk
```

### Histórico

```http
GET /api/admin/reports/asset-risk/history
GET /api/admin/reports/asset-risk/history?agent_id=<uuid>
```

### Snapshot manual

```http
POST /api/admin/reports/asset-risk/snapshot
```

Requer `operator` ou `admin`.

### Remediation Queue

```http
GET /api/admin/reports/remediation-queue
```

### SLA

```http
GET /api/admin/reports/vulnerability-sla
```

## 13. Threat Intelligence

O enrichment opcional usa:

- FIRST EPSS;
- CISA Known Exploited Vulnerabilities.

As informações são armazenadas em:

```text
raw.threat_intel
```

O raw do scanner é preservado.

Falha de uma fonte pode resultar em estado `degraded`, mantendo a outra utilizável.

## 14. Princípios de segurança

O modelo segue estas regras:

- ausência de EPSS/KEV não gera valor inventado;
- exposição não é inferida somente por IP;
- controles compensatórios não alteram evidência original;
- score não muda status do finding;
- score não dispara patch automaticamente;
- campanha continua exigindo revisão humana;
- remediação só é comprovada por evidência/rescan;
- mudanças administrativas relevantes permanecem auditáveis.

## 15. Exemplo completo

Ativo:

```text
tags:
  - tier0
  - internet-facing
  - segmented
  - edr-protected
```

Finding:

```text
CVSS: 9.8
EPSS: 0.95
KEV: true
Ransomware: known
Age: 30 days
Severity: critical
```

O finding recebe risco individual alto devido à combinação de severidade técnica, probabilidade, exploração conhecida, ransomware e idade.

O Asset Risk então aplica:

```text
criticality = 5
exposure = 1.2
severity weight = 2.0
compensating controls = 0.81
```

O resultado permanece elevado, mas os controles compensatórios aparecem explicitamente como redução. O operador consegue ver tanto o risco residual quanto os fatores responsáveis por ele.
