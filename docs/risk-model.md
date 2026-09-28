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

## 7.5. Risk Reduction Opportunities

Além da simulação pontual, o Be Safe calcula oportunidades de redução de risco para findings abertos correlacionados a ativos gerenciados.

Endpoint:

```http
GET /api/admin/reports/risk-reduction-opportunities
```

Para cada finding, a plataforma calcula de forma independente:

- Asset Risk atual;
- Asset Risk projetado sem aquele finding;
- redução absoluta;
- percentual de redução;
- appetite efetivo;
- se a remediação projetada cruza abaixo do appetite;
- risco do finding;
- estado de SLA;
- ação recomendada pela fila de remediação.

O ranking prioriza:

```text
maior redução absoluta
> maior redução percentual
> maior prioridade da recomendação
> maior CVSS
```

Cada linha é uma simulação independente de um único finding.

Por isso, os valores de redução **não são aditivos entre linhas**. Remover dois findings simultaneamente pode produzir um resultado diferente da soma dos deltas individuais, pois o modelo recalcula buckets, médias e multiplicadores sobre o conjunto restante.

Esse relatório é somente leitura e não altera findings, evidência, campanhas, snapshots ou histórico.

## 7.6. Risk Reduction Plan

O Risk Reduction Plan monta uma sequência de remediação por ativo usando ganho marginal recalculado a cada passo.

Endpoint:

```http
GET /api/admin/agents/{agent_id}/risk-reduction-plan?max_steps=25
```

Fluxo:

```text
score atual
-> simula remover cada finding restante
-> escolhe o maior ganho marginal
-> recalcula o score
-> repete sobre o conjunto restante
-> para ao cruzar abaixo do appetite ou atingir max_steps
```

Cada passo retorna:

- finding/CVE;
- ação recomendada;
- score antes;
- score depois;
- redução marginal;
- redução acumulada;
- indicação de cruzamento abaixo do appetite.

A redução acumulada é calculada contra o score inicial do plano, e não pela soma cega de oportunidades independentes.

O algoritmo é **guloso**: escolhe a melhor redução marginal disponível em cada etapa. Ele não afirma encontrar o ótimo global para todas as combinações possíveis de findings.

O plano é somente leitura. Ele não altera:

- status de finding;
- evidência;
- campanha;
- Treatment Plan;
- Risk Acceptance;
- snapshot;
- histórico.

A finalidade é apoiar a ordem operacional de remediação com base no modelo de risco atual.

## 7.7. Campaign Candidate from Risk Reduction Plan

Etapas do Risk Reduction Plan expõem:

- `eligible_for_campaign`;
- referências de patch conhecidas;
- finding de origem;
- ação recomendada.

Quando a etapa é elegível, a console oferece **Preparar campanha**.

Essa ação reutiliza o fluxo normal de campanha e apenas pré-preenche:

- ativo alvo;
- finding de origem;
- nome/descrição;
- sistema operacional;
- ação;
- referências de patch disponíveis.

A campanha continua sendo revisada pelo operador e nasce como `draft`.

Preparar a campanha **não**:

- cria jobs;
- faz deploy;
- avança ring;
- fecha o finding;
- altera evidência;
- altera o Asset Risk.

Deploy permanece uma ação explícita e separada do operador.

## 7.8. Auditable Asset Risk History

Cada snapshot de Asset Risk persiste o contexto necessário para explicar o score histórico sem depender de recálculo futuro.

Além de score, level, criticidade, exposição e findings abertos, o snapshot guarda:

- `model_version`;
- decomposition;
- cálculo intermediário;
- policy efetiva;
- appetite efetivo;
- estado de governança;
- origem do snapshot.

O cálculo persistido inclui:

```text
base_weighted
criticality_multiplier
exposure_multiplier
compensating_multiplier
pre_compensation
raw_score
score_cap
capped
```

Isso permite responder por que determinado ativo tinha um score específico naquele momento, mesmo se tags, policies ou regras evoluírem depois.

A migration correspondente é:

```text
0012_risk_snapshot_details
```

## 7.9. Asset Risk Timeline

A console pode carregar a timeline histórica de um ativo usando:

```http
GET /api/admin/reports/asset-risk/history?agent_id={agent_id}
```

A timeline exibe, por snapshot:

- data/hora;
- score;
- delta contra o snapshot anterior;
- appetite efetivo;
- policy efetiva;
- estado de governança;
- model version;
- origem do snapshot.

O detalhe mais recente também mostra o `raw_score` persistido no cálculo.

Timeline e Risk Reduction Plan são visões somente leitura e estão disponíveis para `viewer`, `operator` e `admin`.

Ações que alteram contexto ou governança continuam restritas ao papel apropriado, como Risk Profile, Treatment Plan e Risk Acceptance.

## 7.10. Asset Accountability

A v0.20 adiciona contexto de responsabilidade ao `AssetRiskProfile`:

- `owner`;
- `business_service`;
- `environment`.

Esses campos são contexto operacional e executivo.

Eles **não alteram diretamente o Asset Risk**. A finalidade é permitir respostas como:

```text
ativo crítico sem owner
ativo de produção sem business service
ativos de um mesmo serviço com risco acima do appetite
```

O relatório de Asset Risk expõe:

- `assets_with_owner`;
- `assets_without_owner`;
- `assets_with_business_service`;
- `critical_high_without_owner`.

Migration:

```text
0013_asset_accountability
```

## 7.11. Remediation Hub

O Remediation Hub agrupa findings abertos pela mesma referência de patch.

Endpoint:

```http
GET /api/admin/reports/remediation-hub
```

Para cada patch reference, o sistema identifica:

- findings cobertos;
- CVEs cobertas;
- ativos afetados;
- sistemas operacionais;
- Asset Risk agregado atual;
- Asset Risk agregado projetado;
- redução projetada;
- quantidade de ativos que cruzariam abaixo do appetite;
- Patch Confidence local, quando disponível.

A matemática evita soma de simulações independentes.

Para cada ativo afetado, o Asset Risk é recalculado removendo **todo o conjunto de findings daquele grupo**. Somente depois os resultados por ativo são agregados.

Isso permite avaliar o impacto de uma ação real de remediação em vez de olhar apenas para CVEs isoladas.

## 7.12. Active Threat Watch

Endpoint:

```http
GET /api/admin/reports/active-threat-watch
```

O Active Threat Watch destaca CVEs abertas quando existe pelo menos um dos sinais:

- presença no CISA KEV;
- ransomware use conhecido;
- EPSS acima do threshold operacional.

O relatório agrupa por CVE e mostra:

- sinais de ameaça;
- maior EPSS;
- maior Detection Risk;
- CVSS máximo;
- findings;
- ativos afetados;
- ativos externos;
- ativos críticos;
- patch references conhecidas.

Essa visão é **signal-based**.

Ela não afirma que o Be Safe mantém um time próprio de threat research nem classifica uma vulnerabilidade como emergent threat por pesquisa independente.

## 7.13. Patch Confidence

Endpoint:

```http
GET /api/admin/reports/patch-confidence
```

Patch Confidence usa o histórico **local** de jobs `install_updates`.

Por patch reference são calculados:

- jobs concluídos;
- sucessos;
- falhas;
- stalled;
- blocked;
- success rate;
- ativos observados;
- campanhas observadas;
- última execução.

Classificação atual:

```text
high
  >= 10 jobs concluídos
  e success rate >= 95%

medium
  >= 5 jobs concluídos
  e success rate >= 80%

low
  >= 5 jobs concluídos
  e success rate < 80%

insufficient_data
  < 5 jobs concluídos
```

Quando uma campanha contém vários packages, o resultado do job é atribuído a cada package do bundle.

Por isso, Patch Confidence deve ser interpretado como **evidência operacional da própria frota**, e não como reliability global fornecida por fabricante.

## 7.14. Business Context Segments

Endpoint:

```http
GET /api/admin/reports/business-context
```

O relatório segmenta os ativos por:

- owner;
- business service;
- environment.

Cada segmento reutiliza o Asset Risk existente e retorna:

- quantidade de ativos;
- risco médio e máximo;
- ativos acima do appetite;
- ativos sem ação;
- governance coverage;
- owner coverage;
- findings abertos.

Nenhum novo multiplicador é aplicado ao score. A segmentação existe para traduzir risco técnico em responsabilidade e contexto de negócio.

## 7.15. Remediation Performance

Endpoint:

```http
GET /api/admin/reports/remediation-performance
```

O relatório usa dados reais do ambiente para medir:

- findings remediados;
- MTTR mediano;
- MTTR médio;
- cumprimento bruto do target de SLA;
- taxa de evidência verificada;
- success rate de jobs `install_updates`;
- duração mediana de patch jobs;
- breaches de SLA ainda abertos;
- MTTR por severidade.

MTTR é calculado de `first_seen` até `resolved_at`.

O campo `raw_sla_target_met_percent` é explicitamente bruto: compara a duração ao target por severidade sem reconstruir pausas históricas de SLA exception.

Isso evita apresentar uma precisão histórica que o modelo ainda não possui.

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

Cada item da decomposition por ativo contém:

- `name`
- `category`
- `raw`
- `percent`

No agregado `top_contributors`, cada contributor também inclui:

- `assets_affected`
- `share_percent`

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

A retenção padrão é de 180 dias e pode ser alterada com:

```text
ASSET_RISK_HISTORY_RETENTION_DAYS
```

Snapshots mais antigos que a retenção são removidos durante novas capturas. Mudanças de Risk Profile, Risk Policy, Risk Acceptance e Treatment Plan geram snapshots imediatos dos ativos afetados para preservar a linha do tempo da governança.

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

A observabilidade separa saúde de freshness:

- `patch_manager_threat_intel_sync_healthy`
- `patch_manager_threat_intel_degraded`
- `patch_manager_threat_intel_stale`
- `patch_manager_threat_intel_age_seconds`

O limite de freshness pode ser configurado por `THREAT_INTEL_STALE_SECONDS`. Assim, um último sync tecnicamente bem-sucedido não permanece verde indefinidamente quando os dados envelhecem.

## 13.1. Integridade da governança

Decisões de Asset Risk são validadas no backend:

- Risk Acceptance exige ativo acima do appetite efetivo;
- Treatment Plan exige ativo acima do appetite efetivo;
- apenas um aceite ativo e um treatment ativo são permitidos por ativo pela lógica transacional;
- criação usa lock do ativo para serializar decisões concorrentes em produção;
- motivos, owners, ações e nomes relevantes são validados após trim;
- mudanças de governança geram audit event e snapshot histórico.

## 13.2. Risk Reduction Goals

O Be Safe trata redução de risco também como programa operacional, não apenas como ranking de findings.

Endpoints:

```http
GET  /api/admin/risk-goals
POST /api/admin/risk-goals
PUT  /api/admin/risk-goals/{goal_id}
```

Cada goal persiste:

- nome;
- owner;
- tipo de métrica;
- tag de escopo opcional;
- baseline congelado no momento da criação;
- target máximo;
- prazo;
- status;
- motivo;
- ator de criação/alteração;
- trilha de auditoria.

Métricas suportadas:

```text
average_asset_risk_max
assets_above_appetite_max
open_findings_max
critical_high_assets_max
```

O escopo vazio representa todos os ativos gerenciados. Quando `scope_tag` é informado, a população é dinâmica: ativos que entram ou saem da tag passam a participar da medição corrente.

O baseline, porém, não é recalculado. Isso preserva a referência histórica da decisão.

### Progresso

Para metas de redução:

```text
progress = (baseline - current) / (baseline - target)
```

limitado a 0–100%.

O sistema também calcula o valor esperado no momento atual por trajetória linear entre criação e prazo.

Estados de pace:

- `on_track`: valor atual igual ou melhor que a trajetória esperada;
- `at_risk`: valor atual pior que o esperado para o tempo transcorrido;
- `overdue`: prazo venceu e target não foi atingido;
- `achieved`: target já foi atingido;
- `completed`: target atingido e goal encerrado formalmente;
- `cancelled`: goal cancelado.

Um goal não pode ser marcado como `completed` enquanto o valor corrente estiver acima do target.

## 13.3. Risk Program Overview

A overview executiva combina métricas já existentes do ambiente, sem criar um score composto oculto:

- ativos acima do appetite;
- backlog acima do appetite sem ação;
- threat-active assets;
- exposição externa;
- owner coverage;
- Critical/High sem owner;
- MTTR mediano;
- taxa de evidência verificada;
- patch job success rate;
- goals em risco ou vencidos;
- grupos do Remediation Hub;
- maior redução potencial do grupo prioritário.

Essa separação é intencional: **Asset Risk continua sendo o score técnico explicável; Program View é uma leitura executiva de métricas observáveis**.

## 13.4. Remediation Projects

Remediation Project é a camada de governança operacional entre uma recomendação de remediação e a execução de uma campanha.

Endpoints:

```http
GET  /api/admin/remediation-projects
POST /api/admin/remediation-projects
PUT  /api/admin/remediation-projects/{project_id}
```

Um projeto persiste:

- patch reference;
- owner;
- prazo;
- status;
- baseline de findings e ativos;
- redução potencial de risco calculada no baseline;
- snapshot do escopo inicial;
- motivo;
- trilha de auditoria.

### Static scope

`static` congela os finding IDs capturados na criação.

Novos findings da mesma patch não entram automaticamente no projeto.

### Dynamic scope

`dynamic` reavalia findings abertos da mesma patch reference e, opcionalmente, da mesma tag.

O projeto expõe separadamente:

- `new_findings_since_baseline`;
- `scope_departures`;
- `baseline_open_findings`;
- `tracked_open_findings`;
- `current_open_findings`.

Finding que continua aberto, mas deixa de casar com a tag dinâmica, aparece como scope departure. Ele **não** é contado como remediado e continua impedindo progresso/conclusão falsos.

### Lifecycle

Estados administrativos:

```text
active
awaiting_verification
completed
cancelled
```

O projeto só pode virar `completed` quando não existem findings rastreados abertos.

Projeto e campanha são objetos diferentes:

```text
Remediation Hub
-> Remediation Project
-> Campaign draft
-> revisão humana
-> deploy
-> health gate / rollback
-> rescan / evidência
```

Criar ou atualizar um projeto não cria jobs, não muda findings e não altera evidência.

### Burndown histórico

A migration `0016_remediation_project_history` adiciona snapshots de progresso por projeto.

Cada snapshot persiste:

- backlog rastreado aberto;
- findings ainda no escopo atual;
- ativos atuais;
- findings fechados desde o baseline;
- novos findings;
- scope departures;
- progresso percentual;
- pace/status;
- origem e timestamp.

Endpoint:

```http
GET /api/admin/remediation-projects/{project_id}/history
```

Capturas administrativas de criação/alteração são imediatas. Capturas automáticas após sync Greenbone e import de vulnerabilities usam intervalo mínimo de uma hora para evitar ruído. Mudanças manuais de status de finding também geram captura imediata.

A timeline permite distinguir **redução real de backlog** de mudanças de população/escopo ao longo do tempo.

### Project Intelligence

A partir da v0.24, Remediation Projects acompanham também a qualidade da remediação, não apenas a contagem de findings.

O projeto calcula:

- `remaining_risk_reduction`: redução de Asset Risk ainda disponível se os findings atuais forem remediados;
- `realized_risk_reduction`: diferença entre a redução potencial do baseline e a redução ainda restante;
- `risk_reduction_progress_percent`;
- `expected_progress_percent`: progresso linear esperado entre criação e prazo;
- `schedule_variance_percent`: progresso real menos progresso esperado;
- findings em CISA KEV;
- findings com SLA vencido, próximo ou em exceção;
- quantidade de ativos externos;
- aging médio e máximo;
- EPSS médio e máximo quando disponível;
- business services e owners envolvidos.

O `attention_status` não é um novo score de risco. É uma classificação operacional explicável:

```text
critical
needs_attention
watch
on_track
```

Exemplos de sinais que elevam atenção:

- projeto vencido;
- SLA vencido;
- KEV em ativo externo;
- atraso relevante contra o progresso esperado;
- novos findings surgindo em escopo dynamic.

A migration `0017_remediation_project_intelligence` persiste esses sinais nos snapshots históricos, permitindo acompanhar backlog e risk burndown separadamente.


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
