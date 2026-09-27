# Be Safe Patch Manager

MVP centralizado de Patch Management para Windows e Linux.

> **Status:** experimental / MVP. Teste primeiro em laboratório e use rings de implantação antes de produção.

## Recursos

- inventário de endpoints;
- scan de updates pendentes;
- dashboard de compliance;
- campanhas por SO, tag e percentual de ring;
- agendamento (`not_before`);
- instalação de patches;
- reboot opcional e adiado;
- logs de execução e auditoria;
- autenticação separada para administrador, enrollment e agentes;
- token individual por endpoint após enrollment;
- agente sem execução de shell arbitrário remoto.

## Arquitetura

```text
                +----------------------+
                |   Dashboard / API    |
                | FastAPI + SQLite     |
                +----------+-----------+
                           |
              HTTPS + token por agente
                           |
        +------------------+------------------+
        |                                     |
+-------+--------+                    +-------+--------+
| Windows Agent |                    |  Linux Agent   |
| WUA COM API   |                    | apt/dnf/yum    |
+----------------+                    +----------------+
```

## 1. Subir o servidor

Pré-requisitos: Docker + Docker Compose.

```bash
cp .env.example .env
```

Gere dois tokens fortes, aleatórios e diferentes. Exemplo:

```bash
python3 - <<'PY'
import secrets
print("ADMIN_TOKEN=" + secrets.token_urlsafe(48))
print("ENROLLMENT_TOKEN=" + secrets.token_urlsafe(48))
PY
```

Copie os valores para `.env` e então:

```bash
docker compose up -d --build
docker compose ps
```

O servidor **recusa iniciar** se os tokens estiverem ausentes, tiverem menos de 32 caracteres, ainda parecerem placeholders ou forem iguais.

Dashboard local:

```text
http://IP-DO-SERVIDOR:8080
```

Em produção, use reverse proxy com HTTPS e não exponha a API administrativa diretamente à Internet.

## 2. Instalar agente Linux

O agente precisa rodar como root porque o gerenciador de pacotes exige privilégio.

No diretório raiz do projeto:

```bash
sudo ./deploy/install-linux.sh https://patch.seudominio.local piloto
```

O instalador solicitará o `ENROLLMENT_TOKEN` sem ecoar o valor no terminal. Para provisionamento automatizado, também é possível fornecer `PATCH_ENROLLMENT_TOKEN` por um mecanismo seguro de secrets do ambiente de automação.

Após o primeiro enrollment bem-sucedido, o agente remove o token compartilhado de enrollment do arquivo `/etc/patch-manager/agent.json` e mantém somente sua credencial individual.

Status:

```bash
systemctl status patch-manager-agent
journalctl -u patch-manager-agent -f
```

## 3. Instalar agente Windows

Pré-requisitos: Python 3 instalado e PowerShell executado como Administrador.

A partir da pasta do projeto:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\deploy\windows\install-agent.ps1 `
  -ServerUrl "https://patch.seudominio.local" `
  -Tags @("piloto")
```

O instalador solicitará o token de enrollment como `SecureString`. O `agent.json` recebe ACL restritiva para `SYSTEM` e o grupo interno de Administradores. Após o enrollment, o token compartilhado é removido do arquivo.

O instalador cria a tarefa agendada `PatchManagerAgent` executada como `SYSTEM`.

## 4. Operação

Abra o dashboard, informe o `ADMIN_TOKEN` e clique em **Entrar**. O token fica somente em memória na página e não é persistido em `localStorage` ou `sessionStorage`; recarregar a página exige autenticação novamente.

Cada agente fará:

1. enrollment inicial;
2. remoção local do token compartilhado de enrollment;
3. scan periódico;
4. heartbeat com inventário e updates;
5. polling de jobs;
6. execução apenas de `scan_updates` ou `install_updates`;
7. envio de resultado e novo scan pós-patch.

### Rings

O campo `ring_percent` seleciona uma parcela determinística dos endpoints que também atendam aos filtros de SO/tag.

Exemplo recomendado:

- campanha 1: tag `lab`, 100%;
- campanha 2: tag `piloto`, 100%;
- campanha 3: tag `prod`, 10%;
- campanha 4: tag `prod`, 30%;
- campanha 5: tag `prod`, 100%.

No MVP cada campanha é independente. Promoção automática entre rings pode ser adicionada posteriormente com health gates.

## 5. Pacotes específicos

Se o campo **Pacotes/KBs** ficar vazio, o agente instala os updates disponíveis do SO.

Windows aceita somente identificadores no formato `KB1234567`. Linux aceita somente nomes de pacote que passem pela whitelist de caracteres do agente.

Isso é proposital: a API não aceita comandos remotos arbitrários.

## 6. Windows

O agente usa a API nativa Windows Update Agent via COM (`Microsoft.Update.Session`). Ele procura software não instalado e não oculto, baixa e instala as atualizações selecionadas.

O reboot nunca acontece antes de o resultado ser produzido. Quando permitido e necessário, ele é agendado para aproximadamente dois minutos depois.

## 7. Linux

Suportado no MVP:

- Debian/Ubuntu: `apt-get`;
- Fedora/RHEL e derivados: `dnf`;
- sistemas legados compatíveis: `yum`.

Sem lista de pacotes, a campanha atualiza os pacotes disponíveis. Com lista, limita a atualização aos pacotes indicados.

## 8. API administrativa

Todas as rotas `/api/admin/*` exigem:

```text
X-Admin-Token: <ADMIN_TOKEN>
```

Exemplo:

```bash
curl -H "X-Admin-Token: $ADMIN_TOKEN" http://localhost:8080/api/admin/summary
```

## 9. Segurança

Controles já presentes no MVP:

- ausência de endpoint de shell remoto arbitrário;
- tokens administrativos/enrollment obrigatórios e distintos;
- credencial individual por agente;
- token de enrollment descartado após o primeiro registro;
- lista restrita de ações aceitas pelo agente;
- validação de nomes de pacotes/KBs;
- configuração do agente Linux com modo `0600`;
- ACL restritiva do `agent.json` no Windows;
- token administrativo não persistido pelo dashboard;
- `.gitignore` cobrindo secrets, chaves, certificados, bancos e logs.

Para produção, ainda são recomendados:

- TLS obrigatório;
- firewall/ACL limitando a API administrativa;
- rotação e revogação de tokens;
- PostgreSQL;
- SSO/RBAC para operadores;
- assinatura dos binários/agentes;
- assinatura de políticas/campanhas;
- rate limiting;
- mTLS para agentes;
- backup e recuperação do banco;
- integração com SIEM/ITSM;
- code signing no agente Windows;
- health gates antes de promover rings.

Leia também [`SECURITY.md`](SECURITY.md).

## 10. Antes de publicar no GitHub

Execute o check incluído no repositório e confirme o status do Git:

```bash
python3 scripts/pre-publish-check.py
git status --short
```

O workflow de CI executa esse check novamente em pushes e pull requests.

Nunca publique um `.env` real nem o `agent.json` de um endpoint já registrado.

## 11. Estrutura

```text
be-safe-patch-manager/
├── docker-compose.yml
├── .env.example
├── .gitignore
├── LICENSE
├── SECURITY.md
├── CHANGELOG.md
├── .github/workflows/ci.yml
├── scripts/pre-publish-check.py
├── README.md
├── server/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py
│       ├── database.py
│       ├── models.py
│       ├── schemas.py
│       ├── security.py
│       └── static/
│           ├── index.html
│           ├── style.css
│           └── app.js
├── agent/
│   ├── patch_agent.py
│   ├── requirements.txt
│   └── config.example.json
└── deploy/
    ├── install-linux.sh
    ├── systemd/patch-manager-agent.service
    └── windows/install-agent.ps1
```

## 12. Próximas evoluções

A arquitetura separa backend e agente para permitir integrações futuras com scanners de vulnerabilidade, SIEM, monitoramento, SOAR e ITSM, além de CVE → patch, health checks, aprovação, SLA, exceções com validade e relatórios de evidência por campanha.

## Licença

Apache License 2.0. Veja [`LICENSE`](LICENSE).
