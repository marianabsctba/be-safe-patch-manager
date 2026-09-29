#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import http.server
import socketserver
import threading
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = ROOT / "server" / "app"
OUT = ROOT / "docs" / "screenshots"
OUT.mkdir(parents=True, exist_ok=True)

PORT = 8765


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


@contextlib.contextmanager
def static_server():
    handler = lambda *args, **kwargs: QuietHandler(*args, directory=str(APP_ROOT), **kwargs)
    with socketserver.TCPServer(("127.0.0.1", PORT), handler) as httpd:
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            yield
        finally:
            httpd.shutdown()
            thread.join(timeout=5)


def base_state(page):
    page.evaluate("""
      () => {
        state.sessionToken = "readme-demo";
        state.user = {username: "admin", role: "admin"};
        document.querySelector("#loginGate").hidden = true;
        document.querySelector("#authUser").hidden = false;
        document.querySelector("#authUsername").textContent = "admin";
        document.querySelector("#authRole").textContent = "ADMIN";
        document.querySelectorAll("[data-min-role]").forEach((element) => { element.hidden = false; });
        document.querySelector("#lastUpdate").textContent = "Atualizado agora";
      }
    """)


def capture_overview(page):
    page.evaluate("""
      () => {
        setView("overview");
        const q = (s) => document.querySelector(s);
        q("#summary").innerHTML = [
          ["Endpoints","148","141 online","neutral"],
          ["Compliance","86%","127 compliant","accent"],
          ["Updates pendentes","63","itens detectados","warn"],
          ["Críticos","11","prioridade alta","danger"],
          ["Reboot pendente","9","endpoints","warn"],
          ["Acima do apetite","17","ativos","danger"]
        ].map(([l,v,h,c]) => '<article class="card '+c+'"><span>'+l+'</span><strong>'+v+'</strong><small>'+h+'</small></article>').join("");

        q("#complianceLabel").textContent = "86%";
        q("#complianceValue").textContent = "86%";
        q("#complianceRing").style.setProperty("--pct", 86);
        q("#healthCompliant").textContent = "127";
        q("#healthPending").textContent = "21";
        q("#healthCritical").textContent = "11";
        q("#healthReboot").textContent = "9";

        q("#riskEndpoints").innerHTML = [
          ["erp-prd-01","Windows Server 2022 · Tier0 · 5 findings","Crítico","fail"],
          ["sql-fin-02","Windows Server 2019 · prod · 4 findings","Crítico","fail"],
          ["api-linux-07","Ubuntu 24.04 · external · 7 findings","Atenção","warn"],
          ["ws-fin-044","Windows 11 · finance · reboot pending","Atenção","warn"]
        ].map(([n,d,b,c]) => '<div class="risk-item"><div><strong>'+n+'</strong><small>'+d+'</small></div><span class="badge '+c+'">'+b+'</span></div>').join("");

        q("#riskProgramOverview").innerHTML =
          '<div class="integration-details">'+
          [
            ["Acima do appetite","17","6 sem ação"],
            ["Threat-active assets","12","5 exposições externas"],
            ["Owner coverage","93%","2 critical/high sem owner"],
            ["MTTR mediano","18.4h","first_seen → resolved"],
            ["Evidência verificada","96%","ciclos terminais"],
            ["Patch success","98.7%","jobs concluídos"],
            ["Goals at risk","2","1 overdue"],
            ["Remediation groups","8","31 findings cobertos"]
          ].map(([l,v,h]) => '<div><span>'+l+'</span><strong>'+v+'</strong><small class="muted">'+h+'</small></div>').join("")+
          '</div>';

        q("#riskGoalStats").innerHTML = [
          ["Ativas","4"],["Atingidas","1"],["On track","2"],["At risk","1"],["Overdue","0"]
        ].map(([l,v]) => '<div><span>'+l+'</span><strong>'+v+'</strong></div>').join("");

        q("#riskGoalTable").innerHTML =
          '<tr><td>Reduzir Tier0</td><td>tag:tier0</td><td>925 → 702 → 600</td><td>69%</td><td><span class="badge ok">ON TRACK</span></td><td>Infra Core</td><td>15/10</td><td></td></tr>'+
          '<tr><td>External exposure</td><td>tag:external</td><td>810 → 745 → 500</td><td>21%</td><td><span class="badge warn">AT RISK</span></td><td>AppSec</td><td>05/10</td><td></td></tr>';

        q("#overviewCampaigns").innerHTML =
          '<article class="campaign"><div class="campaign-head"><div><strong>Windows Setembro - Tier0</strong><small>KB5072198 · 20 endpoints</small></div><span class="badge ok">SOAK</span></div></article>'+
          '<article class="campaign"><div class="campaign-head"><div><strong>Ubuntu external - OpenSSL</strong><small>USN-7081-1 · 38 endpoints</small></div><span class="badge warn">PAUSE</span></div></article>';
      }
    """)
    page.locator('[data-view-panel="overview"]').scroll_into_view_if_needed()
    page.screenshot(path=str(OUT / "01-dashboard-overview.png"), full_page=False)


def capture_risk(page):
    page.evaluate("""
      () => {
        setView("vulnerabilities");
        const q = (s) => document.querySelector(s);

        q("#threatIntelStatusBadge").textContent = "ativo";
        q("#threatIntelStatusBadge").className = "metric-pill";
        q("#threatIntelDetails").innerHTML =
          '<div><span>CISA KEV</span><strong>9 CVEs</strong></div>'+
          '<div><span>FIRST EPSS</span><strong>sincronizado</strong></div>'+
          '<div><span>Última atualização</span><strong>há 7 min</strong></div>';

        q("#vulnerabilitySummary").innerHTML = [
          ["Abertas","46","findings","neutral"],
          ["Críticas","14","prioridade alta","danger"],
          ["SLA vencido","7","findings","danger"],
          ["KEV ativos","9","12 ativos","accent"],
          ["Asset Risk médio","524","0–1000","neutral"],
          ["Acima do appetite","17","ativos","warn"]
        ].map(([l,v,h,c]) => '<article class="card '+c+'"><span>'+l+'</span><strong>'+v+'</strong><small>'+h+'</small></article>').join("");

        q("#activeThreatStats").innerHTML =
          '<div><span>CVEs com sinal</span><strong>9</strong></div>'+
          '<div><span>Ativos afetados</span><strong>12</strong></div>'+
          '<div><span>Exposição externa</span><strong>5</strong></div>'+
          '<div><span>Ransomware known</span><strong>3</strong></div>';

        q("#activeThreatTable").innerHTML =
          '<tr><td><strong>CVE-2026-38421</strong></td><td><span class="badge fail">KEV</span> <span class="badge warn">RANSOMWARE</span></td><td>962</td><td>0.94</td><td>4</td><td>6</td><td>KB5072198</td><td>3 external · Tier0</td></tr>'+
          '<tr><td><strong>CVE-2026-29110</strong></td><td><span class="badge fail">KEV</span></td><td>884</td><td>0.87</td><td>3</td><td>3</td><td>USN-7081-1</td><td>2 production</td></tr>'+
          '<tr><td><strong>CVE-2026-41007</strong></td><td><span class="badge info">EPSS HIGH</span></td><td>731</td><td>0.79</td><td>5</td><td>8</td><td>KB5074021</td><td>finance</td></tr>';

        q("#autoPatchStats").innerHTML =
          '<div><span>READY</span><strong>6</strong></div>'+
          '<div><span>HOLD</span><strong>3</strong></div>'+
          '<div><span>BLOCKED</span><strong>2</strong></div>'+
          '<div><span>Drafts criados</span><strong>4</strong></div>';

        q("#freezeWindowStats").innerHTML =
          '<div><span>Ativas agora</span><strong>1</strong></div>'+
          '<div><span>Agendadas</span><strong>2</strong></div>'+
          '<div><span>Overrides</span><strong>0</strong></div>';

        q("#freezeWindowTable").innerHTML =
          '<tr><td>Fechamento financeiro</td><td><span class="badge fail">ATIVA</span></td><td>Windows</td><td>finance</td><td>29/09 06:00 → 23:00</td><td>blackout operacional</td><td></td></tr>';
      }
    """)
    page.locator("#activeThreatTable").scroll_into_view_if_needed()
    page.screenshot(path=str(OUT / "02-risk-workbench.png"), full_page=False)


def capture_campaigns(page):
    page.evaluate("""
      () => {
        setView("campaigns");
        const q = (s) => document.querySelector(s);

        q("#patchGuardStats").innerHTML =
          '<div><span>Regras ativas</span><strong>2</strong></div>'+
          '<div><span>Bloqueios nas últimas 24h</span><strong>3</strong></div>';

        q("#patchGuardTable").innerHTML =
          '<tr><td>Regressão spooler</td><td>KB5068810</td><td>Windows · prod</td><td><span class="badge fail">ATIVO</span></td><td>-</td><td>admin</td><td></td></tr>'+
          '<tr><td>Pacote nginx</td><td>nginx-1.26.2</td><td>Linux · external</td><td><span class="badge warn">ATIVO</span></td><td>02/10</td><td>admin</td><td></td></tr>';

        const f = q("#campaignForm");
        if (f) {
          f.elements.name.value = "Windows Setembro - Tier0";
          f.elements.target_os.value = "windows";
          f.elements.target_tag.value = "tier0";
          f.elements.ring_percent.value = "5";
          f.elements.rollout_plan.value = "5,10,30,100";
          f.elements.soak_minutes.value = "60";
          f.elements.promotion_min_success_rate.value = "95";
          f.elements.promotion_max_success_drop.value = "5";
          f.elements.packages.value = "KB5072198";
          f.elements.description.value = "Rollout governado para ativos críticos";
          f.elements.approval_required.checked = true;
          f.elements.rollback_required.checked = true;
        }

        q("#campaigns").innerHTML =
          '<article class="campaign">'+
            '<div class="campaign-head"><div><strong>Windows Setembro - Tier0</strong><small>KB5072198 · 20 endpoints · plano 5 → 10 → 30 → 100</small></div><span class="badge ok">SOAK</span></div>'+
            '<div class="campaign-meta"><span>ring atual 30%</span><span>success 96%</span><span>regression STABLE</span></div>'+
            '<div class="campaign-actions"><button class="secondary">Preflight</button><button class="secondary">Evidence Pack</button><button class="secondary">Failure Intel</button><button class="secondary">Safe Promotion</button></div>'+
            '<div class="preflight-box">'+
              '<div class="preflight-head"><div><p class="section-kicker">CHANGE READINESS</p><h4>Campaign Preflight</h4></div><div class="preflight-head-actions"><span class="badge warn">REVIEW</span><span class="badge fail">DRIFT DEGRADED</span></div></div>'+
              '<div class="preflight-summary"><span>Checks <strong>9</strong></span><span>Passed <strong>7</strong></span><span>Warnings <strong>2</strong></span><span>Blockers <strong>0</strong></span><span>Ring <strong>1/20</strong></span><span>Último snapshot <strong>07:42</strong></span></div>'+
              '<div class="preflight-drift"><strong>Drift desde o último snapshot</strong><span class="drift-row degraded"><b>Agent freshness</b> PASSED → WARNING · 1 endpoint sem heartbeat recente</span></div>'+
              '<div class="preflight-grid">'+
              '<article class="preflight-check fail"><div class="preflight-check-head"><strong>Local Regression Intelligence</strong><span class="badge fail">BLOCKED</span></div><p>KB5072198 · Windows Server 2022 · 3 falhas / 100% falha efetiva</p><small class="text-danger">Bloqueia deploy</small></article>'+
                '<article class="preflight-check ok"><div class="preflight-check-head"><strong>Target scope</strong><span class="badge ok">PASSED</span></div><p>20 endpoints elegíveis; 1 no ring inicial de 5%</p></article>'+
                '<article class="preflight-check ok"><div class="preflight-check-head"><strong>Approval Gate</strong><span class="badge ok">PASSED</span></div><p>aprovação administrativa atendida</p></article>'+
                '<article class="preflight-check ok"><div class="preflight-check-head"><strong>Patch Guard</strong><span class="badge ok">PASSED</span></div><p>nenhum bloqueio aplicável</p></article>'+
                '<article class="preflight-check warn"><div class="preflight-check-head"><strong>Patch Confidence</strong><span class="badge warn">WARNING</span></div><p>histórico local ainda insuficiente; manter piloto controlado</p></article>'+
              '</div>'+
            '</div>'+
          '</article>'+
          '<article class="campaign"><div class="campaign-head"><div><strong>Ubuntu external - OpenSSL</strong><small>USN-7081-1 · 38 endpoints · health telemetry required</small></div><span class="badge warn">PAUSE</span></div><div class="campaign-meta"><span>ring atual 25%</span><span>success 91%</span><span>regression -9 p.p.</span></div></article>';
      }
    """)
    page.locator("#campaignForm").scroll_into_view_if_needed()
    page.screenshot(path=str(OUT / "03-campaign-governance.png"), full_page=False)


def capture_executions(page):
    page.evaluate("""
      () => {
        setView("executions");
        const q = (s) => document.querySelector(s);
        q("#jobCount").textContent = "137 jobs";
        q("#jobs").innerHTML =
          '<tr><td><strong>erp-prd-01</strong></td><td>Windows Setembro - Tier0</td><td>Instalar updates</td><td><span class="badge ok">Sucesso</span></td><td>07:12</td><td>07:19</td><td><span class="badge ok">Health OK</span></td><td>checkpoint</td><td>-</td></tr>'+
          '<tr><td><strong>sql-fin-02</strong></td><td>Windows Setembro - Tier0</td><td>Instalar updates</td><td><span class="badge ok">Sucesso</span></td><td>07:13</td><td>07:21</td><td><span class="badge ok">Health OK</span></td><td>checkpoint</td><td>-</td></tr>'+
          '<tr><td><strong>api-linux-07</strong></td><td>Ubuntu external - OpenSSL</td><td>Instalar updates</td><td><span class="badge fail">Falha</span></td><td>07:16</td><td>07:24</td><td><span class="badge fail">HTTP CHECK</span></td><td>disponível</td><td>API local /health retornou 503</td></tr>'+
          '<tr><td><strong>web-linux-03</strong></td><td>Ubuntu external - OpenSSL</td><td>Instalar updates</td><td><span class="badge warn">Executando</span></td><td>07:28</td><td>-</td><td>aguardando</td><td>checkpoint</td><td>-</td></tr>'+
          '<tr><td><strong>dc-01</strong></td><td>Windows Setembro - Tier0</td><td>Instalar updates</td><td><span class="badge ok">Sucesso</span></td><td>06:58</td><td>07:09</td><td><span class="badge ok">Health OK</span></td><td>checkpoint</td><td>-</td></tr>'+
          '<tr><td><strong>ws-fin-044</strong></td><td>Finance workstations</td><td>Instalar updates</td><td><span class="badge fail">Bloqueado</span></td><td>-</td><td>-</td><td>-</td><td>-</td><td>Change Freeze ativo</td></tr>';
      }
    """)
    page.locator('[data-view-panel="executions"]').scroll_into_view_if_needed()
    page.screenshot(path=str(OUT / "04-executions-health-gate.png"), full_page=False)


def main():
    with static_server():
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1600, "height": 900})
            page.goto(f"http://127.0.0.1:{PORT}/static/index.html", wait_until="networkidle")
            base_state(page)
            capture_overview(page)
            capture_risk(page)
            capture_campaigns(page)
            capture_executions(page)
            browser.close()


if __name__ == "__main__":
    main()
