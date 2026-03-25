package main

import (
	"encoding/xml"
	"fmt"
	"html/template"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// ── Parser XML Nmap ───────────────────────────────────────────────────────────

type NmapRun struct {
	Hosts []NmapHost `xml:"host"`
}

type NmapHost struct {
	Status struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Address []struct {
		Addr     string `xml:"addr,attr"`
		AddrType string `xml:"addrtype,attr"`
		Vendor   string `xml:"vendor,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
		Type string `xml:"type,attr"`
	} `xml:"hostnames>hostname"`
	Os struct {
		OsMatch []struct {
			Name     string `xml:"name,attr"`
			Accuracy string `xml:"accuracy,attr"`
		} `xml:"osmatch"`
	} `xml:"os"`
	Uptime struct {
		Seconds  string `xml:"seconds,attr"`
		Lastboot string `xml:"lastboot,attr"`
	} `xml:"uptime"`
	Ports []NmapPort `xml:"ports>port"`
}

type NmapPort struct {
	PortId   string `xml:"portid,attr"`
	Protocol string `xml:"protocol,attr"`
	State    struct {
		State  string `xml:"state,attr"`
		Reason string `xml:"reason,attr"`
	} `xml:"state"`
	Service struct {
		Name    string `xml:"name,attr"`
		Product string `xml:"product,attr"`
		Version string `xml:"version,attr"`
	} `xml:"service"`
	Scripts []NmapScript `xml:"script"`
}

type NmapScript struct {
	Id     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

// ── Estruturas para o Template ────────────────────────────────────────────────

type HostRow struct {
	IP        string
	Hostname  string
	Vendor    string
	OS        string
	OSAcc     string
	OpenPorts []OpenPort
	RiskLevel string
	RiskScore int
	Findings  []string
	Lastboot  string
}

type OpenPort struct {
	Port     string
	Protocol string
	Service  string
	Product  string
	Version  string
}

type VulnEntry struct {
	Severity string
	Title    string
	IP       string
	Port     string
	Output   string
}

type ReportData struct {
	Data        string
	Duration    string
	TotalHosts  int
	TotalOpen   int
	RiskLabel   string
	VulnCount   int
	SafeCount   int
	MedCount    int
	Hosts       []HostRow
	Vulns       []VulnEntry
	DonutLabels template.JS
	DonutData   template.JS
	DonutColors template.JS
	BarLabels   template.JS
	BarScores   template.JS
	BarColors   template.JS
}

// ── Template HTML ─────────────────────────────────────────────────────────────

const htmlTmpl = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ZeScan Pro — Auditoria Zebyte</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Helvetica,Arial,sans-serif;background:#f0f2f5;color:#1a1a1a;font-size:14px}
pre{white-space:pre-wrap;word-break:break-word;font-family:inherit}

.wrap{max-width:1100px;margin:0 auto;padding:28px 18px}

.header{background:#fff;border-radius:12px;padding:20px 28px;
  display:flex;justify-content:space-between;align-items:center;
  margin-bottom:20px;border:1px solid #e0e0e0;border-bottom:4px solid #01579b}
.header h1{font-size:20px;font-weight:700;color:#01579b}
.header p{font-size:12px;color:#666;margin-top:4px}
.header img{height:60px}

.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:20px}
.card{background:#f7f8f9;border-radius:10px;padding:16px 18px;border:1px solid #e8e8e8}
.card .lbl{font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px}
.card .val{font-size:26px;font-weight:700;color:#111}
.card .sub{font-size:11px;color:#aaa;margin-top:3px}
.c-red{color:#b83232}.c-amb{color:#9a6800}.c-grn{color:#287048}

.sec{font-size:11px;font-weight:700;color:#888;text-transform:uppercase;
  letter-spacing:.07em;margin:24px 0 10px;padding-bottom:4px;
  border-bottom:1px solid #e8e8e8}

.charts{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:4px}
.cbox{background:#fff;border-radius:10px;border:1px solid #e8e8e8;padding:18px}
.cbox .ct{font-size:11px;font-weight:700;color:#888;text-transform:uppercase;
  letter-spacing:.06em;margin-bottom:14px}
.cwrap{position:relative;height:190px}

.tbl{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;
  overflow:hidden;border:1px solid #e8e8e8}
.tbl th{font-size:11px;font-weight:700;color:#888;text-transform:uppercase;
  letter-spacing:.04em;padding:10px 12px;border-bottom:1px solid #eee;
  text-align:left;background:#fafafa}
.tbl td{padding:10px 12px;border-bottom:1px solid #f2f2f2;font-size:13px;vertical-align:top}
.tbl tr:last-child td{border-bottom:none}
.tbl tr:hover td{background:#fafbff}
.tip{font-size:11px;color:#999;margin-top:2px}

.badge{display:inline-block;padding:2px 9px;border-radius:4px;font-size:11px;font-weight:700}
.b-red{background:#fde8e8;color:#b83232}
.b-amb{background:#fef3d8;color:#9a6800}
.b-grn{background:#e4f5ea;color:#287048}
.b-gry{background:#f0f0f0;color:#666}

.vitem{display:flex;gap:12px;align-items:flex-start;margin-bottom:10px;
  padding:12px 14px;background:#fff;border:1px solid #e8e8e8;border-radius:8px}
.vdot{width:9px;height:9px;border-radius:50%;margin-top:4px;flex-shrink:0}
.dh{background:#b83232}.dm{background:#b07010}.dl{background:#287048}
.vtitle{font-size:13px;font-weight:700;color:#111;margin-bottom:3px}
.vdesc{font-size:12px;color:#555;line-height:1.6}

.ritem{padding:12px 14px;background:#fff;border:1px solid #e8e8e8;
  border-left:4px solid;border-radius:8px;margin-bottom:8px;
  font-size:13px;line-height:1.6;color:#333}
.rh{border-left-color:#b83232}.rm{border-left-color:#b07010}.rl{border-left-color:#287048}
.rlbl{font-size:11px;font-weight:700;margin-bottom:4px}
.rlbl.h{color:#b83232}.rlbl.m{color:#9a6800}.rlbl.l{color:#287048}

.footer{text-align:center;margin-top:32px;font-size:11px;color:#bbb;
  padding-top:16px;border-top:1px solid #e8e8e8}

@media(max-width:640px){
  .cards{grid-template-columns:1fr 1fr}
  .charts{grid-template-columns:1fr}
}
</style>
</head>
<body>
<div class="wrap">

<div class="header">
  <img src="logo.png" alt="Zebyte" onerror="this.style.display='none'">
  <div style="text-align:right">
    <h1>Auditoria de Infraestrutura de Rede</h1>
    <p><strong>ZeScan Pro v.1</strong> &nbsp;|&nbsp; Zebyte Consulting &nbsp;|&nbsp; Data: {{.Data}} &nbsp;|&nbsp; Duração: {{.Duration}}</p>
  </div>
</div>

<div class="cards">
  <div class="card">
    <div class="lbl">Hosts ativos</div>
    <div class="val">{{.TotalHosts}}</div>
    <div class="sub">na rede escaneada</div>
  </div>
  <div class="card">
    <div class="lbl">Portas abertas</div>
    <div class="val">{{.TotalOpen}}</div>
    <div class="sub">em toda a rede</div>
  </div>
  <div class="card">
    <div class="lbl">Score de risco</div>
    <div class="val {{if eq .RiskLabel "Alto"}}c-red{{else if eq .RiskLabel "Médio"}}c-amb{{else}}c-grn{{end}}">{{.RiskLabel}}</div>
    <div class="sub">avaliação geral da rede</div>
  </div>
  <div class="card">
    <div class="lbl">Com vulnerabilidades</div>
    <div class="val c-red">{{.VulnCount}}</div>
    <div class="sub">{{.SafeCount}} hosts sem achados críticos</div>
  </div>
</div>

<p class="sec">Visão geral — análise de dados</p>
<div class="charts">
  <div class="cbox">
    <div class="ct">Distribuição de hosts por risco</div>
    <div class="cwrap"><canvas id="donutChart"></canvas></div>
  </div>
  <div class="cbox">
    <div class="ct">Score de risco por host (0–10)</div>
    <div class="cwrap"><canvas id="barChart"></canvas></div>
  </div>
</div>

<p class="sec">Inventário de hosts e exposição</p>
<table class="tbl">
  <thead>
    <tr>
      <th>IP / Nome</th>
      <th>Sistema operacional</th>
      <th>Portas abertas</th>
      <th>Risco</th>
      <th>Achados principais</th>
    </tr>
  </thead>
  <tbody>
  {{range .Hosts}}
    <tr>
      <td>
        <strong>{{.IP}}</strong>
        {{if .Hostname}}<div class="tip">{{.Hostname}}</div>{{end}}
        {{if .Vendor}}<div class="tip">{{.Vendor}}</div>{{end}}
      </td>
      <td>
        {{if .OS}}{{.OS}}{{if .OSAcc}}<div class="tip">{{.OSAcc}}% correspondência</div>{{end}}
        {{else}}<span style="color:#bbb">Desconhecido</span>{{end}}
      </td>
      <td>
        {{if .OpenPorts}}
          {{range .OpenPorts}}
            <div>{{.Port}}/{{.Protocol}}{{if .Service}} — <span style="color:#555">{{.Service}}</span>{{end}}{{if .Product}} <span style="color:#999;font-size:11px">({{.Product}}{{if .Version}} {{.Version}}{{end}})</span>{{end}}</div>
          {{end}}
        {{else}}<span style="color:#bbb">Nenhuma detectada</span>{{end}}
      </td>
      <td>
        {{if eq .RiskLevel "Alto"}}<span class="badge b-red">Alto</span>
        {{else if eq .RiskLevel "Médio"}}<span class="badge b-amb">Médio</span>
        {{else if eq .RiskLevel "Baixo"}}<span class="badge b-grn">Baixo</span>
        {{else}}<span class="badge b-gry">Info</span>{{end}}
      </td>
      <td>
        {{if .Findings}}{{range .Findings}}<div style="font-size:12px;color:#555;margin-bottom:2px">• {{.}}</div>{{end}}
        {{else}}<span style="color:#bbb">—</span>{{end}}
      </td>
    </tr>
  {{end}}
  </tbody>
</table>

{{if .Vulns}}
<p class="sec">Vulnerabilidades e achados — detalhamento</p>
{{range .Vulns}}
<div class="vitem">
  <div class="vdot {{if eq .Severity "high"}}dh{{else if eq .Severity "med"}}dm{{else}}dl{{end}}"></div>
  <div style="flex:1;min-width:0">
    <div class="vtitle">{{.Title}} &nbsp;<span style="font-size:11px;font-weight:400;color:#999">{{.IP}}:{{.Port}}</span></div>
    <div class="vdesc"><pre>{{.Output}}</pre></div>
  </div>
</div>
{{end}}
{{end}}

<p class="sec">Recomendações priorizadas</p>
<div class="ritem rh">
  <div class="rlbl h">CRÍTICO — Ação imediata</div>
  Desabilitar modos de depuração (debug) em todos os servidores web expostos. Verificar configurações de ASP.NET, PHP e frameworks similares que possam expor variáveis de sessão, tokens e diagnósticos internos a qualquer host da rede.
</div>
<div class="ritem rh">
  <div class="rlbl h">ALTO — Ação imediata</div>
  Configurar autenticação obrigatória em serviços de streaming (RTSP, câmeras IP). Restringir acesso via firewall somente a dispositivos autorizados e aplicar bloqueio por endereço MAC onde possível.
</div>
<div class="ritem rh">
  <div class="rlbl h">ALTO — Curto prazo</div>
  Atualizar kernels Linux desatualizados (versões 2.6.x/3.x, sem suporte desde 2016). Migrar para distribuições com kernel ≥ 5.15 LTS para eliminar CVEs públicas conhecidas.
</div>
<div class="ritem rm">
  <div class="rlbl m">MÉDIO — Curto prazo</div>
  Isolar dispositivos IoT (câmeras, smart TVs, Chromecast) em VLAN dedicada, separada de estações de trabalho e servidores. Implementar regras de firewall entre segmentos para bloquear movimento lateral.
</div>
<div class="ritem rm">
  <div class="rlbl m">MÉDIO — Curto prazo</div>
  Atualizar firmware de todos os dispositivos identificados. Revisar CVEs específicas para cada versão de software encontrada, especialmente o Web Viewer do DVR.
</div>
<div class="ritem rl">
  <div class="rlbl l">BAIXO — Médio prazo</div>
  Agendar scans periódicos automatizados (OpenVAS/Greenbone) e implementar monitoramento contínuo com Zeek ou Suricata para detectar comportamentos anômalos antes que se tornem incidentes.
</div>

<div class="footer">ZeScan Pro v.1 &nbsp;|&nbsp; Zebyte Consulting &nbsp;|&nbsp; Relatório gerado em {{.Data}}</div>
</div>

<script>
(function(){
  new Chart(document.getElementById('donutChart'),{
    type:'doughnut',
    data:{
      labels:{{.DonutLabels}},
      datasets:[{data:{{.DonutData}},backgroundColor:{{.DonutColors}},borderWidth:0,hoverOffset:4}]
    },
    options:{
      responsive:true,maintainAspectRatio:false,
      plugins:{legend:{position:'bottom',labels:{font:{size:12},padding:14,boxWidth:12}}}
    }
  });
  new Chart(document.getElementById('barChart'),{
    type:'bar',
    data:{
      labels:{{.BarLabels}},
      datasets:[{label:'Score (0-10)',data:{{.BarScores}},backgroundColor:{{.BarColors}},borderRadius:4,borderSkipped:false}]
    },
    options:{
      responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{
        y:{min:0,max:10,grid:{color:'rgba(0,0,0,0.06)'},ticks:{font:{size:11}}},
        x:{grid:{display:false},ticks:{font:{size:11}}}
      }
    }
  });
})();
</script>
</body>
</html>`

// ── Helpers ───────────────────────────────────────────────────────────────────

func jsArr(vals []string) template.JS {
	var b strings.Builder
	b.WriteString("[")
	for i, v := range vals {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"`)
		b.WriteString(strings.ReplaceAll(v, `"`, `\"`))
		b.WriteString(`"`)
	}
	b.WriteString("]")
	return template.JS(b.String())
}

func jsIntArr(vals []int) template.JS {
	var b strings.Builder
	b.WriteString("[")
	for i, v := range vals {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "%d", v)
	}
	b.WriteString("]")
	return template.JS(b.String())
}

func shortLabel(ip, hostname string) string {
	if hostname != "" {
		if len(hostname) > 10 {
			return hostname[:10]
		}
		return hostname
	}
	parts := strings.Split(ip, ".")
	if len(parts) >= 4 {
		return "." + parts[2] + "." + parts[3]
	}
	return ip
}

func scoreHost(ports []NmapPort) (level string, score int, findings []string) {
	seen := map[string]bool{}
	for _, p := range ports {
		if p.State.State != "open" {
			continue
		}
		svc := strings.ToLower(p.Service.Name)
		switch svc {
		case "telnet":
			score += 3
			findings = append(findings, "Telnet aberto — protocolo sem criptografia")
		case "rtsp":
			score += 3
			findings = append(findings, fmt.Sprintf("RTSP exposto na porta %s — verificar autenticação", p.PortId))
		case "ftp":
			score += 2
			findings = append(findings, fmt.Sprintf("FTP na porta %s — preferir SFTP/SCP", p.PortId))
		}
		for _, s := range p.Scripts {
			key := s.Id + ":" + p.PortId
			if seen[key] {
				continue
			}
			out := strings.TrimSpace(s.Output)
			if len(out) < 5 {
				continue
			}
			seen[key] = true
			low := strings.ToLower(out)
			switch {
			case s.Id == "http-aspnet-debug" || strings.Contains(low, "debug is enabled"):
				score += 4
				findings = append(findings, "ASP.NET Debug ATIVO — execução remota possível")
			case strings.Contains(low, "vulnerable"):
				score += 3
				short := s.Id
				if len(out) > 90 {
					short = s.Id + " — " + out[:90] + "…"
				} else {
					short = s.Id + " — " + out
				}
				findings = append(findings, short)
			case strings.Contains(low, "cve"):
				score += 2
				findings = append(findings, s.Id+" — CVE referenciada (verificar manualmente)")
			default:
				score++
				if len(out) > 70 {
					findings = append(findings, s.Id+" — "+out[:70]+"…")
				} else {
					findings = append(findings, s.Id+" — "+out)
				}
			}
		}
	}
	switch {
	case score >= 7:
		level = "Alto"
	case score >= 3:
		level = "Médio"
	default:
		level = "Baixo"
	}
	return
}

func vulnSeverity(id, output string) string {
	low := strings.ToLower(output)
	switch {
	case strings.Contains(low, "debug is enabled"), strings.Contains(low, "vulnerable"):
		return "high"
	case strings.Contains(low, "cve"), strings.Contains(low, "warning"):
		return "med"
	default:
		return "low"
	}
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	a := app.New()
	w := a.NewWindow("ZeScan Pro v.1 — Auditoria Zebyte")
	w.Resize(fyne.NewSize(600, 460))

	logo := canvas.NewImageFromFile("logo.png")
	logo.FillMode = canvas.ImageFillContain
	logo.SetMinSize(fyne.NewSize(120, 120))

	inputRange := widget.NewEntry()
	inputRange.SetText("192.168.86.0/24")

	status := widget.NewLabel("Status: Pronto")

	progress := widget.NewProgressBarInfinite()
	progress.Hide()

	btnScan := widget.NewButton("Executar Auditoria Profunda", func() {
		target := inputRange.Text
		status.SetText("Iniciando scan: " + target)
		progress.Show()

		go func() {
			start := time.Now()

			cmd := exec.Command("sudo", "nmap",
				"-sS", "-sV", "-O", "-A",
				"--script", "vuln",
				"--reason",
				"-oX", "relatorio_zebyte_completo.xml",
				target)
			cmd.Run()

			duration := time.Since(start).Round(time.Second).String()

			// ── Parse XML ─────────────────────────────────────────────────────
			raw, _ := os.ReadFile("relatorio_zebyte_completo.xml")
			var nmapRes NmapRun
			xml.Unmarshal(raw, &nmapRes)

			// ── Processa hosts ────────────────────────────────────────────────
			var hostRows []HostRow
			var vulnEntries []VulnEntry

			totalOpen := 0
			vulnCount, safeCount, medCount := 0, 0, 0

			var barLabels, barColors []string
			var barScores []int

			for _, h := range nmapRes.Hosts {
				if h.Status.State != "up" {
					continue
				}

				ip, vendor := "", ""
				for _, addr := range h.Address {
					if addr.AddrType == "ipv4" && ip == "" {
						ip = addr.Addr
					}
					if addr.Vendor != "" && vendor == "" {
						vendor = addr.Vendor
					}
				}
				hostname := ""
				for _, hn := range h.Hostnames {
					if hn.Name != "" {
						hostname = hn.Name
						break
					}
				}

				osName, osAcc := "", ""
				if len(h.Os.OsMatch) > 0 {
					osName = h.Os.OsMatch[0].Name
					osAcc = h.Os.OsMatch[0].Accuracy
				}

				var openPorts []OpenPort
				for _, p := range h.Ports {
					if p.State.State == "open" {
						totalOpen++
						openPorts = append(openPorts, OpenPort{
							Port:     p.PortId,
							Protocol: p.Protocol,
							Service:  p.Service.Name,
							Product:  p.Service.Product,
							Version:  p.Service.Version,
						})
					}
					for _, s := range p.Scripts {
						out := strings.TrimSpace(s.Output)
						if len(out) < 5 {
							continue
						}
						vulnEntries = append(vulnEntries, VulnEntry{
							Severity: vulnSeverity(s.Id, out),
							Title:    s.Id,
							IP:       ip,
							Port:     p.PortId,
							Output:   out,
						})
					}
				}

				level, score, findings := scoreHost(h.Ports)

				switch level {
				case "Alto":
					vulnCount++
				case "Médio":
					medCount++
				default:
					safeCount++
				}

				c := "#287048"
				if score >= 7 {
					c = "#b83232"
				} else if score >= 3 {
					c = "#b07010"
				}
				barLabels = append(barLabels, shortLabel(ip, hostname))
				barScores = append(barScores, score)
				barColors = append(barColors, c)

				hostRows = append(hostRows, HostRow{
					IP:        ip,
					Hostname:  hostname,
					Vendor:    vendor,
					OS:        osName,
					OSAcc:     osAcc,
					OpenPorts: openPorts,
					RiskLevel: level,
					RiskScore: score,
					Findings:  findings,
					Lastboot:  h.Uptime.Lastboot,
				})
			}

			overallRisk := "Baixo"
			for _, hr := range hostRows {
				if hr.RiskLevel == "Alto" {
					overallRisk = "Alto"
					break
				} else if hr.RiskLevel == "Médio" && overallRisk != "Alto" {
					overallRisk = "Médio"
				}
			}

			donutLabels := []string{
				fmt.Sprintf("Alto risco (%d)", vulnCount),
				fmt.Sprintf("Risco médio (%d)", medCount),
				fmt.Sprintf("Sem achados (%d)", safeCount),
			}
			donutData := []int{vulnCount, medCount, safeCount}
			donutColors := []string{"#b83232", "#b07010", "#287048"}

			rd := ReportData{
				Data:        time.Now().Format("02/01/2006 15:04"),
				Duration:    duration,
				TotalHosts:  len(hostRows),
				TotalOpen:   totalOpen,
				RiskLabel:   overallRisk,
				VulnCount:   vulnCount,
				SafeCount:   safeCount,
				MedCount:    medCount,
				Hosts:       hostRows,
				Vulns:       vulnEntries,
				DonutLabels: jsArr(donutLabels),
				DonutData:   jsIntArr(donutData),
				DonutColors: jsArr(donutColors),
				BarLabels:   jsArr(barLabels),
				BarScores:   jsIntArr(barScores),
				BarColors:   jsArr(barColors),
			}

			out, err := os.Create("Relatorio_Final_Zebyte.html")
			if err == nil {
				tmpl := template.Must(template.New("report").Parse(htmlTmpl))
				tmpl.Execute(out, rd)
				out.Close()
			}

			status.SetText("Concluído! Relatório gerado em " + duration)
			status.Refresh()
			progress.Hide()
			progress.Refresh()
		}()
	})

	btnView := widget.NewButton("Abrir Relatório no Browser", func() {
		pwd, _ := os.Getwd()
		u, _ := url.Parse("file://" + pwd + "/Relatorio_Final_Zebyte.html")
		a.OpenURL(u)
	})

	w.SetContent(container.NewVBox(
		logo,
		widget.NewLabel("Range de Destino:"),
		inputRange,
		status,
		progress,
		btnScan,
		btnView,
	))
	w.ShowAndRun()
}