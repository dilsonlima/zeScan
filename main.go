package main

import (
	"encoding/xml"
	"html/template"
	"net/url"
	"os"
	"os/exec"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// Estrutura para extrair dados do seu comando Nmap completo
type NmapRun struct {
	Hosts []struct {
		Status struct {
			State string `xml:"state,attr"`
		} `xml:"status"`
		Address []struct {
			Addr     string `xml:"addr,attr"`
			AddrType string `xml:"addrtype,attr"`
			Vendor   string `xml:"vendor,attr"`
		} `xml:"address"`
		Os struct {
			OsMatch []struct {
				Name     string `xml:"name,attr"`
				Accuracy string `xml:"accuracy,attr"`
			} `xml:"osmatch"`
		} `xml:"os"`
		Ports []struct {
			PortId  string `xml:"portid,attr"`
			Reason  string `xml:"reason,attr"`
			Service struct {
				Name    string `xml:"name,attr"`
				Product string `xml:"product,attr"`
				Version string `xml:"version,attr"`
			} `xml:"service"`
			Scripts []struct {
				Id     string `xml:"id,attr"`
				Output string `xml:"output,attr"`
			} `xml:"script"`
		} `xml:"ports>port"`
	} `xml:"host"`
}

const htmlTmpl = `
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <title>Relatório Executivo Zebyte</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: #eceff1; color: #37474f; }
        .container { max-width: 1000px; margin: auto; background: white; padding: 40px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 4px solid #01579b; padding-bottom: 20px; margin-bottom: 30px; }
        .card { background: #fff; border: 1px solid #cfd8dc; border-left: 6px solid #b71c1c; padding: 20px; margin-bottom: 20px; border-radius: 8px; }
        .secure { border-left-color: #2e7d32; }
        table { width: 100%; margin-top: 10px; border-collapse: collapse; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; color: #546e7a; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; background: #ffebee; color: #c62828; }
        .chart-box { width: 350px; margin: 20px auto; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <img src="logo.png" style="max-height: 100px;">
            <div style="text-align: right;">
                <h1 style="margin:0; color:#01579b;">Auditoria de Rede</h1>
                <p style="margin:5px 0;"><strong>ZeScan Pro v.1</strong> | Zebyte Consulting</p>
                <p style="font-size: 13px;">Data do Scan: {{.Data}}</p>
            </div>
        </div>

        <div class="chart-box">
            <canvas id="vulnChart"></canvas>
            <p><strong>Resumo de Segurança</strong></p>
        </div>

        {{range .Hosts}}
        <div class="card {{if eq (len .Ports) 0}}secure{{end}}">
            <h3 style="margin-top:0;">Host: {{(index .Address 0).Addr}}</h3>
            <p><strong>OS Detectado:</strong> {{if .Os.OsMatch}}{{(index .Os.OsMatch 0).Name}} ({{(index .Os.OsMatch 0).Accuracy}}%){{else}}Desconhecido{{end}}</p>
            <table>
                <tr><th>Porta</th><th>Serviço/Versão</th><th>Motivo</th><th>Vulnerabilidades</th></tr>
                {{range .Ports}}
                <tr>
                    <td>{{.PortId}}</td>
                    <td>{{.Service.Product}} {{.Service.Version}}</td>
                    <td><small>{{.Reason}}</small></td>
                    <td>
                        {{range .Scripts}}
                            <span class="badge">{{.Id}}</span><br>
                        {{else}}
                            <span style="color:green">✔ Seguro</span>
                        {{end}}
                    </td>
                </tr>
                {{end}}
            </table>
        </div>
        {{end}}
    </div>
    <script>
        new Chart(document.getElementById('vulnChart'), {
            type: 'doughnut',
            data: {
                labels: ['Críticos/Vulneráveis', 'Seguros/Limpos'],
                datasets: [{ data: [{{.Vulns}}, {{.Safe}}], backgroundColor: ['#b71c1c', '#2e7d32'], hoverOffset: 4 }]
            }
        });
    </script>
</body>
</html>`

func main() {
	a := app.New()
	w := a.NewWindow("ZeScan Pro v.1 - Auditoria Zebyte")
	w.Resize(fyne.NewSize(600, 450))

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
		status.SetText("Iniciando Scan: " + target)
		progress.Show()
		
		go func() {
			// SEU COMANDO COMPLETO
			cmd := exec.Command("sudo", "nmap", "-sS", "-sV", "-O", "-A", "--script", "vuln", "--reason", "-oX", "relatorio_zebyte_completo.xml", target)
			cmd.Run()

			// PARSER DO XML GERADO
			data, _ := os.ReadFile("relatorio_zebyte_completo.xml")
			var nmapRes NmapRun
			xml.Unmarshal(data, &nmapRes)

			vCount, sCount := 0, 0
			for _, h := range nmapRes.Hosts {
				isVuln := false
				for _, p := range h.Ports {
					if len(p.Scripts) > 0 { isVuln = true; break }
				}
				if isVuln { vCount++ } else { sCount++ }
			}

			// GERAÇÃO DO HTML EXECUTIVO
			out, _ := os.Create("Relatorio_Final_Zebyte.html")
			tmpl := template.Must(template.New("report").Parse(htmlTmpl))
			tmpl.Execute(out, map[string]interface{}{
				"Hosts": nmapRes.Hosts, "Data": time.Now().Format("02/01/2006 15:04"),
				"Vulns": vCount, "Safe": sCount,
			})
			out.Close()

			// ATUALIZAÇÃO SEGURA
			status.SetText("Concluído! Relatório gerado.")
			status.Refresh()
			progress.Hide()
		}()
	})

	btnView := widget.NewButton("Abrir Relatório no Browser", func() {
		pwd, _ := os.Getwd()
		u, _ := url.Parse("file://" + pwd + "/Relatorio_Final_Zebyte.html")
		a.OpenURL(u)
	})

	w.SetContent(container.NewVBox(logo, widget.NewLabel("Range de Destino:"), inputRange, status, progress, btnScan, btnView))
	w.ShowAndRun()
}