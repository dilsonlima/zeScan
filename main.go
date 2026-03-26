package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/beevik/ntp"
)

// ════════════════════════════════════════════════════════════════════════════
//  BASE OUI — MAC VENDOR LOOKUP
// ════════════════════════════════════════════════════════════════════════════

var ouiDB = map[string]string{}
var ouiLoaded = false

const ouiCacheFile = ".oui_cache.txt"
const ouiURL = "https://standards-oui.ieee.org/oui/oui.txt"

func loadOUI(statusFn func(string)) {
	if ouiLoaded {
		return
	}
	if data, err := os.ReadFile(ouiCacheFile); err == nil {
		if info, err2 := os.Stat(ouiCacheFile); err2 == nil {
			if time.Since(info.ModTime()) < 30*24*time.Hour {
				parseOUI(data)
				statusFn(fmt.Sprintf("Base OUI: %d fabricantes (cache)", len(ouiDB)))
				ouiLoaded = true
				return
			}
		}
	}
	statusFn("Baixando base OUI do IEEE (~4 MB)…")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(ouiURL)
	if err != nil {
		statusFn("OUI offline — usando base embutida")
		loadOUIFallback()
		return
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		loadOUIFallback()
		return
	}
	os.WriteFile(ouiCacheFile, data, 0644)
	parseOUI(data)
	statusFn(fmt.Sprintf("Base OUI: %d fabricantes (IEEE)", len(ouiDB)))
	ouiLoaded = true
}

func parseOUI(data []byte) {
	ouiDB = make(map[string]string, 40000)
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, "(hex)") {
			continue
		}
		parts := strings.SplitN(line, "(hex)", 2)
		if len(parts) != 2 {
			continue
		}
		prefix := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(parts[0]), "-", ""))
		if len(prefix) != 6 {
			continue
		}
		vendor := strings.TrimSpace(parts[1])
		if vendor != "" {
			ouiDB[prefix] = vendor
		}
	}
}

func lookupMAC(mac string) string {
	if mac == "" {
		return ""
	}
	clean := strings.ToUpper(strings.NewReplacer(":", "", "-", "", ".", "").Replace(mac))
	if len(clean) < 6 {
		return ""
	}
	var firstByte uint64
	fmt.Sscanf(clean[:2], "%X", &firstByte)
	if firstByte&0x02 != 0 {
		return "(MAC aleatório — privacidade)"
	}
	if v, ok := ouiDB[clean[:6]]; ok {
		return v
	}
	return ""
}

func loadOUIFallback() {
	ouiDB = map[string]string{
		"F4FC49": "Google LLC", "A47733": "Google LLC", "3C5AB4": "Google LLC",
		"F88FCA": "Google LLC", "4472AC": "AzureWave Technology",
		"FCFC48": "Apple Inc.", "AC8C46": "Apple Inc.", "A8667F": "Apple Inc.",
		"3C0754": "Apple Inc.", "7C6D62": "Apple Inc.", "001451": "Apple Inc.",
		"000142": "Cisco Systems", "001A2B": "Cisco Systems", "885A92": "Cisco Systems",
		"000AEB": "TP-Link", "50C7BF": "TP-Link", "74DA88": "TP-Link",
		"002339": "Samsung", "0024E9": "Samsung", "3CB87A": "Samsung",
		"000F35": "Intel", "001302": "Intel", "40251B": "Intel",
		"0002BE": "Amazon", "6477B7": "Amazon", "74C246": "Amazon",
		"002722": "Ubiquiti", "04189A": "Ubiquiti", "DC9FDB": "Ubiquiti",
		"28CDA4": "Raspberry Pi", "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi",
		"000569": "VMware", "000C29": "VMware", "005056": "VMware",
		"283B82": "Hikvision", "4C5099": "Hikvision", "546BEB": "Hikvision",
		"1C622E": "Dahua", "34C939": "Dahua",
		"001143": "Dell", "00145E": "Dell", "B083FE": "Dell",
		"001560": "HP Inc.", "001708": "HP Inc.", "9CB70D": "HP Inc.",
		"004E07": "MikroTik", "18FD74": "MikroTik", "74AD4B": "MikroTik",
	}
	ouiLoaded = true
}

// ════════════════════════════════════════════════════════════════════════════
//  BANCO DE PORTAS DE ACESSO REMOTO
// ════════════════════════════════════════════════════════════════════════════

type RemoteAccessPort struct {
	Port  string
	Proto string
	Name  string
	Risk  string
	Score int
	Note  string
}

var remoteAccessDB = map[string]RemoteAccessPort{
	"23":    {"23", "tcp", "Telnet", "CRÍTICO", 5, "Desabilitar. Substituir por SSH."},
	"512":   {"512", "tcp", "rexec", "CRÍTICO", 5, "Protocolo Unix sem criptografia."},
	"513":   {"513", "tcp", "rlogin", "CRÍTICO", 5, "Sem criptografia. Substituir por SSH."},
	"514":   {"514", "tcp", "rsh", "CRÍTICO", 5, "Sem autenticação forte. Bloquear."},
	"22":    {"22", "tcp", "SSH", "MÉDIO", 1, "Verificar versão, desabilitar root login."},
	"2222":  {"2222", "tcp", "SSH alt.", "MÉDIO", 2, "SSH em porta não-padrão."},
	"3389":  {"3389", "tcp", "RDP", "ALTO", 4, "RDP exposto. Restringir por IP, usar NLA e VPN."},
	"5900":  {"5900", "tcp", "VNC", "ALTO", 4, "VNC sem criptografia. Tunelizar via SSH."},
	"5901":  {"5901", "tcp", "VNC :1", "ALTO", 4, "VNC exposto. Restringir acesso."},
	"5938":  {"5938", "tcp", "TeamViewer", "ALTO", 3, "Verificar se autorizado."},
	"7070":  {"7070", "tcp", "AnyDesk", "ALTO", 3, "Confirmar autorização."},
	"6568":  {"6568", "tcp", "AnyDesk", "ALTO", 3, "Verificar autorização e senha."},
	"4899":  {"4899", "tcp", "Radmin", "ALTO", 4, "CVEs críticas em versões antigas."},
	"5985":  {"5985", "tcp", "WinRM HTTP", "ALTO", 4, "Desabilitar ou usar HTTPS."},
	"5986":  {"5986", "tcp", "WinRM HTTPS", "MÉDIO", 2, "Verificar certificado."},
	"135":   {"135", "tcp", "MSRPC", "ALTO", 3, "Bloquear externamente."},
	"445":   {"445", "tcp", "SMB", "ALTO", 4, "Risco EternalBlue. Bloquear externo."},
	"139":   {"139", "tcp", "NetBIOS", "ALTO", 3, "Bloquear externamente."},
	"623":   {"623", "udp", "IPMI/BMC", "CRÍTICO", 5, "Isolar em rede de gestão."},
	"1194":  {"1194", "udp", "OpenVPN", "MÉDIO", 1, "Verificar configuração."},
	"1723":  {"1723", "tcp", "PPTP VPN", "ALTO", 3, "Inseguro. Migrar para WireGuard."},
	"51820": {"51820", "udp", "WireGuard", "MÉDIO", 1, "Verificar peers."},
	"4444":  {"4444", "tcp", "Backdoor", "CRÍTICO", 6, "Associado a Metasploit. Investigar."},
	"1337":  {"1337", "tcp", "Backdoor", "CRÍTICO", 6, "Associado a RATs. Investigar."},
	"31337": {"31337", "tcp", "Back Orifice", "CRÍTICO", 6, "Backdoor histórico. Investigar."},
	"161":   {"161", "udp", "SNMP", "ALTO", 3, "SNMPv1/v2 inseguro. Migrar para v3."},
}

func remotePorts() string {
	ports := make([]string, 0, len(remoteAccessDB))
	for p := range remoteAccessDB {
		ports = append(ports, p)
	}
	return strings.Join(ports, ",")
}

// ════════════════════════════════════════════════════════════════════════════
//  PARSER XML NMAP
// ════════════════════════════════════════════════════════════════════════════

type NmapRun struct {
	Hosts []NmapHost `xml:"host"`
}
type NmapHost struct {
	Status    struct{ State string `xml:"state,attr"` } `xml:"status"`
	Address   []struct {
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

// ════════════════════════════════════════════════════════════════════════════
//  ESTRUTURAS DO TEMPLATE
// ════════════════════════════════════════════════════════════════════════════

type HostRow struct {
	IP, MAC, Hostname, Vendor, OS, OSAcc string
	DeviceType, DeviceIcon               string
	OpenPorts                            []OpenPort
	RiskLevel                            string
	RiskScore                            int
	Findings                             []string
	RemoteFindings                       []RemoteFinding
	Lastboot                             string
}
type OpenPort struct{ Port, Protocol, Service, Product, Version string }
type RemoteFinding struct{ Port, Name, Risk, Note, Badge string }
type VulnEntry struct{ Severity, Title, IP, Port, Output string }
type AIRecommendation struct{ Priority, CssClass, LblClass, Timeframe, Description string }

type ReportData struct {
	Data, Duration                          string
	TotalHosts, TotalOpen                   int
	RiskLabel                               string
	VulnCount, SafeCount, MedCount          int
	RemoteAccessCount                       int
	Hosts                                   []HostRow
	Vulns                                   []VulnEntry
	Recommendations                         []AIRecommendation
	AIAnalysis                              template.HTML
	VendorLabels, VendorCounts, VendorColors template.JS
	VendorTypeLabels, VendorTypePct, VendorTypeColors template.JS
	DonutLabels, DonutData, DonutColors     template.JS
	BarLabels, BarScores, BarColors         template.JS
}

// ════════════════════════════════════════════════════════════════════════════
//  CLIENTE ANTHROPIC
// ════════════════════════════════════════════════════════════════════════════

const anthropicAPI = "https://api.anthropic.com/v1/messages"
const anthropicModel = "claude-haiku-4-5-20251001"

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system"`
	Messages  []anthropicMessage `json:"messages"`
}
type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type anthropicResponse struct {
	Content []struct{ Text string `json:"text"` } `json:"content"`
	Error   *struct{ Message string `json:"message"` } `json:"error"`
}

func callClaude(apiKey, system, user string) (string, error) {
	b, _ := json.Marshal(anthropicRequest{
		Model: anthropicModel, MaxTokens: 2048, System: system,
		Messages: []anthropicMessage{{Role: "user", Content: user}},
	})
	req, _ := http.NewRequest("POST", anthropicAPI, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var ar anthropicResponse
	json.Unmarshal(body, &ar)
	if ar.Error != nil {
		return "", fmt.Errorf("API: %s", ar.Error.Message)
	}
	if len(ar.Content) == 0 {
		return "", fmt.Errorf("resposta vazia")
	}
	return ar.Content[0].Text, nil
}

func buildScanSummary(hosts []HostRow, vulns []VulnEntry) string {
	var sb strings.Builder
	sb.WriteString("=== SCAN NMAP ===\n\n")
	for _, h := range hosts {
		sb.WriteString(fmt.Sprintf("HOST: %s", h.IP))
		if h.Hostname != "" {
			sb.WriteString(fmt.Sprintf(" (%s)", h.Hostname))
		}
		if h.Vendor != "" {
			sb.WriteString(fmt.Sprintf(" [%s]", h.Vendor))
		}
		sb.WriteString("\n")
		if h.OS != "" {
			sb.WriteString(fmt.Sprintf("  OS: %s (%s%%)\n", h.OS, h.OSAcc))
		}
		sb.WriteString(fmt.Sprintf("  Risco: %s (score %d)\n", h.RiskLevel, h.RiskScore))
		for _, p := range h.OpenPorts {
			sb.WriteString(fmt.Sprintf("  Porta: %s/%s %s %s\n", p.Port, p.Protocol, p.Service, p.Product))
		}
		for _, f := range h.Findings {
			sb.WriteString(fmt.Sprintf("  Achado: %s\n", f))
		}
		sb.WriteString("\n")
	}
	if len(vulns) > 0 {
		sb.WriteString("=== VULNERABILIDADES ===\n\n")
		n := 15
		if len(vulns) < n {
			n = len(vulns)
		}
		for _, v := range vulns[:n] {
			out := v.Output
			if len(out) > 200 {
				out = out[:200] + "…"
			}
			sb.WriteString(fmt.Sprintf("%s | %s:%s\n%s\n\n", v.Title, v.IP, v.Port, out))
		}
	}
	return sb.String()
}

func parseAIRecommendations(jsonText string) ([]AIRecommendation, error) {
	clean := strings.TrimSpace(jsonText)
	if idx := strings.Index(clean, "["); idx >= 0 {
		clean = clean[idx:]
	}
	if idx := strings.LastIndex(clean, "]"); idx >= 0 {
		clean = clean[:idx+1]
	}
	var raw []struct {
		Priority, Timeframe, Description string
	}
	if err := json.Unmarshal([]byte(clean), &raw); err != nil {
		return nil, err
	}
	cssMap := map[string]string{"CRÍTICO": "rh", "ALTO": "rh", "MÉDIO": "rm", "BAIXO": "rl"}
	lblMap := map[string]string{"CRÍTICO": "h", "ALTO": "h", "MÉDIO": "m", "BAIXO": "l"}
	var recs []AIRecommendation
	for _, r := range raw {
		p := strings.ToUpper(strings.TrimSpace(r.Priority))
		recs = append(recs, AIRecommendation{
			Priority: p, CssClass: cssMap[p], LblClass: lblMap[p],
			Timeframe: r.Timeframe, Description: r.Description,
		})
	}
	return recs, nil
}

func generateAIContent(apiKey string, hosts []HostRow, vulns []VulnEntry) ([]AIRecommendation, template.HTML, error) {
	summary := buildScanSummary(hosts, vulns)
	sys := `Você é especialista sênior em segurança de redes. Gera relatórios executivos em português do Brasil.`
	recJSON, err := callClaude(apiKey, sys, fmt.Sprintf(`Gere 4 a 7 recomendações específicas para:\n%s\nSomente array JSON: [{"priority":"CRÍTICO"|"ALTO"|"MÉDIO"|"BAIXO","timeframe":"texto","description":"detalhes com IPs e portas reais"}]`, summary))
	if err != nil {
		return nil, "", err
	}
	recs, err := parseAIRecommendations(recJSON)
	if err != nil {
		recs = []AIRecommendation{{Priority: "INFO", CssClass: "rl", LblClass: "l", Timeframe: "N/A", Description: "Erro ao parsear resposta da IA."}}
	}
	execText, _ := callClaude(apiKey, sys, fmt.Sprintf(`Escreva 3-5 frases sobre segurança desta rede, riscos críticos (mencione IPs) e urgência.\n%s\nSó o parágrafo, sem markdown.`, summary))
	execHTML := template.HTML(strings.ReplaceAll(template.HTMLEscapeString(execText), "\n", "<br>"))
	return recs, execHTML, nil
}

// ════════════════════════════════════════════════════════════════════════════
//  HELPERS
// ════════════════════════════════════════════════════════════════════════════

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

// ════════════════════════════════════════════════════════════════════════════
//  CLASSIFICADOR DE DISPOSITIVOS
// ════════════════════════════════════════════════════════════════════════════

type DeviceClass struct{ Type, Icon string }

func classifyDevice(hostname, osName, vendor string, ports []OpenPort) DeviceClass {
	hn := strings.ToLower(hostname)
	os := strings.ToLower(osName)
	ven := strings.ToLower(vendor)
	hasPort := func(p string) bool {
		for _, op := range ports {
			if op.Port == p {
				return true
			}
		}
		return false
	}
	containsAny := func(s string, kw []string) bool {
		for _, k := range kw {
			if strings.Contains(s, k) {
				return true
			}
		}
		return false
	}
	if containsAny(hn, []string{"print", "printer", "impressora", "epson", "canon", "lexmark", "xerox", "brother", "kyocera", "ricoh"}) ||
		containsAny(ven, []string{"hewlett", "epson", "canon", "lexmark", "xerox", "brother", "kyocera", "ricoh"}) ||
		hasPort("9100") || hasPort("515") || hasPort("631") {
		return DeviceClass{"Impressora", "🖨️"}
	}
	if containsAny(hn, []string{"cam", "camera", "dvr", "nvr", "ipcam", "hikvision", "dahua", "cctv"}) ||
		containsAny(ven, []string{"hikvision", "dahua", "axis", "hanwha", "azurewave"}) ||
		hasPort("554") || hasPort("8899") {
		return DeviceClass{"Câmera IP / DVR", "📷"}
	}
	if containsAny(hn, []string{"router", "roteador", "gateway", "ap", "switch", "firewall", "mikrotik", "ubnt", "unifi", "tp-link", "routeros"}) ||
		containsAny(ven, []string{"cisco", "tp-link", "mikrotik", "ubiquiti", "netgear", "asus", "d-link", "zyxel", "aruba", "ruckus"}) ||
		containsAny(os, []string{"routeros", "junos", "openwrt", "dd-wrt", "pfsense", "airos"}) {
		return DeviceClass{"Roteador / Switch / AP", "🌐"}
	}
	serverPortCount := 0
	for _, sp := range []string{"21", "22", "25", "80", "443", "3306", "5432", "8080", "8443", "27017"} {
		if hasPort(sp) {
			serverPortCount++
		}
	}
	if containsAny(hn, []string{"srv", "server", "servidor", "nas", "storage", "dc", "mail", "smtp", "db", "sql", "proxy", "proxmox", "esxi"}) ||
		containsAny(os, []string{"server", "debian", "centos", "red hat", "rhel", "freebsd", "proxmox", "esxi", "truenas"}) ||
		serverPortCount >= 3 {
		return DeviceClass{"Servidor", "🖥️"}
	}
	if containsAny(hn, []string{"vm", "vps", "virtual", "docker", "kvm", "qemu"}) ||
		containsAny(ven, []string{"vmware", "virtualbox", "parallels"}) {
		return DeviceClass{"Máquina Virtual", "☁️"}
	}
	if containsAny(hn, []string{"iphone", "ipad", "android", "phone", "tablet", "pixel", "galaxy"}) ||
		containsAny(os, []string{"ios", "ipados", "android"}) {
		return DeviceClass{"Smartphone / Tablet", "📱"}
	}
	if containsAny(hn, []string{"tv", "appletv", "firetv", "chromecast", "smarttv"}) ||
		(containsAny(ven, []string{"google llc", "amazon"}) && (hasPort("8008") || hasPort("8009"))) {
		return DeviceClass{"Smart TV / Streaming", "📺"}
	}
	if containsAny(hn, []string{"iot", "sensor", "arduino", "esp", "raspberry", "shelly", "sonoff"}) ||
		containsAny(ven, []string{"raspberry pi", "espressif"}) {
		return DeviceClass{"Dispositivo IoT", "🔌"}
	}
	if containsAny(os, []string{"windows", "win10", "win11", "win7"}) {
		return DeviceClass{"Computador Windows", "💻"}
	}
	if containsAny(os, []string{"macos", "mac os x", "darwin", "os x"}) || containsAny(ven, []string{"apple inc."}) {
		return DeviceClass{"Computador Mac", "🍎"}
	}
	if containsAny(os, []string{"linux", "ubuntu", "linux 2.", "linux 3.", "linux 4.", "linux 5.", "linux 6."}) {
		desktopHN := []string{"tuxao", "tux", "desktop", "notebook", "laptop", "pc", "work", "dev", "home"}
		if containsAny(hn, desktopHN) || hn != "" {
			return DeviceClass{"Computador Linux", "🐧"}
		}
		return DeviceClass{"Servidor Linux", "🖥️"}
	}
	if containsAny(ven, []string{"apple inc."}) || hasPort("62078") {
		return DeviceClass{"Dispositivo Apple", "🍎"}
	}
	if hn != "" {
		return DeviceClass{"Dispositivo de Rede", "🔧"}
	}
	return DeviceClass{"Desconhecido", "❓"}
}

func buildVendorCharts(hosts []HostRow) (vendorLabels, vendorCounts, vendorColors, typeLabels, typePct, typeColors template.JS) {
	palette := []string{"#3B7DD8", "#E8593C", "#1D9E75", "#EF9F27", "#7F77DD", "#D4537E", "#378ADD", "#639922", "#BA7517", "#534AB7"}
	sortKV := func(m map[string]int) []struct{ k string; v int } {
		var s []struct{ k string; v int }
		for k, v := range m {
			s = append(s, struct{ k string; v int }{k, v})
		}
		for i := 0; i < len(s)-1; i++ {
			for j := i + 1; j < len(s); j++ {
				if s[j].v > s[i].v {
					s[i], s[j] = s[j], s[i]
				}
			}
		}
		return s
	}
	vc := map[string]int{}
	for _, h := range hosts {
		v := strings.TrimSpace(h.Vendor)
		if v == "" {
			v = "Não identificado"
		}
		vc[v]++
	}
	var vL []string; var vD []int; var vC []string
	for i, item := range sortKV(vc) {
		vL = append(vL, item.k); vD = append(vD, item.v); vC = append(vC, palette[i%len(palette)])
	}
	vendorLabels = jsArr(vL); vendorCounts = jsIntArr(vD); vendorColors = jsArr(vC)

	tc := map[string]int{}
	for _, h := range hosts {
		t := h.DeviceType
		if t == "" {
			t = "Desconhecido"
		}
		tc[t]++
	}
	tcm := map[string]string{
		"Computador Windows": "#0078D4", "Computador Linux": "#E95420", "Computador Mac": "#A2AAAD",
		"Servidor": "#004A99", "Servidor Linux": "#2D3E50", "Câmera IP / DVR": "#D83B01",
		"Impressora": "#107C10", "Roteador / Switch / AP": "#00B7C3", "Smartphone / Tablet": "#C239B3",
		"Smart TV / Streaming": "#FF8C00", "Dispositivo IoT": "#7A7574", "Máquina Virtual": "#00BCF2",
		"Desconhecido": "#8A8886",
	}
	var tL []string; var tD []int; var tC []string
	for i, item := range sortKV(tc) {
		tL = append(tL, item.k); tD = append(tD, item.v)
		if c, ok := tcm[item.k]; ok {
			tC = append(tC, c)
		} else {
			tC = append(tC, palette[i%len(palette)])
		}
	}
	typeLabels = jsArr(tL); typePct = jsIntArr(tD); typeColors = jsArr(tC)
	return
}

// ════════════════════════════════════════════════════════════════════════════
//  ANÁLISE DE RISCO
// ════════════════════════════════════════════════════════════════════════════

func scoreHost(ports []NmapPort) (level string, score int, findings []string, remoteFindings []RemoteFinding) {
	seen := map[string]bool{}
	for _, p := range ports {
		if p.State.State != "open" {
			continue
		}
		svc := strings.ToLower(p.Service.Name)
		if ra, ok := remoteAccessDB[p.PortId]; ok {
			score += ra.Score
			badge := "b-amb"
			if ra.Risk == "CRÍTICO" {
				badge = "b-red"
			} else if ra.Risk == "MÉDIO" {
				badge = "b-gry"
			}
			remoteFindings = append(remoteFindings, RemoteFinding{Port: p.PortId + "/" + p.Protocol, Name: ra.Name, Risk: ra.Risk, Note: ra.Note, Badge: badge})
			findings = append(findings, fmt.Sprintf("[%s] %s (porta %s)", ra.Risk, ra.Name, p.PortId))
		}
		switch svc {
		case "telnet":
			if !seen["telnet"] {
				score += 3; findings = append(findings, "Telnet aberto"); seen["telnet"] = true
			}
		case "rtsp":
			score += 3; findings = append(findings, fmt.Sprintf("RTSP exposto na porta %s", p.PortId))
		case "ftp":
			score += 2; findings = append(findings, fmt.Sprintf("FTP na porta %s", p.PortId))
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
				score += 4; findings = append(findings, "ASP.NET Debug ATIVO")
			case strings.Contains(low, "vulnerable"):
				score += 3
				if len(out) > 90 {
					findings = append(findings, s.Id+" — "+out[:90]+"…")
				} else {
					findings = append(findings, s.Id+" — "+out)
				}
			case strings.Contains(low, "cve"):
				score += 2; findings = append(findings, s.Id+" — CVE referenciada")
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
	if strings.Contains(low, "debug is enabled") || strings.Contains(low, "vulnerable") {
		return "high"
	}
	if strings.Contains(low, "cve") || strings.Contains(low, "warning") {
		return "med"
	}
	return "low"
}

// ════════════════════════════════════════════════════════════════════════════
//  MODOS DE SCAN
// ════════════════════════════════════════════════════════════════════════════

type ScanMode struct {
	Label, Description string
	Args               func(target, extraPorts string) []string
}

var scanModes = []ScanMode{
	{
		Label: "Rápido (~5 min)", Description: "Descoberta de hosts e portas comuns. Sem scripts vuln.",
		Args: func(target, extraPorts string) []string {
			return []string{"-sS", "-sV", "--version-intensity", "3", "-T4", "--min-rate", "1000",
				"--max-retries", "1", "--host-timeout", "30s", "--min-hostgroup", "64", "--min-parallelism", "100",
				"-p", "21-23,25,53,80,110,135,139,143,161,443,445,554,993,995,1194,1433,1723,3306,3389,5432,5900,5938,6568,7070,8080,8443,8899,9090," + extraPorts,
				"--reason", "-oX", "relatorio_zebyte_completo.xml", target}
		},
	},
	{
		Label: "Balanceado (~20 min)", Description: "Versão + OS + scripts seguros. Sem vuln pesados.",
		Args: func(target, extraPorts string) []string {
			return []string{"-sS", "-sV", "--version-intensity", "5", "-O", "--osscan-limit", "-T4",
				"--min-rate", "500", "--max-retries", "2", "--host-timeout", "2m", "--min-hostgroup", "32", "--min-parallelism", "50",
				"--script", "banner,http-title,http-server-header,ftp-anon,ssh-auth-methods,smb-security-mode,ssl-cert,rdp-enum-encryption,vnc-info,snmp-info",
				"-p", "1-1024," + extraPorts, "--reason", "-oX", "relatorio_zebyte_completo.xml", target}
		},
	},
	{
		Label: "Profundo (~45 min)", Description: "Scripts vuln com timeouts.",
		Args: func(target, extraPorts string) []string {
			return []string{"-sS", "-sV", "--version-intensity", "6", "-O", "--osscan-limit", "-T4",
				"--min-rate", "300", "--max-retries", "2", "--host-timeout", "5m", "--script-timeout", "30s",
				"--min-hostgroup", "16", "--min-parallelism", "25",
				"--script", "vuln,auth,default",
				"-p", "1-1024," + extraPorts, "--reason", "-oX", "relatorio_zebyte_completo.xml", target}
		},
	},
}

// ════════════════════════════════════════════════════════════════════════════
//  INSTALAÇÃO AUTOMÁTICA DO NMAP (Windows)
// ════════════════════════════════════════════════════════════════════════════

// nmapInstalled verifica se o nmap está disponível no PATH.
func nmapInstalled() bool {
	_, err := exec.LookPath("nmap")
	return err == nil
}

// installNmapWindows baixa e instala o Nmap silenciosamente via winget ou
// download direto do installer oficial.
func installNmapWindows(statusFn func(string)) error {
	// Tenta winget primeiro (disponível no Win 10 1709+ e Win 11)
	statusFn("Verificando winget…")
	if _, err := exec.LookPath("winget"); err == nil {
		statusFn("Instalando Nmap via winget…")
		cmd := exec.Command("winget", "install", "--id", "Insecure.Nmap",
			"--silent", "--accept-package-agreements", "--accept-source-agreements")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err == nil {
			statusFn("Nmap instalado com sucesso via winget!")
			return nil
		}
	}

	// Fallback: baixa o installer MSI do site oficial
	statusFn("Baixando instalador do Nmap (~30 MB)…")
	nmapURL := "https://nmap.org/dist/nmap-7.95-setup.exe"
	tmpFile := os.TempDir() + "\\nmap-setup.exe"

	resp, err := http.Get(nmapURL)
	if err != nil {
		return fmt.Errorf("falha ao baixar Nmap: %w", err)
	}
	defer resp.Body.Close()
	f, err := os.Create(tmpFile)
	if err != nil {
		return fmt.Errorf("falha ao criar arquivo: %w", err)
	}
	io.Copy(f, resp.Body)
	f.Close()

	statusFn("Executando instalador (aceite o UAC)…")
	cmd := exec.Command(tmpFile, "/S") // /S = silencioso (NSIS)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("falha na instalação: %w", err)
	}
	os.Remove(tmpFile)
	statusFn("Nmap instalado com sucesso!")
	return nil
}

// ════════════════════════════════════════════════════════════════════════════
//  TEMPLATE HTML (idêntico ao original — mantido aqui para compilar)
// ════════════════════════════════════════════════════════════════════════════

const htmlTmpl = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ZeScan Pro — Auditoria Zebyte</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Helvetica,Arial,sans-serif;background:#f0f2f5;color:#1a1a1a;font-size:14px}
pre{white-space:pre-wrap;word-break:break-word;font-family:inherit}
.wrap{max-width:1100px;margin:0 auto;padding:28px 18px}
.header{background:#fff;border-radius:12px;padding:20px 28px;display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;border:1px solid #e0e0e0;border-bottom:4px solid #01579b}
.header h1{font-size:20px;font-weight:700;color:#01579b}.header p{font-size:12px;color:#666;margin-top:4px}.header img{height:60px}
.cards{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px;margin-bottom:20px}
.card{background:#f7f8f9;border-radius:10px;padding:16px 18px;border:1px solid #e8e8e8}
.card .lbl{font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px}
.card .val{font-size:26px;font-weight:700;color:#111}.card .sub{font-size:11px;color:#aaa;margin-top:3px}
.c-red{color:#b83232}.c-amb{color:#9a6800}.c-grn{color:#287048}
.sec{font-size:11px;font-weight:700;color:#888;text-transform:uppercase;letter-spacing:.07em;margin:24px 0 10px;padding-bottom:4px;border-bottom:1px solid #e8e8e8}
.ai-box{background:#f0f4ff;border:1px solid #c7d4f5;border-left:4px solid #3b5bdb;border-radius:8px;padding:14px 16px;margin-bottom:16px;font-size:13px;line-height:1.7;color:#2c3e6b}
.ai-badge{display:inline-block;background:#3b5bdb;color:#fff;font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;margin-bottom:8px}
.charts{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:4px}
.cbox{background:#fff;border-radius:10px;border:1px solid #e8e8e8;padding:18px}
.cbox .ct{font-size:11px;font-weight:700;color:#888;text-transform:uppercase;letter-spacing:.06em;margin-bottom:14px}
.cwrap{position:relative;height:190px}.cwrap-lg{position:relative;height:300px}
.tbl{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden;border:1px solid #e8e8e8}
.tbl th{font-size:11px;font-weight:700;color:#888;text-transform:uppercase;letter-spacing:.04em;padding:10px 12px;border-bottom:1px solid #eee;text-align:left;background:#fafafa}
.tbl td{padding:10px 12px;border-bottom:1px solid #f2f2f2;font-size:13px;vertical-align:top}
.tbl tr:last-child td{border-bottom:none}.tbl tr:hover td{background:#fafbff}
.tip{font-size:11px;color:#999;margin-top:2px}.mac{font-family:monospace;font-size:11px;color:#888;margin-top:2px}
.badge{display:inline-block;padding:2px 9px;border-radius:4px;font-size:11px;font-weight:700}
.b-red{background:#fde8e8;color:#b83232}.b-amb{background:#fef3d8;color:#9a6800}
.b-grn{background:#e4f5ea;color:#287048}.b-gry{background:#f0f0f0;color:#666}
.vitem{display:flex;gap:12px;align-items:flex-start;margin-bottom:10px;padding:12px 14px;background:#fff;border:1px solid #e8e8e8;border-radius:8px}
.vdot{width:9px;height:9px;border-radius:50%;margin-top:4px;flex-shrink:0}
.dh{background:#b83232}.dm{background:#b07010}.dl{background:#287048}
.vtitle{font-size:13px;font-weight:700;color:#111;margin-bottom:3px}.vdesc{font-size:12px;color:#555;line-height:1.6}
.ra-table{width:100%;border-collapse:collapse;font-size:12px;margin-top:8px}
.ra-table th{font-size:10px;font-weight:700;color:#999;text-transform:uppercase;padding:5px 8px;border-bottom:1px solid #eee;text-align:left;background:#fafafa}
.ra-table td{padding:6px 8px;border-bottom:1px solid #f5f5f5;vertical-align:top}
.ra-table tr:last-child td{border-bottom:none}
.ritem{padding:12px 14px;background:#fff;border:1px solid #e8e8e8;border-left:4px solid;border-radius:8px;margin-bottom:8px;font-size:13px;line-height:1.6;color:#333}
.rh{border-left-color:#b83232}.rm{border-left-color:#b07010}.rl{border-left-color:#287048}
.rlbl{font-size:11px;font-weight:700;margin-bottom:4px}
.rlbl.h{color:#b83232}.rlbl.m{color:#9a6800}.rlbl.l{color:#287048}
.footer{text-align:center;margin-top:32px;font-size:11px;color:#bbb;padding-top:16px;border-top:1px solid #e8e8e8}
@media(max-width:750px){.cards{grid-template-columns:repeat(2,1fr)}.charts{grid-template-columns:1fr}}
</style></head><body><div class="wrap">
<div class="header">
  <img src="logo.png" alt="Zebyte" onerror="this.style.display='none'">
  <div style="text-align:right"><h1>Auditoria de Infraestrutura de Rede</h1>
  <p><strong>ZeScan Pro v.1</strong> &nbsp;|&nbsp; Zebyte Consulting &nbsp;|&nbsp; {{.Data}} &nbsp;|&nbsp; {{.Duration}}</p></div>
</div>
<div class="cards">
  <div class="card"><div class="lbl">Hosts ativos</div><div class="val">{{.TotalHosts}}</div><div class="sub">na rede escaneada</div></div>
  <div class="card"><div class="lbl">Portas abertas</div><div class="val">{{.TotalOpen}}</div><div class="sub">em toda a rede</div></div>
  <div class="card"><div class="lbl">Score de risco</div><div class="val {{if eq .RiskLabel "Alto"}}c-red{{else if eq .RiskLabel "Médio"}}c-amb{{else}}c-grn{{end}}">{{.RiskLabel}}</div><div class="sub">avaliação geral</div></div>
  <div class="card"><div class="lbl">Com vulnerabilidades</div><div class="val c-red">{{.VulnCount}}</div><div class="sub">{{.SafeCount}} sem achados</div></div>
  <div class="card"><div class="lbl">Acesso remoto</div><div class="val {{if gt .RemoteAccessCount 0}}c-red{{else}}c-grn{{end}}">{{.RemoteAccessCount}}</div><div class="sub">portas expostas</div></div>
</div>
{{if .AIAnalysis}}<p class="sec">Análise executiva — IA</p><div class="ai-box"><div class="ai-badge">✦ ZeAI</div><p>{{.AIAnalysis}}</p></div>{{end}}
<p class="sec">Visão geral</p>
<div class="charts">
  <div class="cbox"><div class="ct">Hosts por risco</div><div class="cwrap"><canvas id="donutChart"></canvas></div></div>
  <div class="cbox"><div class="ct">Score por host (0–10)</div><div class="cwrap"><canvas id="barChart"></canvas></div></div>
</div>
<div class="charts" style="margin-top:14px">
  <div class="cbox"><div class="ct">Fabricantes (MAC vendor)</div><div class="cwrap-lg"><canvas id="vendorChart"></canvas></div></div>
  <div class="cbox"><div class="ct">Tipo de dispositivo</div><div class="cwrap-lg"><canvas id="vendorTypeChart"></canvas></div></div>
</div>
<p class="sec">Inventário de hosts</p>
<table class="tbl"><thead><tr><th>IP / MAC / Fabricante</th><th>Tipo</th><th>Sistema operacional</th><th>Portas abertas</th><th>Risco</th><th>Achados</th></tr></thead>
<tbody>{{range .Hosts}}<tr>
  <td><strong>{{.IP}}</strong>{{if .MAC}}<div class="mac">{{.MAC}}</div>{{end}}{{if .Hostname}}<div class="tip">{{.Hostname}}</div>{{end}}{{if .Vendor}}<div class="tip">🏭 {{.Vendor}}</div>{{end}}</td>
  <td><span style="font-size:20px;line-height:1">{{.DeviceIcon}}</span><div style="font-size:12px;font-weight:600;color:#333;margin-top:3px">{{.DeviceType}}</div></td>
  <td>{{if .OS}}{{.OS}}{{if .OSAcc}}<div class="tip">{{.OSAcc}}% correspondência</div>{{end}}{{else}}<span style="color:#bbb">Desconhecido</span>{{end}}</td>
  <td>{{if .OpenPorts}}{{range .OpenPorts}}<div>{{.Port}}/{{.Protocol}}{{if .Service}} — <span style="color:#555">{{.Service}}</span>{{end}}{{if .Product}} <span style="color:#999;font-size:11px">({{.Product}})</span>{{end}}</div>{{end}}{{else}}<span style="color:#bbb">Nenhuma</span>{{end}}</td>
  <td>{{if eq .RiskLevel "Alto"}}<span class="badge b-red">Alto</span>{{else if eq .RiskLevel "Médio"}}<span class="badge b-amb">Médio</span>{{else if eq .RiskLevel "Baixo"}}<span class="badge b-grn">Baixo</span>{{else}}<span class="badge b-gry">Info</span>{{end}}</td>
  <td>{{if .Findings}}{{range .Findings}}<div style="font-size:12px;color:#555;margin-bottom:2px">• {{.}}</div>{{end}}{{else}}<span style="color:#bbb">—</span>{{end}}</td>
</tr>{{end}}</tbody></table>
{{$hr := false}}{{range .Hosts}}{{if .RemoteFindings}}{{$hr = true}}{{end}}{{end}}
{{if $hr}}<p class="sec">Acesso remoto exposto</p>
{{range .Hosts}}{{if .RemoteFindings}}<div class="vitem" style="flex-direction:column;gap:8px">
  <div style="display:flex;align-items:center;gap:10px"><strong>{{.IP}}</strong>{{if .Hostname}}<span style="font-size:11px;color:#999">{{.Hostname}}</span>{{end}}<span class="badge b-red" style="margin-left:auto">{{len .RemoteFindings}} porta(s)</span></div>
  <table class="ra-table"><thead><tr><th>Porta</th><th>Serviço</th><th>Risco</th><th>Orientação</th></tr></thead><tbody>
  {{range .RemoteFindings}}<tr><td><code style="font-size:11px;background:#f5f5f5;padding:1px 5px;border-radius:3px">{{.Port}}</code></td><td><strong>{{.Name}}</strong></td><td><span class="badge {{.Badge}}">{{.Risk}}</span></td><td style="font-size:11px;color:#777">{{.Note}}</td></tr>{{end}}
  </tbody></table></div>{{end}}{{end}}{{end}}
{{if .Vulns}}<p class="sec">Vulnerabilidades</p>
{{range .Vulns}}<div class="vitem"><div class="vdot {{if eq .Severity "high"}}dh{{else if eq .Severity "med"}}dm{{else}}dl{{end}}"></div>
<div style="flex:1;min-width:0"><div class="vtitle">{{.Title}} <span style="font-size:11px;font-weight:400;color:#999">{{.IP}}:{{.Port}}</span></div><div class="vdesc"><pre>{{.Output}}</pre></div></div></div>{{end}}{{end}}
<p class="sec">Recomendações{{if .Recommendations}} — IA{{end}}</p>
{{if .Recommendations}}{{range .Recommendations}}<div class="ritem {{.CssClass}}"><div class="rlbl {{.LblClass}}">{{.Priority}} — {{.Timeframe}}</div>{{.Description}}</div>{{end}}
{{else}}
<div class="ritem rh"><div class="rlbl h">CRÍTICO — Imediato</div>Desabilitar debug em servidores web. Revisar ASP.NET e frameworks expostos.</div>
<div class="ritem rh"><div class="rlbl h">ALTO — Imediato</div>Configurar autenticação em RTSP e câmeras IP.</div>
<div class="ritem rm"><div class="rlbl m">MÉDIO — Curto prazo</div>Isolar dispositivos IoT em VLAN dedicada.</div>
<div class="ritem rl"><div class="rlbl l">BAIXO — Médio prazo</div>Agendar scans periódicos com OpenVAS e monitoramento com Zeek/Suricata.</div>
{{end}}
<div class="footer">ZeScan Pro v.1 &nbsp;|&nbsp; Zebyte Consulting &nbsp;|&nbsp; ZeAI &nbsp;|&nbsp; {{.Data}}</div>
</div>
<script>(function(){
  new Chart(document.getElementById('donutChart'),{type:'doughnut',data:{labels:{{.DonutLabels}},datasets:[{data:{{.DonutData}},backgroundColor:{{.DonutColors}},borderWidth:0,hoverOffset:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'bottom',labels:{font:{size:12},padding:14,boxWidth:12}}}}});
  new Chart(document.getElementById('barChart'),{type:'bar',data:{labels:{{.BarLabels}},datasets:[{label:'Score',data:{{.BarScores}},backgroundColor:{{.BarColors}},borderRadius:4,borderSkipped:false}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{y:{min:0,max:10,grid:{color:'rgba(0,0,0,0.06)'},ticks:{font:{size:11}}},x:{grid:{display:false},ticks:{font:{size:11}}}}}});
  function makePie(id,labels,data,colors,cutout){var cfg={type:cutout?'doughnut':'pie',data:{labels:labels,datasets:[{data:data,backgroundColor:colors,borderWidth:3,borderColor:'#fff',hoverOffset:8}]},options:{responsive:true,maintainAspectRatio:false,layout:{padding:8},plugins:{legend:{display:true,position:'bottom',labels:{font:{size:12},padding:12,boxWidth:14,generateLabels:function(chart){var d=chart.data;var total=d.datasets[0].data.reduce(function(a,b){return a+b;},0);return d.labels.map(function(label,i){var val=d.datasets[0].data[i];var pct=total>0?Math.round(val*100/total):0;return{text:label+' — '+val+' ('+pct+'%)',fillStyle:d.datasets[0].backgroundColor[i],strokeStyle:'#fff',lineWidth:2,index:i,hidden:false};});}}},tooltip:{callbacks:{label:function(ctx){var total=ctx.dataset.data.reduce(function(a,b){return a+b;},0);var pct=total>0?Math.round(ctx.parsed*100/total):0;return'  '+ctx.label+': '+ctx.parsed+' ('+pct+'%)';}}}}}};if(cutout)cfg.options.cutout='52%';new Chart(document.getElementById(id),cfg);}
  makePie('vendorChart',{{.VendorLabels}},{{.VendorCounts}},{{.VendorColors}},false);
  makePie('vendorTypeChart',{{.VendorTypeLabels}},{{.VendorTypePct}},{{.VendorTypeColors}},true);
})();</script></body></html>`

// ════════════════════════════════════════════════════════════════════════════
//  MAIN
// ════════════════════════════════════════════════════════════════════════════

func main() {
	a := app.New()

	// ── Verificação de licença ANTES de abrir a janela principal ─────────
	lic := CheckLicense()
	if !lic.Active {
		// Mostra janela de erro e sai
		w := a.NewWindow("ZeScan Pro — Licença")
		w.Resize(fyne.NewSize(480, 200))
		w.SetFixedSize(true)

		msg := widget.NewLabel(lic.Message)
		msg.Wrapping = fyne.TextWrapWord

		contactBtn := widget.NewButton("Contatar Zebyte Consulting", func() {
			u, _ := url.Parse("mailto:contato@zebyte.com.br?subject=Renovação ZeScan Pro")
			a.OpenURL(u)
		})

		w.SetContent(container.NewVBox(
			widget.NewLabel(""),
			container.NewCenter(widget.NewLabel("⛔  Licença Expirada ou Inválida")),
			widget.NewLabel(""),
			container.NewPadded(msg),
			widget.NewLabel(""),
			container.NewCenter(contactBtn),
		))
		w.ShowAndRun()
		return
	}
	
	// ── Janela principal ─────────────────────────────────────────────────
	w := a.NewWindow("ZeScan Pro v.1 — Auditoria Zebyte")
	w.Resize(fyne.NewSize(640, 620))

	logo := canvas.NewImageFromFile("logo.png")
	logo.FillMode = canvas.ImageFillContain
	logo.SetMinSize(fyne.NewSize(120, 90))

	// Banner de licença (dias restantes)
	licBanner := widget.NewLabel("🔑 " + lic.Message)
	licBanner.Importance = widget.WarningImportance

	inputRange := widget.NewEntry()
	inputRange.SetText("192.168.86.0/24")
	inputRange.SetPlaceHolder("ex: 192.168.1.0/24")

	inputAPIKey := widget.NewPasswordEntry()
	inputAPIKey.SetPlaceHolder("sk-ant-api03-… (opcional)")
	if saved, err := os.ReadFile(".apikey"); err == nil {
		inputAPIKey.SetText(strings.TrimSpace(string(saved)))
	}

	modeLabels := make([]string, len(scanModes))
	for i, m := range scanModes {
		modeLabels[i] = m.Label
	}
	selectedMode := 0
	modeSelect := widget.NewSelect(modeLabels, func(val string) {
		for i, m := range scanModes {
			if m.Label == val {
				selectedMode = i
			}
		}
	})
	modeSelect.SetSelected(modeLabels[0])
	modeDesc := widget.NewLabel("  → " + scanModes[0].Description)
	modeDesc.Wrapping = 3
	modeSelect.OnChanged = func(val string) {
		for i, m := range scanModes {
			if m.Label == val {
				selectedMode = i
				modeDesc.SetText("  → " + m.Description)
				modeDesc.Refresh()
			}
		}
	}

	status := widget.NewLabel("Status: Pronto")
	progress := widget.NewProgressBarInfinite()
	progress.Hide()

	btnScan := widget.NewButton("▶  Executar Auditoria", func() {
		// Revalida licença a cada scan
		lic2 := CheckLicense()
		if !lic2.Active {
			dialog.ShowError(fmt.Errorf(lic2.Message), w)
			return
		}

		target := inputRange.Text
		apiKey := strings.TrimSpace(inputAPIKey.Text)
		mode := scanModes[selectedMode]
		if apiKey != "" {
			os.WriteFile(".apikey", []byte(apiKey), 0600)
		}

		// Verifica / instala Nmap
		if !nmapInstalled() {
			if runtime.GOOS == "windows" {
				dialog.ShowConfirm("Nmap não encontrado",
					"O Nmap não está instalado.\nDeseja instalar automaticamente agora?",
					func(ok bool) {
						if !ok {
							return
						}
						progress.Show()
						progress.Refresh()
						go func() {
							err := installNmapWindows(func(msg string) {
								status.SetText(msg)
								status.Refresh()
							})
							if err != nil {
								status.SetText("Erro ao instalar Nmap: " + err.Error())
							} else {
								status.SetText("Nmap instalado! Clique em Executar novamente.")
							}
							progress.Hide()
							progress.Refresh()
						}()
					}, w)
			} else {
				dialog.ShowError(fmt.Errorf("Nmap não encontrado. Instale com: sudo apt install nmap"), w)
			}
			return
		}

		status.SetText("Iniciando [" + mode.Label + "]: " + target)
		progress.Show()
		progress.Refresh()

		go func() {
			start := time.Now()

			status.SetText("Nmap rodando [" + mode.Label + "]… aguarde")
			status.Refresh()
			extraPorts := remotePorts()
			args := mode.Args(target, extraPorts)
			cmd := exec.Command("nmap", args...) // Windows não precisa sudo
			if runtime.GOOS != "windows" {
				cmd = exec.Command("sudo", append([]string{"nmap"}, args...)...)
			}
			cmd.Run()
			duration := time.Since(start).Round(time.Second).String()

			status.SetText("Carregando base OUI…")
			status.Refresh()
			loadOUI(func(msg string) { status.SetText(msg); status.Refresh() })

			status.SetText("Processando resultados…")
			status.Refresh()
			rawXML, _ := os.ReadFile("relatorio_zebyte_completo.xml")
			var nmapRes NmapRun
			xml.Unmarshal(rawXML, &nmapRes)

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
				ip, vendor, mac := "", "", ""
				for _, addr := range h.Address {
					if addr.AddrType == "ipv4" && ip == "" {
						ip = addr.Addr
					}
					if addr.AddrType == "mac" {
						mac = addr.Addr
						if addr.Vendor != "" && vendor == "" {
							vendor = addr.Vendor
						}
					}
				}
				if vendor == "" && mac != "" {
					vendor = lookupMAC(mac)
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
						openPorts = append(openPorts, OpenPort{Port: p.PortId, Protocol: p.Protocol, Service: p.Service.Name, Product: p.Service.Product, Version: p.Service.Version})
					}
					for _, s := range p.Scripts {
						out := strings.TrimSpace(s.Output)
						if len(out) < 5 {
							continue
						}
						vulnEntries = append(vulnEntries, VulnEntry{Severity: vulnSeverity(s.Id, out), Title: s.Id, IP: ip, Port: p.PortId, Output: out})
					}
				}
				level, score, findings, remoteFindings := scoreHost(h.Ports)
				dc := classifyDevice(hostname, osName, vendor, openPorts)
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
					IP: ip, MAC: mac, Hostname: hostname, Vendor: vendor,
					OS: osName, OSAcc: osAcc, DeviceType: dc.Type, DeviceIcon: dc.Icon,
					OpenPorts: openPorts, RiskLevel: level, RiskScore: score,
					Findings: findings, RemoteFindings: remoteFindings, Lastboot: h.Uptime.Lastboot,
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
			donutLabels := []string{fmt.Sprintf("Alto (%d)", vulnCount), fmt.Sprintf("Médio (%d)", medCount), fmt.Sprintf("Limpo (%d)", safeCount)}
			donutData := []int{vulnCount, medCount, safeCount}
			donutColors := []string{"#b83232", "#b07010", "#287048"}

			var recommendations []AIRecommendation
			var aiAnalysis template.HTML
			if apiKey != "" {
				status.SetText("Consultando ZeAI… ✦")
				status.Refresh()
				recs, analysis, err := generateAIContent(apiKey, hostRows, vulnEntries)
				if err != nil {
					status.SetText("Aviso IA: " + err.Error())
				} else {
					recommendations = recs
					aiAnalysis = analysis
				}
			}

			vendorLabels, vendorCounts, vendorColors2,
				vendorTypeLabels, vendorTypePct, vendorTypeColors := buildVendorCharts(hostRows)

			remoteAccessCount := 0
			for _, hr := range hostRows {
				remoteAccessCount += len(hr.RemoteFindings)
			}

			rd := ReportData{
				Data: time.Now().Format("02/01/2006 15:04"), Duration: duration,
				TotalHosts: len(hostRows), TotalOpen: totalOpen,
				RiskLabel: overallRisk, VulnCount: vulnCount, SafeCount: safeCount, MedCount: medCount,
				RemoteAccessCount: remoteAccessCount, Hosts: hostRows, Vulns: vulnEntries,
				Recommendations: recommendations, AIAnalysis: aiAnalysis,
				VendorLabels: vendorLabels, VendorCounts: vendorCounts, VendorColors: vendorColors2,
				VendorTypeLabels: vendorTypeLabels, VendorTypePct: vendorTypePct, VendorTypeColors: vendorTypeColors,
				DonutLabels: jsArr(donutLabels), DonutData: jsIntArr(donutData), DonutColors: jsArr(donutColors),
				BarLabels: jsArr(barLabels), BarScores: jsIntArr(barScores), BarColors: jsArr(barColors),
			}

			outFile, err := os.Create("Relatorio_Final_Zebyte.html")
			if err == nil {
				tmpl := template.Must(template.New("report").Parse(htmlTmpl))
				tmpl.Execute(outFile, rd)
				outFile.Close()
			}

			status.SetText(fmt.Sprintf("✅ Concluído em %s! Relatório gerado.", duration))
			status.Refresh()
			progress.Hide()
			progress.Refresh()
		}()
	})

	btnView := widget.NewButton("🌐  Abrir Relatório no Browser", func() {
		pwd, _ := os.Getwd()
		u, _ := url.Parse("file://" + pwd + "/Relatorio_Final_Zebyte.html")
		a.OpenURL(u)
	})

	w.SetContent(container.NewVBox(
		logo,
		licBanner,
		widget.NewSeparator(),
		widget.NewLabel("Range de Destino:"),
		inputRange,
		widget.NewLabel("Chave API Anthropic (Claude):"),
		inputAPIKey,
		widget.NewLabel("Modo de Scan:"),
		modeSelect,
		modeDesc,
		status,
		progress,
		btnScan,
		btnView,
	))
	w.ShowAndRun()
	
}


// ════════════════════════════════════════════════════════════════════════════
//  SISTEMA DE LICENÇA TEMPORÁRIA (Zebyte Consulting)
// ════════════════════════════════════════════════════════════════════════════

type LicenseStatus struct {
	Active  bool
	Message string
}

func CheckLicense() LicenseStatus {
    // 1. DATA DE EXPIRAÇÃO: 28/03/2026 às 23:59
    expirationDate := time.Date(2026, time.March, 28, 23, 59, 59, 0, time.Local)
    
    // 2. CONSULTA HORA REAL (NTP) - Usando servidores do Google ou NTP.br
    // Tenta o Google primeiro, se falhar tenta o pool brasileiro
    currentTime, err := ntp.Time("time.google.com")
    if err != nil {
        currentTime, err = ntp.Time("a.st1.ntp.br")
    }

    // Se o cliente estiver SEM INTERNET, você decide: 
    // Bloquear (mais seguro) ou usar a hora local (mais permissivo)
    if err != nil {
        // Para a Zebyte, vamos ser rigorosos: Sem internet = Não abre (evita burla)
        return LicenseStatus{
            Active:  false, 
            Message: "Erro de conexão: O ZeScan Pro requer internet para validar a licença da Zebyte.",
        }
    }

    // 3. COMPARAÇÃO COM A HORA REAL
    if currentTime.After(expirationDate) {
        return LicenseStatus{
            Active:  false,
            Message: "⛔ Licença Expirada em " + expirationDate.Format("02/01/2006") + ". Contato: dilsinhu@zebyte.com.br",
        }
    }

    // 4. CÁLCULO DO TEMPO RESTANTE
    diff := expirationDate.Sub(currentTime)
    days := int(diff.Hours() / 24)
    hours := int(diff.Hours()) % 24

    return LicenseStatus{
        Active:  true,
        Message: fmt.Sprintf("Licença Zebyte [OK]: Expira em %d dias e %d horas", days, hours),
    }
}