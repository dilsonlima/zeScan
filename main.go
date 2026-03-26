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
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// ════════════════════════════════════════════════════════════════════════════
//  BANCO DE PORTAS DE ACESSO REMOTO
// ════════════════════════════════════════════════════════════════════════════

// RemoteAccessPort descreve um serviço de acesso remoto conhecido.
type RemoteAccessPort struct {
	Port     string
	Proto    string
	Name     string // nome amigável do serviço
	Risk     string // "CRÍTICO" | "ALTO" | "MÉDIO"
	Score    int    // pontos adicionados ao score do host
	Note     string // orientação de remediação
}

// remoteAccessDB mapeia número de porta → metadados de risco.
// Inclui: protocolos legados inseguros, ferramentas de acesso remoto comerciais
// e administrativas, VPNs, gestão out-of-band e serviços de tunelamento.
var remoteAccessDB = map[string]RemoteAccessPort{
	// ── Protocolos legados (sem criptografia) ─────────────────────────────
	"23":   {"23", "tcp", "Telnet", "CRÍTICO", 5, "Desabilitar imediatamente. Substituir por SSH. Credenciais trafegam em texto puro."},
	"512":  {"512", "tcp", "rexec", "CRÍTICO", 5, "Protocolo Unix remoto sem criptografia. Bloquear no firewall."},
	"513":  {"513", "tcp", "rlogin", "CRÍTICO", 5, "rlogin sem criptografia. Substituir por SSH."},
	"514":  {"514", "tcp", "rsh/syslog", "CRÍTICO", 5, "rsh sem autenticação forte. Bloquear ou restringir por IP."},
	"177":  {"177", "udp", "XDMCP", "CRÍTICO", 4, "Acesso remoto a desktop X11 sem criptografia. Desabilitar."},

	// ── SSH e variantes ───────────────────────────────────────────────────
	"22":   {"22", "tcp", "SSH", "MÉDIO", 1, "SSH padrão. Verificar versão, desabilitar root login e usar autenticação por chave."},
	"2222": {"2222", "tcp", "SSH alternativo", "MÉDIO", 2, "SSH em porta não-padrão. Confirmar se intencional; aplicar as mesmas boas práticas do SSH."},
	"22222":{"22222", "tcp", "SSH alternativo", "MÉDIO", 2, "SSH em porta não-padrão. Verificar configuração."},

	// ── RDP (Windows Remote Desktop) ─────────────────────────────────────
	"3389": {"3389", "tcp", "RDP (Windows)", "ALTO", 4, "RDP exposto. Risco de BlueKeep/DejaBlue se desatualizado. Restringir por IP, usar NLA e VPN."},
	"3390": {"3390", "tcp", "RDP alternativo", "ALTO", 4, "RDP em porta alternativa. Mesmas recomendações do 3389."},

	// ── VNC ───────────────────────────────────────────────────────────────
	"5900": {"5900", "tcp", "VNC", "ALTO", 4, "VNC sem criptografia nativa. Tunelizar via SSH ou VPN. Verificar se há senha configurada."},
	"5901": {"5901", "tcp", "VNC display :1", "ALTO", 4, "VNC exposto. Restringir acesso e tunelizar."},
	"5902": {"5902", "tcp", "VNC display :2", "ALTO", 4, "VNC exposto. Restringir acesso."},
	"5903": {"5903", "tcp", "VNC display :3", "ALTO", 3, "VNC exposto. Restringir acesso."},
	"5800": {"5800", "tcp", "VNC (web)", "ALTO", 3, "Interface web do VNC. Desabilitar se não utilizado."},

	// ── Ferramentas de acesso remoto comerciais ───────────────────────────
	"5938": {"5938", "tcp", "TeamViewer", "ALTO", 3, "TeamViewer detectado. Verificar se autorizado; manter atualizado (histórico de CVEs críticos)."},
	"7070": {"7070", "tcp", "AnyDesk / RealServer", "ALTO", 3, "Possível AnyDesk. Confirmar autorização e versão atualizada."},
	"6568": {"6568", "tcp", "AnyDesk", "ALTO", 3, "AnyDesk detectado. Verificar autorização e aplicar senha de acesso irrestrito."},
	"4899": {"4899", "tcp", "Radmin", "ALTO", 4, "Radmin exposto. Versões antigas têm vulnerabilidades críticas. Atualizar e restringir."},
	"1494": {"1494", "tcp", "Citrix ICA", "MÉDIO", 3, "Citrix ICA detectado. Verificar versão e patches (CVE-2019-19781 e similares)."},
	"2598": {"2598", "tcp", "Citrix CGP", "MÉDIO", 2, "Citrix Session Reliability. Restringir acesso externo."},

	// ── Gestão remota Windows ─────────────────────────────────────────────
	"5985": {"5985", "tcp", "WinRM HTTP", "ALTO", 4, "Windows Remote Management via HTTP. Desabilitar ou usar HTTPS (5986). Alvo comum de ataques."},
	"5986": {"5986", "tcp", "WinRM HTTPS", "MÉDIO", 2, "WinRM via HTTPS. Verificar certificado e restringir por IP."},
	"135":  {"135", "tcp", "MSRPC", "ALTO", 3, "Microsoft RPC. Frequentemente explorado (MS03-026, EternalBlue chain). Bloquear externamente."},
	"445":  {"445", "tcp", "SMB", "ALTO", 4, "SMB exposto. Risco de EternalBlue/WannaCry se desatualizado. Bloquear acesso externo imediatamente."},
	"139":  {"139", "tcp", "NetBIOS/SMB", "ALTO", 3, "NetBIOS-SSN. Vetor clássico de exploração Windows. Bloquear externamente."},

	// ── X11 forwarding ────────────────────────────────────────────────────
	"6000": {"6000", "tcp", "X11", "ALTO", 3, "X11 exposto diretamente. Permite captura de tela e keylogging remoto. Desabilitar ou tunelizar."},
	"6001": {"6001", "tcp", "X11 display :1", "ALTO", 3, "X11 exposto. Restringir imediatamente."},

	// ── Protocolos de gestão out-of-band ──────────────────────────────────
	"623":  {"623", "udp", "IPMI/BMC", "CRÍTICO", 5, "IPMI exposto. Vulnerabilidades críticas conhecidas (cipher 0, hash dump). Isolar em rede de gestão dedicada."},
	"664":  {"664", "tcp", "IPMI over LAN", "CRÍTICO", 4, "IPMI sobre LAN. Mesmas recomendações do 623."},

	// ── VPN e tunelamento ─────────────────────────────────────────────────
	"1194": {"1194", "udp", "OpenVPN", "MÉDIO", 1, "OpenVPN detectado. Verificar versão e configuração de autenticação."},
	"1723": {"1723", "tcp", "PPTP VPN", "ALTO", 3, "PPTP é considerado inseguro (MS-CHAPv2 quebrável). Migrar para OpenVPN, WireGuard ou IPsec."},
	"500":  {"500", "udp", "IPsec IKE", "MÉDIO", 1, "IPsec/IKE. Verificar algoritmos de criptografia configurados."},
	"1701": {"1701", "udp", "L2TP", "MÉDIO", 2, "L2TP sem IPsec é inseguro. Verificar se IPsec está habilitado."},
	"51820":{"51820", "udp", "WireGuard", "MÉDIO", 1, "WireGuard VPN. Protocolo moderno; verificar configuração de peers."},
	"4500": {"4500", "udp", "IPsec NAT-T", "MÉDIO", 1, "IPsec NAT Traversal. Normal em ambientes com NAT."},

	// ── Serviços de suporte remoto ────────────────────────────────────────
	"9090": {"9090", "tcp", "Cockpit Web", "MÉDIO", 2, "Cockpit (gestão Linux via web). Restringir acesso por IP."},
	"9100": {"9100", "tcp", "JetDirect/RAW print", "MÉDIO", 2, "Impressora com JetDirect. Pode expor documentos e permitir DoS."},
	"5631": {"5631", "tcp", "PCAnywhere", "CRÍTICO", 4, "Symantec pcAnywhere. Produto descontinuado com CVEs críticas. Desinstalar."},
	"5632": {"5632", "udp", "PCAnywhere", "CRÍTICO", 4, "Symantec pcAnywhere UDP. Desinstalar imediatamente."},
	"4444": {"4444", "tcp", "Metasploit/backdoor", "CRÍTICO", 6, "Porta 4444 associada a Metasploit e backdoors. Investigar imediatamente."},
	"1337": {"1337", "tcp", "Backdoor comum", "CRÍTICO", 6, "Porta associada a backdoors e RATs. Investigar imediatamente."},
	"31337":{"31337", "tcp", "Back Orifice", "CRÍTICO", 6, "Back Orifice / backdoor histórico. Investigar imediatamente."},

	// ── Gestão de rede ────────────────────────────────────────────────────
	"161":  {"161", "udp", "SNMP", "ALTO", 3, "SNMP v1/v2 usa community strings em texto puro. Migrar para SNMPv3 ou desabilitar."},
	"162":  {"162", "udp", "SNMP Trap", "MÉDIO", 2, "SNMP Trap receptor. Verificar versão e autenticação."},
}

// remotePorts retorna a lista de portas para o argumento -p do Nmap.
func remotePorts() string {
	ports := make([]string, 0, len(remoteAccessDB))
	seen := map[string]bool{}
	for p := range remoteAccessDB {
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	return strings.Join(ports, ",")
}

// ════════════════════════════════════════════════════════════════════════════
//  BASE OUI — MAC VENDOR LOOKUP (igual ao Angry IP Scanner)
// ════════════════════════════════════════════════════════════════════════════

// ouiDB é a base em memória: prefixo de 6 hex maiúsculos → nome do fabricante.
// Ex: "A477B3" → "Google LLC"
var ouiDB = map[string]string{}
var ouiLoaded = false

// ouiCacheFile é onde guardamos a base baixada para não baixar toda vez.
const ouiCacheFile = ".oui_cache.txt"

// ouiURL é a base oficial IEEE — ~4 MB, ~37.000 registros.
const ouiURL = "https://standards-oui.ieee.org/oui/oui.txt"

// loadOUI carrega a base OUI do cache local ou baixa do IEEE.
// Chame uma vez antes de processar os hosts.
func loadOUI(statusFn func(string)) {
	if ouiLoaded {
		return
	}

	// Tenta o cache local primeiro (arquivo atualizado há menos de 30 dias)
	if data, err := os.ReadFile(ouiCacheFile); err == nil {
		if info, err := os.Stat(ouiCacheFile); err == nil {
			age := time.Since(info.ModTime())
			if age < 30*24*time.Hour {
				parseOUI(data)
				statusFn(fmt.Sprintf("Base OUI carregada do cache (%d fabricantes)", len(ouiDB)))
				ouiLoaded = true
				return
			}
		}
	}

	// Baixa do IEEE
	statusFn("Baixando base OUI do IEEE (~4 MB)…")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(ouiURL)
	if err != nil {
		statusFn("Aviso: não foi possível baixar OUI — usando fallback embutido")
		loadOUIFallback()
		return
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		statusFn("Aviso: erro ao ler OUI — usando fallback embutido")
		loadOUIFallback()
		return
	}

	// Salva cache
	os.WriteFile(ouiCacheFile, data, 0644)
	parseOUI(data)
	statusFn(fmt.Sprintf("Base OUI atualizada do IEEE (%d fabricantes)", len(ouiDB)))
	ouiLoaded = true
}

// parseOUI analisa o formato texto do arquivo IEEE OUI.
// Cada registro tem uma linha como:
//   A4-77-33   (hex)   Google LLC
func parseOUI(data []byte) {
	ouiDB = make(map[string]string, 40000)
	for _, line := range strings.Split(string(data), "\n") {
		// Linhas de interesse têm "(hex)" no meio
		if !strings.Contains(line, "(hex)") {
			continue
		}
		// Formato: "AA-BB-CC   (hex)\t\tNome do Fabricante"
		parts := strings.SplitN(line, "(hex)", 2)
		if len(parts) != 2 {
			continue
		}
		// Normaliza prefixo: "AA-BB-CC" → "AABBCC"
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

// lookupMAC recebe um endereço MAC em qualquer formato e retorna o fabricante.
// Retorna string especial para MACs aleatórios de privacidade.
func lookupMAC(mac string) string {
	if mac == "" {
		return ""
	}
	// Normaliza: remove separadores e pega os primeiros 6 hex
	clean := strings.ToUpper(mac)
	clean = strings.NewReplacer(":", "", "-", "", ".", "").Replace(clean)
	if len(clean) < 6 {
		return ""
	}

	// Detecta MACs localmente administrados (bit U/L = 1 no segundo bit do 1º octeto)
	// Ex: 8E:xx, 0E:xx, 4E:xx, CE:xx, 02:xx, 06:xx, 0A:xx, ...
	// Esses são MACs aleatórios de privacidade (iOS, Android, Windows 10+)
	firstByte := clean[:2]
	val := uint64(0)
	fmt.Sscanf(firstByte, "%X", &val)
	if val&0x02 != 0 {
		return "(MAC aleatório — privacidade iOS/Android)"
	}

	prefix := clean[:6]
	if v, ok := ouiDB[prefix]; ok {
		return v
	}
	return ""
}

// loadOUIFallback carrega ~200 prefixos dos fabricantes mais comuns
// para o caso de não conseguir baixar do IEEE.
func loadOUIFallback() {
	ouiDB = map[string]string{
		// Apple
		"001451": "Apple Inc.", "003065": "Apple Inc.", "0017F2": "Apple Inc.",
		"001CB3": "Apple Inc.", "001E52": "Apple Inc.", "001EC2": "Apple Inc.",
		"002312": "Apple Inc.", "002500": "Apple Inc.", "00264B": "Apple Inc.",
		"003EE1": "Apple Inc.", "0050E4": "Apple Inc.",
		"006171": "Apple Inc.", "006D52": "Apple Inc.", "00C610": "Apple Inc.",
		"040CCE": "Apple Inc.", "0418B6": "Apple Inc.", "04488A": "Apple Inc.",
		"046D6F": "Apple Inc.", "04F7E4": "Apple Inc.", "085898": "Apple Inc.",
		"086698": "Apple Inc.", "0C1539": "Apple Inc.", "0C3E9F": "Apple Inc.",
		"0C4DE9": "Apple Inc.", "0C7725": "Apple Inc.", "0C771A": "Apple Inc.",
		"104FA8": "Apple Inc.", "109ADD": "Apple Inc.", "10DDB1": "Apple Inc.",
		"143692": "Apple Inc.", "14548C": "Apple Inc.", "14999E": "Apple Inc.",
		"189EFC": "Apple Inc.", "18E7F4": "Apple Inc.",
		"1C1AC0": "Apple Inc.", "1C36BB": "Apple Inc.", "1C5CF2": "Apple Inc.",
		"200DB0": "Apple Inc.", "20A2E4": "Apple Inc.", "20C9D0": "Apple Inc.",
		"243C20": "Apple Inc.", "244B03": "Apple Inc.", "247290": "Apple Inc.",
		"28CFE9": "Apple Inc.", "28E02C": "Apple Inc.", "2C1F23": "Apple Inc.",
		"2CF0A2": "Apple Inc.", "34159E": "Apple Inc.", "3451C9": "Apple Inc.",
		"3C0754": "Apple Inc.", "3C15C2": "Apple Inc.", "3CECEF": "Apple Inc.",
		"40331A": "Apple Inc.", "403004": "Apple Inc.", "40A6D9": "Apple Inc.",
		"40CBC0": "Apple Inc.", "440010": "Apple Inc.", "449A4B": "Apple Inc.",
		"48437C": "Apple Inc.", "485B39": "Apple Inc.", "48D705": "Apple Inc.",
		"4C57CA": "Apple Inc.", "4C74BF": "Apple Inc.", "4C8D79": "Apple Inc.",
		"50EAD6": "Apple Inc.", "543D37": "Apple Inc.", "54724F": "Apple Inc.",
		"544E90": "Apple Inc.", "54AE27": "Apple Inc.", "58404E": "Apple Inc.",
		"5855CA": "Apple Inc.", "5C5948": "Apple Inc.", "5C8D4E": "Apple Inc.",
		"5CF938": "Apple Inc.", "60334B": "Apple Inc.", "60F4F5": "Apple Inc.",
		"60FB42": "Apple Inc.", "64200C": "Apple Inc.", "6476BA": "Apple Inc.",
		"6887C3": "Apple Inc.", "6C4008": "Apple Inc.", "6C709F": "Apple Inc.",
		"6C8DC1": "Apple Inc.", "6CB7F4": "Apple Inc.", "70700D": "Apple Inc.",
		"7048F7": "Apple Inc.", "709C28": "Apple Inc.", "70DE01": "Apple Inc.",
		"7831C1": "Apple Inc.", "788C54": "Apple Inc.", "78CA39": "Apple Inc.",
		"78D75F": "Apple Inc.", "78FD94": "Apple Inc.", "7C011B": "Apple Inc.",
		"7C6D62": "Apple Inc.", "7CD1C3": "Apple Inc.", "80006E": "Apple Inc.",
		"80BE05": "Apple Inc.", "80E650": "Apple Inc.", "840D8E": "Apple Inc.",
		"842299": "Apple Inc.", "845B12": "Apple Inc.", "848506": "Apple Inc.",
		"88C663": "Apple Inc.", "8C2DAA": "Apple Inc.", "8C7C92": "Apple Inc.",
		"8C8590": "Apple Inc.", "90B21F": "Apple Inc.", "90C1C6": "Apple Inc.",
		"903C92": "Apple Inc.", "9027E4": "Apple Inc.", "940C6D": "Apple Inc.",
		"94E96A": "Apple Inc.", "9801A7": "Apple Inc.", "984B4A": "Apple Inc.",
		"9C04EB": "Apple Inc.", "9C207B": "Apple Inc.", "9CF387": "Apple Inc.",
		"A036BC": "Apple Inc.", "A06F76": "Apple Inc.", "A0999B": "Apple Inc.",
		"A4B197": "Apple Inc.", "A4C361": "Apple Inc.", "A4D18C": "Apple Inc.",
		"A4F1E8": "Apple Inc.", "A82066": "Apple Inc.", "A8667F": "Apple Inc.",
		"A8863D": "Apple Inc.", "A88895": "Apple Inc.", "AC293A": "Apple Inc.",
		"ACE433": "Apple Inc.", "ACF6F6": "Apple Inc.", "B03495": "Apple Inc.",
		"B065BD": "Apple Inc.", "B0702D": "Apple Inc.", "B418D1": "Apple Inc.",
		"B44BD2": "Apple Inc.", "B4F0AB": "Apple Inc.", "B8098A": "Apple Inc.",
		"B81FBA": "Apple Inc.", "B88D12": "Apple Inc.", "B8C75D": "Apple Inc.",
		"BC3BAF": "Apple Inc.", "BC4CC4": "Apple Inc.", "BC52B7": "Apple Inc.",
		"BC6778": "Apple Inc.", "C02573": "Apple Inc.", "C06347": "Apple Inc.",
		"C08997": "Apple Inc.", "C419D1": "Apple Inc.", "C42C03": "Apple Inc.",
		"C4618B": "Apple Inc.", "C47880": "Apple Inc.", "C82A14": "Apple Inc.",
		"C8BCC8": "Apple Inc.", "C8E0EB": "Apple Inc.", "CC08E0": "Apple Inc.",
		"CC29F5": "Apple Inc.", "D02708": "Apple Inc.", "D04F7E": "Apple Inc.",
		"D0A637": "Apple Inc.", "D421DF": "Apple Inc.", "D49A20": "Apple Inc.",
		"D4DCCD": "Apple Inc.", "D8004D": "Apple Inc.", "D83134": "Apple Inc.",
		"D8CF9C": "Apple Inc.", "DC0C5C": "Apple Inc.", "DC2B2A": "Apple Inc.",
		"DCA904": "Apple Inc.", "E0B52D": "Apple Inc.", "E0C767": "Apple Inc.",
		"E0F5C6": "Apple Inc.", "E43A5A": "Apple Inc.", "E49261": "Apple Inc.",
		"E4C63D": "Apple Inc.", "E4E0C5": "Apple Inc.", "E80688": "Apple Inc.",
		"E89C25": "Apple Inc.", "E8B2AC": "Apple Inc.", "EC3586": "Apple Inc.",
		"ECF4BB": "Apple Inc.", "F04F7C": "Apple Inc.",
		"F0D1A9": "Apple Inc.", "F41BA1": "Apple Inc.", "F45C89": "Apple Inc.",
		"F4F15A": "Apple Inc.", "F82793": "Apple Inc.",
		"FCFC48": "Apple Inc.", "FCFBFB": "Apple Inc.",
		// Google
		"3C5AB4": "Google LLC", "A477B3": "Google LLC", "A477B5": "Google LLC",
		"00E04C": "Google LLC", "F88FCA": "Google LLC", "54607E": "Google LLC",
		"D83060": "Google LLC", "20DF3B": "Google LLC", "40F407": "Google LLC",
		"B0E0D9": "Google LLC", "00F110": "Google LLC",
		// Samsung
		"002339": "Samsung Electronics", "0023D7": "Samsung Electronics",
		"0024E9": "Samsung Electronics", "002566": "Samsung Electronics",
		"0026E2": "Samsung Electronics", "002836": "Samsung Electronics",
		"00E3B2": "Samsung Electronics", "040ECE": "Samsung Electronics",
		"0416B9": "Samsung Electronics", "04FE31": "Samsung Electronics",
		"08002E": "Samsung Electronics", "08D4D1": "Samsung Electronics",
		"0CF145": "Samsung Electronics", "10D542": "Samsung Electronics",
		"147590": "Samsung Electronics", "18AF61": "Samsung Electronics",
		"200476": "Samsung Electronics", "204EF6": "Samsung Electronics",
		"240528": "Samsung Electronics", "2C0E3D": "Samsung Electronics",
		"2C4404": "Samsung Electronics", "2CFDE2": "Samsung Electronics",
		"30C5D8": "Samsung Electronics", "34145F": "Samsung Electronics",
		"3471C8": "Samsung Electronics", "380195": "Samsung Electronics",
		"3CB87A": "Samsung Electronics", "40B076": "Samsung Electronics",
		"441316": "Samsung Electronics", "44A742": "Samsung Electronics",
		"487805": "Samsung Electronics", "48A1D2": "Samsung Electronics",
		"4C3C16": "Samsung Electronics", "4CACF6": "Samsung Electronics",
		"5001BB": "Samsung Electronics", "500578": "Samsung Electronics",
		"5056BF": "Samsung Electronics", "5475D0": "Samsung Electronics",
		"5C3D5E": "Samsung Electronics", "5C6678": "Samsung Electronics",
		"6006E6": "Samsung Electronics", "60A10A": "Samsung Electronics",
		"6CA86B": "Samsung Electronics", "6CB8FE": "Samsung Electronics",
		"708319": "Samsung Electronics", "74458A": "Samsung Electronics",
		"745232": "Samsung Electronics", "7825AD": "Samsung Electronics",
		"785132": "Samsung Electronics", "7CEF07": "Samsung Electronics",
		"80652D": "Samsung Electronics", "8099B4": "Samsung Electronics",
		"80B6FC": "Samsung Electronics", "840B2D": "Samsung Electronics",
		"88329B": "Samsung Electronics", "883206": "Samsung Electronics",
		"8CB4D4": "Samsung Electronics", "8CC8CD": "Samsung Electronics",
		"9007F1": "Samsung Electronics", "903469": "Samsung Electronics",
		"944DFB": "Samsung Electronics", "9861DF": "Samsung Electronics",
		"9C0298": "Samsung Electronics", "9C02B2": "Samsung Electronics",
		"A04299": "Samsung Electronics", "A0821F": "Samsung Electronics",
		"A04060": "Samsung Electronics", "A40CDB": "Samsung Electronics",
		"A8B6D2": "Samsung Electronics", "AC5A14": "Samsung Electronics",
		"B047BF": "Samsung Electronics", "B0C4E7": "Samsung Electronics",
		"B4EF39": "Samsung Electronics", "B827EB": "Samsung Electronics",
		"BC20A4": "Samsung Electronics", "BC7EEA": "Samsung Electronics",
		"C01173": "Samsung Electronics", "C0BDD1": "Samsung Electronics",
		"C45006": "Samsung Electronics", "C86527": "Samsung Electronics",
		"CCA26B": "Samsung Electronics", "CCF9E8": "Samsung Electronics",
		"D021F9": "Samsung Electronics", "D0176A": "Samsung Electronics",
		"D087E2": "Samsung Electronics", "D4E8B2": "Samsung Electronics",
		"DC7144": "Samsung Electronics", "E09892": "Samsung Electronics",
		"E0CB4E": "Samsung Electronics", "E493D2": "Samsung Electronics",
		"E8039A": "Samsung Electronics", "E8508B": "Samsung Electronics",
		"ECC04B": "Samsung Electronics", "F025B7": "Samsung Electronics",
		"F0E77E": "Samsung Electronics", "F47B5E": "Samsung Electronics",
		"F4F5DB": "Samsung Electronics", "F8D0AC": "Samsung Electronics",
		"FC19DE": "Samsung Electronics",
		// Cisco
		"000142": "Cisco Systems", "000143": "Cisco Systems", "0001C7": "Cisco Systems",
		"000201": "Cisco Systems", "000296": "Cisco Systems", "0002B9": "Cisco Systems",
		"0002FC": "Cisco Systems", "000334": "Cisco Systems", "0003FD": "Cisco Systems",
		"000476": "Cisco Systems", "0004C0": "Cisco Systems", "000501": "Cisco Systems",
		"00059A": "Cisco Systems", "0005DC": "Cisco Systems", "000602": "Cisco Systems",
		"00062F": "Cisco Systems", "0006D6": "Cisco Systems", "000742": "Cisco Systems",
		"00079E": "Cisco Systems", "0007B3": "Cisco Systems", "0007EB": "Cisco Systems",
		"000801": "Cisco Systems", "000866": "Cisco Systems", "0008A3": "Cisco Systems",
		"0008E2": "Cisco Systems", "0009B0": "Cisco Systems", "001279": "Cisco Systems",
		"001A2B": "Cisco Systems", "001DA2": "Cisco Systems", "001E13": "Cisco Systems",
		"0021D8": "Cisco Systems", "00236C": "Cisco Systems", "002499": "Cisco Systems",
		"0025B4": "Cisco Systems", "0026CB": "Cisco Systems",
		"002738": "Cisco Systems", "002797": "Cisco Systems",
		"58AC78": "Cisco Systems", "6872AC": "Cisco Systems", "885A92": "Cisco Systems",
		"9CADF4": "Cisco Systems", "A4935E": "Cisco Systems", "B8AFCE": "Cisco Systems",
		"D072DC": "Cisco Systems", "DC8C37": "Cisco Systems", "E84F25": "Cisco Systems",
		"F07F06": "Cisco Systems", "F49CA1": "Cisco Systems", "F8A5C5": "Cisco Systems",
		// TP-Link
		"000AEB": "TP-Link Technologies", "001D0F": "TP-Link Technologies",
		"002268": "TP-Link Technologies", "0025D0": "TP-Link Technologies",
		"0027E3": "TP-Link Technologies", "30B49E": "TP-Link Technologies",
		"50C7BF": "TP-Link Technologies", "5479CD": "TP-Link Technologies",
		"6062BE": "TP-Link Technologies", "644DB3": "TP-Link Technologies",
		"686A44": "TP-Link Technologies", "74DA88": "TP-Link Technologies",
		"80CC9C": "TP-Link Technologies", "8C4DEB": "TP-Link Technologies",
		"90F652": "TP-Link Technologies", "A0F3C1": "TP-Link Technologies",
		"B0487A": "TP-Link Technologies", "B4B024": "TP-Link Technologies",
		"C07E91": "TP-Link Technologies", "C46E1F": "TP-Link Technologies",
		"D86095": "TP-Link Technologies", "DC9FAB": "TP-Link Technologies",
		"E00EDA": "TP-Link Technologies", "E84DCC": "TP-Link Technologies",
		"EC086B": "TP-Link Technologies", "F46D04": "TP-Link Technologies",
		"F4F26D": "TP-Link Technologies", "F8D111": "TP-Link Technologies",
		"F4FC49": "TP-Link Technologies", "AC8C46": "TP-Link Technologies",
		"4472AC": "Hangzhou Hikvision",   // prefixo do DVR do scan real
		"8EB53D": "Espressif Systems",    // ESP32/ESP8266 (IoT)
		"025B2B": "Apple Inc.",           // iOS do scan original
		// Intel
		"000F35": "Intel Corporate", "001101": "Intel Corporate", "001150": "Intel Corporate",
		"0011D8": "Intel Corporate", "001302": "Intel Corporate", "001320": "Intel Corporate",
		"00135E": "Intel Corporate", "001374": "Intel Corporate", "00137F": "Intel Corporate",
		"001438": "Intel Corporate", "0015A8": "Intel Corporate", "001600": "Intel Corporate",
		"00166F": "Intel Corporate", "001676": "Intel Corporate", "0016EA": "Intel Corporate",
		"0016EB": "Intel Corporate", "001731": "Intel Corporate", "0017C4": "Intel Corporate",
		"001894": "Intel Corporate", "0019D1": "Intel Corporate", "001A22": "Intel Corporate",
		"001A6B": "Intel Corporate", "001B21": "Intel Corporate", "001B77": "Intel Corporate",
		"001C12": "Intel Corporate", "001CB8": "Intel Corporate", "001D92": "Intel Corporate",
		"001DE0": "Intel Corporate", "001DE1": "Intel Corporate", "001EE3": "Intel Corporate",
		"001F3B": "Intel Corporate", "001FE1": "Intel Corporate", "001FE2": "Intel Corporate",
		"002060": "Intel Corporate", "002191": "Intel Corporate", "0021CE": "Intel Corporate",
		"002261": "Intel Corporate", "0023A1": "Intel Corporate",
		"002414": "Intel Corporate", "00247B": "Intel Corporate", "0024D6": "Intel Corporate",
		"002548": "Intel Corporate", "002564": "Intel Corporate", "0025D3": "Intel Corporate",
		"002600": "Intel Corporate", "00261A": "Intel Corporate", "00264A": "Intel Corporate",
		"002676": "Intel Corporate", "002689": "Intel Corporate", "0026B9": "Intel Corporate",
		"0026C6": "Intel Corporate", "002723": "Intel Corporate", "002741": "Intel Corporate",
		"40251B": "Intel Corporate", "4062BF": "Intel Corporate", "48A2E6": "Intel Corporate",
		"4C3488": "Intel Corporate", "5CF370": "Intel Corporate", "5CF951": "Intel Corporate",
		"60674E": "Intel Corporate", "60F67E": "Intel Corporate", "645110": "Intel Corporate",
		"68A3C4": "Intel Corporate", "6C2901": "Intel Corporate", "6C887B": "Intel Corporate",
		"70856C": "Intel Corporate", "7483C2": "Intel Corporate", "80861B": "Intel Corporate",
		"84699A": "Intel Corporate", "8C70DF": "Intel Corporate", "98E743": "Intel Corporate",
		"A0880D": "Intel Corporate", "A4C3F0": "Intel Corporate", "A4344B": "Intel Corporate",
		"B8763F": "Intel Corporate", "C0CB38": "Intel Corporate", "C47E19": "Intel Corporate",
		"E88D28": "Intel Corporate",
		// Amazon
		"0002BE": "Amazon Technologies", "001A4C": "Amazon Technologies",
		"6477B7": "Amazon Technologies", "68370B": "Amazon Technologies",
		"74C246": "Amazon Technologies",
		"7C612C": "Amazon Technologies", "84D6D0": "Amazon Technologies",
		"A002DC": "Amazon Technologies", "A43149": "Amazon Technologies",
		"B47C9C": "Amazon Technologies", "B8D812": "Amazon Technologies",
		"FC6516": "Amazon Technologies", "FC65DE": "Amazon Technologies",
		// Netgear
		"001B2F": "Netgear", "00146C": "Netgear", "001E2A": "Netgear",
		"001F33": "Netgear", "002196": "Netgear", "002275": "Netgear",
		"00224D": "Netgear", "00265A": "Netgear", "203095": "Netgear",
		"281F EF": "Netgear", "28C68E": "Netgear", "30469A": "Netgear",
		"3895DB": "Netgear", "404A03": "Netgear", "44941A": "Netgear",
		"4CE675": "Netgear", "6CB0CE": "Netgear", "744401": "Netgear",
		"8FFFFF": "Netgear", "9C3DCF": "Netgear", "A021B7": "Netgear",
		"C03F0E": "Netgear", "E091F5": "Netgear",
		// Ubiquiti
		"002722": "Ubiquiti Networks", "04189A": "Ubiquiti Networks",
		"0418D6": "Ubiquiti Networks", "044259": "Ubiquiti Networks",
		"0861DF": "Ubiquiti Networks", "18E829": "Ubiquiti Networks",
		"24A43C": "Ubiquiti Networks", "44D9E7": "Ubiquiti Networks",
		"4C5E0C": "Ubiquiti Networks", "687278": "Ubiquiti Networks",
		"6C3B6B": "Ubiquiti Networks", "788A20": "Ubiquiti Networks",
		"80AA9B": "Ubiquiti Networks", "98DA38": "Ubiquiti Networks",
		"9C0524": "Ubiquiti Networks", "B4FBE4": "Ubiquiti Networks",
		"DC9FDB": "Ubiquiti Networks", "E063DA": "Ubiquiti Networks",
		"F09FC2": "Ubiquiti Networks", "F4E2C6": "Ubiquiti Networks",
		"F80E13": "Ubiquiti Networks", "FCECDA": "Ubiquiti Networks",
		// Raspberry Pi
		"28CDA4": "Raspberry Pi Foundation", "2CCF67": "Raspberry Pi Foundation",
		"D83ADD": "Raspberry Pi Foundation",
		"DCA632": "Raspberry Pi Foundation", "E45F01": "Raspberry Pi Foundation",
		// VMware
		"000569": "VMware Inc.", "000C29": "VMware Inc.", "001C14": "VMware Inc.",
		"005056": "VMware Inc.",
		// Hikvision
		"283B82": "Hikvision Digital", "4C5099": "Hikvision Digital",
		"546BEB": "Hikvision Digital", "8CE748": "Hikvision Digital",
		"B4A3B8": "Hikvision Digital", "C8BD26": "Hikvision Digital",
		"E4C93C": "Hikvision Digital",
		// Dahua
		"1C622E": "Dahua Technology", "34C939": "Dahua Technology",
		"5E2A01": "Dahua Technology", "70850C": "Dahua Technology",
		"90E6BA": "Dahua Technology", "A4AE11": "Dahua Technology",
		// Huawei
		"001882": "Huawei Technologies", "001E10": "Huawei Technologies",
		"002568": "Huawei Technologies", "0025AB": "Huawei Technologies",
		"0025D4": "Huawei Technologies", "002599": "Huawei Technologies",
		"0026D6": "Huawei Technologies", "002721": "Huawei Technologies",
		"00259E": "Huawei Technologies", "0028F8": "Huawei Technologies",
		"286ED4": "Huawei Technologies", "30D17E": "Huawei Technologies",
		"34DBFD": "Huawei Technologies", "38B1DB": "Huawei Technologies",
		"3C4A92": "Huawei Technologies", "40CB A8": "Huawei Technologies",
		"48C5B5": "Huawei Technologies", "4CA7B8": "Huawei Technologies",
		"54BE53": "Huawei Technologies", "5C4CA9": "Huawei Technologies",
		"5C5EC7": "Huawei Technologies", "68A028": "Huawei Technologies",
		"78EB14": "Huawei Technologies", "8C34FD": "Huawei Technologies",
		"9C37F4": "Huawei Technologies", "A845DC": "Huawei Technologies",
		"B8BC1B": "Huawei Technologies", "C82B96": "Huawei Technologies",
		"CC536E": "Huawei Technologies", "D46A6A": "Huawei Technologies",
		"D4B113": "Huawei Technologies", "D4F9A1": "Huawei Technologies",
		"DCEE06": "Huawei Technologies", "E082A0": "Huawei Technologies",
		"E0ECC0": "Huawei Technologies", "ECE63E": "Huawei Technologies",
		"F44290": "Huawei Technologies", "F44C7F": "Huawei Technologies",
		"F4DC7A": "Huawei Technologies", "F8A45F": "Huawei Technologies",
		// Dell
		"001143": "Dell Inc.", "00145E": "Dell Inc.",
		"001E4F": "Dell Inc.", "00219B": "Dell Inc.", "00236F": "Dell Inc.",
		"0024E8": "Dell Inc.", "00265E": "Dell Inc.", "B083FE": "Dell Inc.",
		"B0FBEF": "Dell Inc.", "C8F750": "Dell Inc.", "D4AE52": "Dell Inc.",
		"EC9A74": "Dell Inc.", "F04DA2": "Dell Inc.", "F48E38": "Dell Inc.",
		// HP / HPE
		"001560": "HP Inc.", "001708": "HP Inc.", "001A4B": "HP Inc.",
		"001B78": "HP Inc.", "001CC4": "HP Inc.", "001E0B": "HP Inc.",
		"001FE6": "HP Inc.", "002182": "HP Inc.", "0023C9": "HP Inc.",
		"002655": "HP Inc.", "0026F2": "HP Inc.", "00273D": "HP Inc.",
		"001635": "Hewlett Packard", "001CC0": "Hewlett Packard",
		"002129": "Hewlett Packard", "00248C": "Hewlett Packard",
		// MikroTik
		"004E07": "MikroTik", "18FD74": "MikroTik", "2CC8D3": "MikroTik",
		"48A98A": "MikroTik", 
		"74AD4B": "MikroTik", "B8DE53": "MikroTik", "CC2D E0": "MikroTik",
		"D4CA6D": "MikroTik", "DC2C6E": "MikroTik", "E48D8C": "MikroTik",
		// Xiaomi
		"0C1DBF": "Xiaomi Communications", "106F3F": "Xiaomi Communications",
		"14F65A": "Xiaomi Communications", "18598B": "Xiaomi Communications",
		"20286B": "Xiaomi Communications", "28E31F": "Xiaomi Communications",
		"34805E": "Xiaomi Communications", "38A4ED": "Xiaomi Communications",
		"58443F": "Xiaomi Communications", "5C828A": "Xiaomi Communications",
		"64B473": "Xiaomi Communications", "64CC2E": "Xiaomi Communications",
		"6C5AB0": "Xiaomi Communications", "74051B": "Xiaomi Communications",
		"7801B2": "Xiaomi Communications", "8CBEBE": "Xiaomi Communications",
		"98FAE3": "Xiaomi Communications", "9CB7C8": "Xiaomi Communications",
		"A086C6": "Xiaomi Communications", "A0CB4B": "Xiaomi Communications",
		"AC1749": "Xiaomi Communications", "B0E235": "Xiaomi Communications",
		"C89B4C": "Xiaomi Communications", "F0B429": "Xiaomi Communications",
		"F48B32": "Xiaomi Communications",
	}
	ouiLoaded = true
}



type NmapRun struct {
	Hosts     []NmapHost `xml:"host"`
	HostHints []struct {
		Address []struct {
			Addr     string `xml:"addr,attr"`
			AddrType string `xml:"addrtype,attr"`
		} `xml:"address"`
	} `xml:"hosthint"`
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

// ════════════════════════════════════════════════════════════════════════════
//  ESTRUTURAS DO TEMPLATE
// ════════════════════════════════════════════════════════════════════════════

type HostRow struct {
	IP             string
	MAC            string // endereço físico completo
	Hostname       string
	Vendor         string
	OS             string
	OSAcc          string
	OpenPorts      []OpenPort
	RiskLevel      string
	RiskScore      int
	Findings       []string
	RemoteFindings []RemoteFinding // portas de acesso remoto detectadas
	Lastboot       string
}

// RemoteFinding representa uma porta de acesso remoto encontrada aberta.
type RemoteFinding struct {
	Port  string
	Name  string
	Risk  string
	Note  string
	Badge string // classe CSS do badge
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

// Recomendação gerada pela IA
type AIRecommendation struct {
	Priority    string // "CRÍTICO" | "ALTO" | "MÉDIO" | "BAIXO"
	CssClass    string // "rh" | "rm" | "rl"
	LblClass    string // "h"  | "m"  | "l"
	Timeframe   string // ex: "Ação imediata"
	Description string
}

type ReportData struct {
	Data            string
	Duration        string
	TotalHosts      int
	TotalOpen       int
	RiskLabel       string
	VulnCount       int
	SafeCount       int
	MedCount        int
	Hosts           []HostRow
	Vulns           []VulnEntry
	Recommendations []AIRecommendation
	AIAnalysis      template.HTML
	RemoteAccessCount int   // total de portas de acesso remoto encontradas
	// Gráficos de fabricantes (MAC vendor)
	VendorLabels     template.JS // ex: ["Apple","Google","Desconhecido"]
	VendorCounts     template.JS // ex: [3,1,2]
	VendorColors     template.JS
	VendorTypeLabels template.JS // ex: ["Mobile/IoT","Infraestrutura","Desconhecido"]
	VendorTypePct    template.JS // ex: [50,17,33]
	VendorTypeColors template.JS
	DonutLabels     template.JS
	DonutData       template.JS
	DonutColors     template.JS
	BarLabels       template.JS
	BarScores       template.JS
	BarColors       template.JS
}

// ════════════════════════════════════════════════════════════════════════════
//  CLIENTE ANTHROPIC
// ════════════════════════════════════════════════════════════════════════════

const anthropicAPI = "https://api.anthropic.com/v1/messages"
const anthropicModel = "claude-haiku-4-5-20251001" // rápido e barato para relatórios

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
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// callClaude envia um prompt para a API e retorna o texto da resposta.
func callClaude(apiKey, systemPrompt, userPrompt string) (string, error) {
	reqBody := anthropicRequest{
		Model:     anthropicModel,
		MaxTokens: 2048,
		System:    systemPrompt,
		Messages: []anthropicMessage{
			{Role: "user", Content: userPrompt},
		},
	}

	b, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", anthropicAPI, bytes.NewReader(b))
	if err != nil {
		return "", err
	}
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
	if err := json.Unmarshal(body, &ar); err != nil {
		return "", err
	}
	if ar.Error != nil {
		return "", fmt.Errorf("API error: %s", ar.Error.Message)
	}
	if len(ar.Content) == 0 {
		return "", fmt.Errorf("resposta vazia da API")
	}
	return ar.Content[0].Text, nil
}

// buildScanSummary converte os dados do scan em texto estruturado para o prompt.
func buildScanSummary(hosts []HostRow, vulns []VulnEntry) string {
	var sb strings.Builder
	sb.WriteString("=== RESUMO DO SCAN NMAP ===\n\n")

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
		sb.WriteString(fmt.Sprintf("  Risco calculado: %s (score %d)\n", h.RiskLevel, h.RiskScore))
		if len(h.OpenPorts) > 0 {
			sb.WriteString("  Portas abertas:\n")
			for _, p := range h.OpenPorts {
				sb.WriteString(fmt.Sprintf("    - %s/%s %s %s %s\n",
					p.Port, p.Protocol, p.Service, p.Product, p.Version))
			}
		}
		if len(h.Findings) > 0 {
			sb.WriteString("  Achados do scan:\n")
			for _, f := range h.Findings {
				sb.WriteString(fmt.Sprintf("    * %s\n", f))
			}
		}
		sb.WriteString("\n")
	}

	if len(vulns) > 0 {
		sb.WriteString("=== DETALHES DE VULNERABILIDADES ===\n\n")
		// Limita para não estourar o contexto da API
		count := len(vulns)
		if count > 20 {
			count = 20
		}
		for _, v := range vulns[:count] {
			sb.WriteString(fmt.Sprintf("Script: %s | IP: %s | Porta: %s | Severidade: %s\n",
				v.Title, v.IP, v.Port, v.Severity))
			out := v.Output
			if len(out) > 300 {
				out = out[:300] + "…"
			}
			sb.WriteString(fmt.Sprintf("Output: %s\n\n", out))
		}
	}

	return sb.String()
}

// parseAIRecommendations converte a resposta JSON da IA em structs prontas para o template.
func parseAIRecommendations(jsonText string) ([]AIRecommendation, error) {
	// A IA retorna um JSON array; extraímos mesmo se vier com markdown fences
	clean := strings.TrimSpace(jsonText)
	if idx := strings.Index(clean, "["); idx >= 0 {
		clean = clean[idx:]
	}
	if idx := strings.LastIndex(clean, "]"); idx >= 0 {
		clean = clean[:idx+1]
	}

	var raw []struct {
		Priority    string `json:"priority"`
		Timeframe   string `json:"timeframe"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal([]byte(clean), &raw); err != nil {
		return nil, err
	}

	cssMap := map[string]string{
		"CRÍTICO": "rh", "ALTO": "rh", "MÉDIO": "rm", "BAIXO": "rl",
	}
	lblMap := map[string]string{
		"CRÍTICO": "h", "ALTO": "h", "MÉDIO": "m", "BAIXO": "l",
	}

	var recs []AIRecommendation
	for _, r := range raw {
		p := strings.ToUpper(strings.TrimSpace(r.Priority))
		css, ok := cssMap[p]
		if !ok {
			css = "rl"
		}
		lbl, ok := lblMap[p]
		if !ok {
			lbl = "l"
		}
		recs = append(recs, AIRecommendation{
			Priority:    p,
			CssClass:    css,
			LblClass:    lbl,
			Timeframe:   r.Timeframe,
			Description: r.Description,
		})
	}
	return recs, nil
}

// generateAIContent chama a API duas vezes:
// 1. Para gerar recomendações estruturadas (JSON)
// 2. Para gerar um parágrafo de análise executiva
func generateAIContent(apiKey string, hosts []HostRow, vulns []VulnEntry) ([]AIRecommendation, template.HTML, error) {
	summary := buildScanSummary(hosts, vulns)

	systemPrompt := `Você é um especialista sênior em segurança de redes e pentest.
Analisa resultados de scans Nmap e gera relatórios executivos precisos, objetivos e em português do Brasil.
Suas recomendações são sempre específicas para os achados reais — nunca genéricas.`

	// ── Passo 1: Recomendações em JSON ────────────────────────────────────────
	recPrompt := fmt.Sprintf(`Com base neste scan de rede, gere entre 4 e 7 recomendações de segurança ESPECÍFICAS para os achados encontrados.

%s

Responda SOMENTE com um array JSON válido, sem texto antes ou depois, sem markdown fences.
Formato exato de cada item:
{
  "priority": "CRÍTICO" | "ALTO" | "MÉDIO" | "BAIXO",
  "timeframe": "texto curto como 'Ação imediata' ou 'Curto prazo (7 dias)'",
  "description": "descrição detalhada e específica da recomendação, mencionando IPs, portas e serviços reais encontrados"
}`, summary)

	recJSON, err := callClaude(apiKey, systemPrompt, recPrompt)
	if err != nil {
		return nil, "", fmt.Errorf("erro ao gerar recomendações: %w", err)
	}

	recs, err := parseAIRecommendations(recJSON)
	if err != nil {
		// Fallback: retorna recomendação de erro legível
		recs = []AIRecommendation{{
			Priority:    "INFO",
			CssClass:    "rl",
			LblClass:    "l",
			Timeframe:   "N/A",
			Description: "Não foi possível parsear as recomendações da IA. Resposta bruta: " + recJSON[:min(200, len(recJSON))],
		}}
	}

	// ── Passo 2: Análise executiva em HTML simples ────────────────────────────
	execPrompt := fmt.Sprintf(`Com base neste scan, escreva UM parágrafo executivo de 3 a 5 frases resumindo:
- o estado geral de segurança da rede
- os riscos mais críticos identificados (mencione IPs e serviços reais)
- a urgência de remediação

%s

Responda APENAS o parágrafo em texto puro, sem títulos, sem markdown, sem HTML.`, summary)

	execText, err := callClaude(apiKey, systemPrompt, execPrompt)
	if err != nil {
		execText = "Análise executiva indisponível (erro na API)."
	}

	// Converte quebras de linha em <br> para renderizar no HTML
	execHTML := template.HTML(strings.ReplaceAll(template.HTMLEscapeString(execText), "\n", "<br>"))

	return recs, execHTML, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ════════════════════════════════════════════════════════════════════════════
//  TEMPLATE HTML
// ════════════════════════════════════════════════════════════════════════════

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

/* Cabeçalho */
.header{background:#fff;border-radius:12px;padding:20px 28px;
  display:flex;justify-content:space-between;align-items:center;
  margin-bottom:20px;border:1px solid #e0e0e0;border-bottom:4px solid #01579b}
.header h1{font-size:20px;font-weight:700;color:#01579b}
.header p{font-size:12px;color:#666;margin-top:4px}
.header img{height:60px}

/* Cards */
.cards{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px;margin-bottom:20px}
.card{background:#f7f8f9;border-radius:10px;padding:16px 18px;border:1px solid #e8e8e8}
.card .lbl{font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px}
.card .val{font-size:26px;font-weight:700;color:#111}
.card .sub{font-size:11px;color:#aaa;margin-top:3px}
.c-red{color:#b83232}.c-amb{color:#9a6800}.c-grn{color:#287048}

/* Tabela de acesso remoto */
.ra-table{width:100%;border-collapse:collapse;font-size:12px;margin-top:8px}
.ra-table th{font-size:10px;font-weight:700;color:#999;text-transform:uppercase;
  padding:5px 8px;border-bottom:1px solid #eee;text-align:left;background:#fafafa}
.ra-table td{padding:6px 8px;border-bottom:1px solid #f5f5f5;vertical-align:top}
.ra-table tr:last-child td{border-bottom:none}
.ra-note{font-size:11px;color:#777;margin-top:2px;line-height:1.4}

/* Seção */
.sec{font-size:11px;font-weight:700;color:#888;text-transform:uppercase;
  letter-spacing:.07em;margin:24px 0 10px;padding-bottom:4px;
  border-bottom:1px solid #e8e8e8}

/* Análise executiva IA */
.ai-box{background:#f0f4ff;border:1px solid #c7d4f5;border-left:4px solid #3b5bdb;
  border-radius:8px;padding:14px 16px;margin-bottom:16px;font-size:13px;
  line-height:1.7;color:#2c3e6b}
.ai-badge{display:inline-block;background:#3b5bdb;color:#fff;font-size:10px;
  font-weight:700;padding:2px 8px;border-radius:4px;margin-bottom:8px;
  letter-spacing:.05em}

/* Gráficos */
.charts{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:4px}
.cbox{background:#fff;border-radius:10px;border:1px solid #e8e8e8;padding:18px}
.cbox .ct{font-size:11px;font-weight:700;color:#888;text-transform:uppercase;
  letter-spacing:.06em;margin-bottom:14px}
.cwrap{position:relative;height:190px}

/* Tabela */
.tbl{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;
  overflow:hidden;border:1px solid #e8e8e8}
.tbl th{font-size:11px;font-weight:700;color:#888;text-transform:uppercase;
  letter-spacing:.04em;padding:10px 12px;border-bottom:1px solid #eee;
  text-align:left;background:#fafafa}
.tbl td{padding:10px 12px;border-bottom:1px solid #f2f2f2;font-size:13px;vertical-align:top}
.tbl tr:last-child td{border-bottom:none}
.tbl tr:hover td{background:#fafbff}
.tip{font-size:11px;color:#999;margin-top:2px}

/* Badges */
.badge{display:inline-block;padding:2px 9px;border-radius:4px;font-size:11px;font-weight:700}
.b-red{background:#fde8e8;color:#b83232}
.b-amb{background:#fef3d8;color:#9a6800}
.b-grn{background:#e4f5ea;color:#287048}
.b-gry{background:#f0f0f0;color:#666}

/* Vulns */
.vitem{display:flex;gap:12px;align-items:flex-start;margin-bottom:10px;
  padding:12px 14px;background:#fff;border:1px solid #e8e8e8;border-radius:8px}
.vdot{width:9px;height:9px;border-radius:50%;margin-top:4px;flex-shrink:0}
.dh{background:#b83232}.dm{background:#b07010}.dl{background:#287048}
.vtitle{font-size:13px;font-weight:700;color:#111;margin-bottom:3px}
.vdesc{font-size:12px;color:#555;line-height:1.6}

/* Recomendações */
.ritem{padding:12px 14px;background:#fff;border:1px solid #e8e8e8;
  border-left:4px solid;border-radius:8px;margin-bottom:8px;
  font-size:13px;line-height:1.6;color:#333}
.rh{border-left-color:#b83232}.rm{border-left-color:#b07010}.rl{border-left-color:#287048}
.rlbl{font-size:11px;font-weight:700;margin-bottom:4px}
.rlbl.h{color:#b83232}.rlbl.m{color:#9a6800}.rlbl.l{color:#287048}

.footer{text-align:center;margin-top:32px;font-size:11px;color:#bbb;
  padding-top:16px;border-top:1px solid #e8e8e8}

@media(max-width:750px){
  .cards{grid-template-columns:repeat(2,1fr)}
  .charts{grid-template-columns:1fr}
}
</style>
</head>
<body>
<div class="wrap">

<!-- Cabeçalho -->
<div class="header">
  <img src="logo.png" alt="Zebyte" onerror="this.style.display='none'">
  <div style="text-align:right">
    <h1>Auditoria de Infraestrutura de Rede</h1>
    <p><strong>ZeScan Pro v.1</strong> &nbsp;|&nbsp; Zebyte Consulting &nbsp;|&nbsp; Data: {{.Data}} &nbsp;|&nbsp; Duração: {{.Duration}}</p>
  </div>
</div>

<!-- Metric cards -->
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
  <div class="card">
    <div class="lbl">Acesso remoto exposto</div>
    <div class="val {{if gt .RemoteAccessCount 0}}c-red{{else}}c-grn{{end}}">{{.RemoteAccessCount}}</div>
    <div class="sub">portas de acesso remoto abertas</div>
  </div>
</div>

<!-- Análise executiva IA -->
{{if .AIAnalysis}}
<p class="sec">Análise executiva — gerada por IA</p>
<div class="ai-box">
  <div class="ai-badge">✦ CLAUDE AI</div>
  <p>{{.AIAnalysis}}</p>
</div>
{{end}}

<!-- Gráficos de risco -->
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

<!-- Gráficos de fabricantes MAC -->
<div class="charts" style="margin-top:14px">
  <div class="cbox">
    <div class="ct">Fabricantes detectados (MAC vendor) — quantidade</div>
    <div class="cwrap"><canvas id="vendorChart"></canvas></div>
  </div>
  <div class="cbox">
    <div class="ct">Tipo de dispositivo por fabricante — percentual</div>
    <div class="cwrap"><canvas id="vendorTypeChart"></canvas></div>
  </div>
</div>

<!-- Tabela de inventário -->
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
        {{if .MAC}}<div class="tip" style="font-family:monospace">{{.MAC}}</div>{{end}}
        {{if .Vendor}}<div class="tip">🏭 {{.Vendor}}</div>{{end}}
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

<!-- Acesso remoto exposto -->
{{$hasRemote := false}}
{{range .Hosts}}{{if .RemoteFindings}}{{$hasRemote = true}}{{end}}{{end}}
{{if $hasRemote}}
<p class="sec">Acesso remoto exposto — risco potencial</p>
{{range .Hosts}}
  {{if .RemoteFindings}}
  <div class="vitem" style="flex-direction:column;gap:8px">
    <div style="display:flex;align-items:center;gap:10px">
      <strong style="font-size:13px">{{.IP}}</strong>
      {{if .Hostname}}<span style="font-size:11px;color:#999">{{.Hostname}}</span>{{end}}
      <span class="badge b-red" style="margin-left:auto">{{len .RemoteFindings}} porta(s) de acesso remoto</span>
    </div>
    <table class="ra-table">
      <thead>
        <tr>
          <th>Porta</th>
          <th>Serviço</th>
          <th>Risco</th>
          <th>Orientação de remediação</th>
        </tr>
      </thead>
      <tbody>
      {{range .RemoteFindings}}
        <tr>
          <td><code style="font-size:11px;background:#f5f5f5;padding:1px 5px;border-radius:3px">{{.Port}}</code></td>
          <td><strong>{{.Name}}</strong></td>
          <td><span class="badge {{.Badge}}">{{.Risk}}</span></td>
          <td class="ra-note">{{.Note}}</td>
        </tr>
      {{end}}
      </tbody>
    </table>
  </div>
  {{end}}
{{end}}
{{end}}

<!-- Vulnerabilidades detalhadas -->
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

<!-- Recomendações geradas pela IA -->
<p class="sec">Recomendações — geradas por IA com base nos achados reais</p>
{{if .Recommendations}}
  {{range .Recommendations}}
  <div class="ritem {{.CssClass}}">
    <div class="rlbl {{.LblClass}}">{{.Priority}} — {{.Timeframe}}</div>
    {{.Description}}
  </div>
  {{end}}
{{else}}
  <div class="ritem rl">
    <div class="rlbl l">INFO</div>
    Recomendações não disponíveis (verifique a chave da API).
  </div>
{{end}}

<div class="footer">
  ZeScan Pro v.1 &nbsp;|&nbsp; Zebyte Consulting &nbsp;|&nbsp; Análise por Claude AI &nbsp;|&nbsp; {{.Data}}
</div>
</div>

<script>
(function(){
  new Chart(document.getElementById('donutChart'),{
    type:'doughnut',
    data:{
      labels:{{.DonutLabels}},
      datasets:[{data:{{.DonutData}},backgroundColor:{{.DonutColors}},borderWidth:0,hoverOffset:4}]
    },
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{position:'bottom',labels:{font:{size:12},padding:14,boxWidth:12}}}}
  });
  new Chart(document.getElementById('barChart'),{
    type:'bar',
    data:{
      labels:{{.BarLabels}},
      datasets:[{label:'Score (0-10)',data:{{.BarScores}},
        backgroundColor:{{.BarColors}},borderRadius:4,borderSkipped:false}]
    },
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{
        y:{min:0,max:10,grid:{color:'rgba(0,0,0,0.06)'},ticks:{font:{size:11}}},
        x:{grid:{display:false},ticks:{font:{size:11}}}
      }
    }
  });
  new Chart(document.getElementById('vendorChart'),{
    type:'pie',
    data:{
      labels:{{.VendorLabels}},
      datasets:[{data:{{.VendorCounts}},backgroundColor:{{.VendorColors}},borderWidth:2,borderColor:'#fff'}]
    },
    options:{
      responsive:true,maintainAspectRatio:false,
      plugins:{
        legend:{
          position:'right',
          labels:{font:{size:11},padding:10,boxWidth:12,
            generateLabels:function(chart){
              var data=chart.data;
              return data.labels.map(function(label,i){
                return {text:label,fillStyle:data.datasets[0].backgroundColor[i],
                  strokeStyle:'#fff',lineWidth:2,index:i};
              });
            }
          }
        },
        tooltip:{callbacks:{label:function(ctx){
          var total=ctx.dataset.data.reduce(function(a,b){return a+b;},0);
          var pct=Math.round(ctx.parsed*100/total);
          return ' '+ctx.label+': '+ctx.parsed+' host(s) ('+pct+'%)';
        }}}
      }
    }
  });
  new Chart(document.getElementById('vendorTypeChart'),{
    type:'doughnut',
    data:{
      labels:{{.VendorTypeLabels}},
      datasets:[{data:{{.VendorTypePct}},backgroundColor:{{.VendorTypeColors}},borderWidth:2,borderColor:'#fff',hoverOffset:6}]
    },
    options:{
      responsive:true,maintainAspectRatio:false,
      cutout:'55%',
      plugins:{
        legend:{
          position:'right',
          labels:{font:{size:11},padding:10,boxWidth:12}
        },
        tooltip:{callbacks:{label:function(ctx){
          var total=ctx.dataset.data.reduce(function(a,b){return a+b;},0);
          var pct=Math.round(ctx.parsed*100/total);
          return ' '+ctx.label+': '+pct+'%';
        }}}
      }
    }
  });
})();
</script>
</body>
</html>`

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

// vendorCategory classifica um MAC vendor numa categoria de dispositivo.
func vendorCategory(vendor string) string {
	if vendor == "" {
		return "Desconhecido"
	}
	v := strings.ToLower(vendor)
	switch {
	case strings.Contains(v, "apple"):
		return "Apple (Mac/iOS)"
	case strings.Contains(v, "google"):
		return "Google (IoT/Chromecast)"
	case strings.Contains(v, "samsung"):
		return "Samsung (Mobile/TV)"
	case strings.Contains(v, "huawei"):
		return "Huawei"
	case strings.Contains(v, "xiaomi"):
		return "Xiaomi (Mobile/IoT)"
	case strings.Contains(v, "amazon"):
		return "Amazon (Echo/Fire)"
	case strings.Contains(v, "raspberry") || strings.Contains(v, "raspberr"):
		return "Raspberry Pi"
	case strings.Contains(v, "intel"):
		return "Intel (PC/Server)"
	case strings.Contains(v, "dell"):
		return "Dell (PC/Server)"
	case strings.Contains(v, "hp") || strings.Contains(v, "hewlett"):
		return "HP (PC/Printer)"
	case strings.Contains(v, "lenovo"):
		return "Lenovo (PC/Notebook)"
	case strings.Contains(v, "asus"):
		return "ASUS (PC/Roteador)"
	case strings.Contains(v, "tp-link") || strings.Contains(v, "tplink"):
		return "TP-Link (Rede)"
	case strings.Contains(v, "cisco"):
		return "Cisco (Rede)"
	case strings.Contains(v, "netgear"):
		return "Netgear (Rede)"
	case strings.Contains(v, "ubiquiti") || strings.Contains(v, "ubnt"):
		return "Ubiquiti (Rede)"
	case strings.Contains(v, "mikrotik"):
		return "MikroTik (Rede)"
	case strings.Contains(v, "hikvision") || strings.Contains(v, "dahua") ||
		strings.Contains(v, "axis") || strings.Contains(v, "hanwha"):
		return "Câmera IP/NVR"
	case strings.Contains(v, "vmware") || strings.Contains(v, "virtualbox") ||
		strings.Contains(v, "parallels"):
		return "Máquina Virtual"
	default:
		return vendor // mantém o nome original se não reconhecido
	}
}

// vendorDeviceType agrupa vendors em tipos amplos para o segundo gráfico.
func vendorDeviceType(vendor string) string {
	if vendor == "" {
		return "Desconhecido"
	}
	v := strings.ToLower(vendor)
	switch {
	case strings.Contains(v, "apple"), strings.Contains(v, "samsung"),
		strings.Contains(v, "xiaomi"), strings.Contains(v, "huawei"),
		strings.Contains(v, "amazon"), strings.Contains(v, "google"):
		return "Mobile / Smart Device"
	case strings.Contains(v, "cisco"), strings.Contains(v, "tp-link"),
		strings.Contains(v, "tplink"), strings.Contains(v, "netgear"),
		strings.Contains(v, "ubiquiti"), strings.Contains(v, "ubnt"),
		strings.Contains(v, "mikrotik"), strings.Contains(v, "asus"):
		return "Infraestrutura de Rede"
	case strings.Contains(v, "dell"), strings.Contains(v, "hp"),
		strings.Contains(v, "hewlett"), strings.Contains(v, "lenovo"),
		strings.Contains(v, "intel"), strings.Contains(v, "acer"),
		strings.Contains(v, "gigabyte"):
		return "Computador / Servidor"
	case strings.Contains(v, "hikvision"), strings.Contains(v, "dahua"),
		strings.Contains(v, "axis"), strings.Contains(v, "hanwha"),
		strings.Contains(v, "dvr"), strings.Contains(v, "nvr"):
		return "Câmera / Vigilância"
	case strings.Contains(v, "vmware"), strings.Contains(v, "virtualbox"),
		strings.Contains(v, "parallels"), strings.Contains(v, "xen"):
		return "Máquina Virtual"
	case strings.Contains(v, "raspberry"):
		return "Single-Board Computer"
	default:
		return "Outro / Desconhecido"
	}
}

// buildVendorCharts calcula os dados dos dois gráficos de fabricantes.
func buildVendorCharts(hosts []HostRow) (
	vendorLabels, vendorCounts, vendorColors template.JS,
	typeLabels, typePct, typeColors template.JS,
) {
	// Paleta de cores para os gráficos
	palette := []string{
		"#3B7DD8", "#E8593C", "#1D9E75", "#EF9F27", "#7F77DD",
		"#D4537E", "#378ADD", "#639922", "#BA7517", "#534AB7",
		"#0F6E56", "#993C1D", "#185FA5", "#3B6D11", "#854F0B",
	}

	// Gráfico 1: contagem por vendor (categoria)
	vendorCount := map[string]int{}
	for _, h := range hosts {
		cat := vendorCategory(h.Vendor)
		vendorCount[cat]++
	}
	// Ordena por contagem decrescente
	type kv struct{ k string; v int }
	var sorted []kv
	for k, v := range vendorCount {
		sorted = append(sorted, kv{k, v})
	}
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].v > sorted[i].v {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	var vLabels []string
	var vData []int
	var vColors []string
	for i, item := range sorted {
		vLabels = append(vLabels, fmt.Sprintf("%s (%d)", item.k, item.v))
		vData = append(vData, item.v)
		vColors = append(vColors, palette[i%len(palette)])
	}
	vendorLabels = jsArr(vLabels)
	vendorCounts = jsIntArr(vData)
	vendorColors = jsArr(vColors)

	// Gráfico 2: percentual por tipo de dispositivo
	typeCount := map[string]int{}
	total := len(hosts)
	if total == 0 {
		total = 1
	}
	for _, h := range hosts {
		t := vendorDeviceType(h.Vendor)
		typeCount[t]++
	}
	var tSorted []kv
	for k, v := range typeCount {
		tSorted = append(tSorted, kv{k, v})
	}
	for i := 0; i < len(tSorted)-1; i++ {
		for j := i + 1; j < len(tSorted); j++ {
			if tSorted[j].v > tSorted[i].v {
				tSorted[i], tSorted[j] = tSorted[j], tSorted[i]
			}
		}
	}
	var tLabels []string
	var tData []int
	var tColors []string
	typeColorMap := map[string]string{
		"Mobile / Smart Device":    "#3B7DD8",
		"Infraestrutura de Rede":   "#1D9E75",
		"Computador / Servidor":    "#534AB7",
		"Câmera / Vigilância":      "#E8593C",
		"Máquina Virtual":          "#EF9F27",
		"Single-Board Computer":    "#D4537E",
		"Outro / Desconhecido":     "#888780",
	}
	for i, item := range tSorted {
		pct := item.v * 100 / total
		label := fmt.Sprintf("%s — %d%%", item.k, pct)
		tLabels = append(tLabels, label)
		tData = append(tData, item.v)
		c, ok := typeColorMap[item.k]
		if !ok {
			c = palette[i%len(palette)]
		}
		tColors = append(tColors, c)
	}
	typeLabels = jsArr(tLabels)
	typePct = jsIntArr(tData)
	typeColors = jsArr(tColors)
	return
}

func scoreHost(ports []NmapPort) (level string, score int, findings []string, remoteFindings []RemoteFinding) {
	seen := map[string]bool{}
	for _, p := range ports {
		if p.State.State != "open" {
			continue
		}
		svc := strings.ToLower(p.Service.Name)

		// ── Detecção de portas de acesso remoto ───────────────────────────
		if ra, ok := remoteAccessDB[p.PortId]; ok {
			score += ra.Score
			badge := "b-amb"
			if ra.Risk == "CRÍTICO" {
				badge = "b-red"
			} else if ra.Risk == "MÉDIO" {
				badge = "b-gry"
			}
			remoteFindings = append(remoteFindings, RemoteFinding{
				Port:  p.PortId + "/" + p.Protocol,
				Name:  ra.Name,
				Risk:  ra.Risk,
				Note:  ra.Note,
				Badge: badge,
			})
			findings = append(findings, fmt.Sprintf("[%s] %s (porta %s) — %s",
				ra.Risk, ra.Name, p.PortId, ra.Note))
		}

		// ── Serviços legados pelo nome (quando porta não é padrão) ────────
		switch svc {
		case "telnet":
			if !seen["telnet"] {
				score += 3
				findings = append(findings, "Telnet aberto — protocolo sem criptografia")
				seen["telnet"] = true
			}
		case "rtsp":
			score += 3
			findings = append(findings, fmt.Sprintf("RTSP exposto na porta %s — verificar autenticação", p.PortId))
		case "ftp":
			score += 2
			findings = append(findings, fmt.Sprintf("FTP na porta %s — preferir SFTP/SCP", p.PortId))
		case "vnc":
			if !seen["vnc:"+p.PortId] {
				score += 3
				seen["vnc:"+p.PortId] = true
				findings = append(findings, fmt.Sprintf("VNC detectado na porta %s — verificar criptografia e senha", p.PortId))
			}
		case "rdp", "ms-wbt-server":
			if !seen["rdp:"+p.PortId] {
				score += 4
				seen["rdp:"+p.PortId] = true
				findings = append(findings, fmt.Sprintf("RDP detectado na porta %s — restringir por IP e usar NLA", p.PortId))
			}
		}

		// ── Scripts de vulnerabilidade ────────────────────────────────────
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
				findings = append(findings, s.Id+" — CVE referenciada")
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

// ════════════════════════════════════════════════════════════════════════════
//  MAIN
// ════════════════════════════════════════════════════════════════════════════

// ════════════════════════════════════════════════════════════════════════════
//  MODOS DE SCAN
// ════════════════════════════════════════════════════════════════════════════

// ScanMode define a intensidade e velocidade do scan Nmap.
type ScanMode struct {
	Label       string // exibido na UI
	Description string // tooltip / status
	Args        func(target, extraPorts string) []string
}

var scanModes = []ScanMode{
	{
		// ── RÁPIDO ────────────────────────────────────────────────────────
		// ~2-5 min para /24. Descobre hosts + portas mais comuns + versão.
		// Sem detecção de OS pesada, sem scripts vuln.
		Label:       "Rápido (~5 min)",
		Description: "Descoberta de hosts e portas comuns. Sem scripts de vulnerabilidade.",
		Args: func(target, extraPorts string) []string {
			return []string{
				"-sS",              // SYN scan (stealth)
				"-sV",              // versão dos serviços
				"--version-intensity", "3", // intensidade reduzida (0-9, padrão 7)
				"-T4",              // timing agressivo
				"--min-rate", "1000",       // mínimo 1000 pkts/s
				"--max-retries", "1",       // 1 retry por porta
				"--host-timeout", "30s",    // abandona host após 30s
				"--min-hostgroup", "64",    // escaneia 64 hosts em paralelo
				"--min-parallelism", "100", // 100 probes em paralelo
				"-p", "21-23,25,53,80,110,135,139,143,161,443,445,554,993,995,1194,1433,1723,3306,3389,5432,5900,5938,6568,7070,8080,8443,8899,9090," + extraPorts,
				"--reason",
				"-oX", "relatorio_zebyte_completo.xml",
				target,
			}
		},
	},
	{
		// ── BALANCEADO ────────────────────────────────────────────────────
		// ~15-30 min para /24. Versão completa + OS + scripts seguros (sem vuln).
		// Scripts safe detectam banners, configurações ruins, auth anon, etc.
		Label:       "Balanceado (~20 min)",
		Description: "Versão + OS + scripts de configuração. Sem scripts vuln pesados.",
		Args: func(target, extraPorts string) []string {
			return []string{
				"-sS",
				"-sV",
				"--version-intensity", "5",
				"-O",                // OS detection
				"--osscan-limit",    // só tenta OS em hosts promissores
				"-T4",
				"--min-rate", "500",
				"--max-retries", "2",
				"--host-timeout", "2m",
				"--min-hostgroup", "32",
				"--min-parallelism", "50",
				// Scripts úteis mas rápidos (categoria safe, não vuln)
				"--script", strings.Join([]string{
					"banner",
					"http-title",
					"http-server-header",
					"http-auth-finder",
					"ftp-anon",
					"ssh-auth-methods",
					"smb-security-mode",
					"ssl-cert",
					"ssl-enum-ciphers",
					"rdp-enum-encryption",
					"vnc-info",
					"snmp-info",
					"rtsp-url-brute",
				}, ","),
				"-p", "1-1024," + extraPorts,
				"--reason",
				"-oX", "relatorio_zebyte_completo.xml",
				target,
			}
		},
	},
	{
		// ── PROFUNDO ──────────────────────────────────────────────────────
		// ~30-60 min para /24 (vs 4h antes). Aplica as otimizações de timing
		// mas mantém os scripts vuln, só que com paralelismo máximo e
		// timeout por host para não travar em hosts lentos.
		Label:       "Profundo (~45 min)",
		Description: "Scan completo com scripts vuln otimizado. Muito mais rápido que o original.",
		Args: func(target, extraPorts string) []string {
			return []string{
				"-sS",
				"-sV",
				"--version-intensity", "6",
				"-O",
				"--osscan-limit",
				"-T4",
				"--min-rate", "300",
				"--max-retries", "2",
				"--host-timeout", "5m",     // abandona host travado após 5 min
				"--script-timeout", "30s",  // cada script tem 30s por host
				"--min-hostgroup", "16",
				"--min-parallelism", "25",
				// Scripts vuln específicos e relevantes (em vez de --script vuln que carrega ~50 scripts)
				"--script", strings.Join([]string{
					"vuln",          // categoria completa, mas timeout por script
					"exploit",       // checa exploits conhecidos
					"auth",          // autenticação fraca/anônima
					"default",       // scripts padrão do Nmap
				}, ","),
				"-p", "1-1024," + extraPorts,
				"--reason",
				"-oX", "relatorio_zebyte_completo.xml",
				target,
			}
		},
	},
}

func main() {
	a := app.New()
	w := a.NewWindow("ZeScan Pro v.1 — Auditoria Zebyte")
	w.Resize(fyne.NewSize(640, 580))

	logo := canvas.NewImageFromFile("logo.png")
	logo.FillMode = canvas.ImageFillContain
	logo.SetMinSize(fyne.NewSize(120, 90))

	inputRange := widget.NewEntry()
	inputRange.SetText("192.168.86.0/24")
	inputRange.SetPlaceHolder("ex: 192.168.1.0/24")

	// Chave API Anthropic
	inputAPIKey := widget.NewPasswordEntry()
	inputAPIKey.SetPlaceHolder("sk-ant-api03-…  (deixe vazio para pular IA)")
	if saved, err := os.ReadFile(".apikey"); err == nil {
		inputAPIKey.SetText(strings.TrimSpace(string(saved)))
	}

	// Seletor de modo de scan
	modeLabels := make([]string, len(scanModes))
	for i, m := range scanModes {
		modeLabels[i] = m.Label
	}
	selectedMode := 0 // padrão: Rápido
	modeSelect := widget.NewSelect(modeLabels, func(val string) {
		for i, m := range scanModes {
			if m.Label == val {
				selectedMode = i
				break
			}
		}
	})
	modeSelect.SetSelected(modeLabels[0])

	modeDesc := widget.NewLabel("  → " + scanModes[0].Description)
	modeDesc.Wrapping = 3 // fyne.TextWrapWord
	modeSelect.OnChanged = func(val string) {
		for i, m := range scanModes {
			if m.Label == val {
				selectedMode = i
				modeDesc.SetText("  → " + m.Description)
				modeDesc.Refresh()
				break
			}
		}
	}

	status := widget.NewLabel("Status: Pronto")

	progress := widget.NewProgressBarInfinite()
	progress.Hide()

	btnScan := widget.NewButton("▶  Executar Auditoria", func() {
		target := inputRange.Text
		apiKey := strings.TrimSpace(inputAPIKey.Text)
		mode := scanModes[selectedMode]

		if apiKey != "" {
			os.WriteFile(".apikey", []byte(apiKey), 0600)
		}

		status.SetText("Iniciando scan [" + mode.Label + "]: " + target)
		progress.Show()
		progress.Refresh()

		go func() {
			start := time.Now()

			// ── 1. Executa Nmap com o modo selecionado ────────────────────────
			status.SetText("Nmap rodando [" + mode.Label + "]… aguarde")
			status.Refresh()

			extraPorts := remotePorts()
			args := mode.Args(target, extraPorts)
			cmd := exec.Command("sudo", append([]string{"nmap"}, args...)...)
			cmd.Run()

			duration := time.Since(start).Round(time.Second).String()

			// ── 2. Parse XML ──────────────────────────────────────────────────
			status.SetText("Carregando base OUI de fabricantes...")
			status.Refresh()
			loadOUI(func(msg string) {
				status.SetText(msg)
				status.Refresh()
			})

			status.SetText("Processando resultados...")
			status.Refresh()

			raw, _ := os.ReadFile("relatorio_zebyte_completo.xml")
			var nmapRes NmapRun
			xml.Unmarshal(raw, &nmapRes)

			// ── 3. Processa dados ─────────────────────────────────────────────
			// Constrói mapa IP→MAC a partir de <hosthint> — o Nmap coloca
			// MACs nos hosthints mesmo para hosts onde não aparece no <host>
			hintMAC := map[string]string{}
			for _, hint := range nmapRes.HostHints {
				hintIP, hintMac := "", ""
				for _, addr := range hint.Address {
					if addr.AddrType == "ipv4" {
						hintIP = addr.Addr
					}
					if addr.AddrType == "mac" {
						hintMac = addr.Addr
					}
				}
				if hintIP != "" && hintMac != "" {
					hintMAC[hintIP] = hintMac
				}
			}

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
						if addr.Vendor != "" {
							vendor = addr.Vendor
						}
					}
				}
				// Fallback 1: tenta o MAC do <hosthint> (Nmap coloca lá mesmo
				// quando o host não responde com MAC direto, ex: localhost)
				if mac == "" && ip != "" {
					mac = hintMAC[ip]
				}
				// Fallback 2: resolve vendor pela base OUI se o Nmap não trouxe
				// (no XML real o atributo vendor quase sempre vem vazio)
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

				level, score, findings, remoteFindings := scoreHost(h.Ports)

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
					IP:             ip,
					MAC:            mac,
					Hostname:       hostname,
					Vendor:         vendor,
					OS:             osName,
					OSAcc:          osAcc,
					OpenPorts:      openPorts,
					RiskLevel:      level,
					RiskScore:      score,
					Findings:       findings,
					RemoteFindings: remoteFindings,
					Lastboot:       h.Uptime.Lastboot,
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

			// ── 4. IA: Recomendações e análise executiva ──────────────────────
			var recommendations []AIRecommendation
			var aiAnalysis template.HTML

			if apiKey != "" {
				status.SetText("Consultando Claude AI para análise... ✦")
				status.Refresh()

				recs, analysis, err := generateAIContent(apiKey, hostRows, vulnEntries)
				if err != nil {
					status.SetText("Aviso: erro na API — " + err.Error())
				} else {
					recommendations = recs
					aiAnalysis = analysis
				}
			}

			// ── 5. Gera HTML ──────────────────────────────────────────────────
			remoteAccessCount := 0
			for _, hr := range hostRows {
				remoteAccessCount += len(hr.RemoteFindings)
			}

			// Gráficos de fabricantes MAC
			vendorLabels, vendorCounts, vendorColors,
				vendorTypeLabels, vendorTypePct, vendorTypeColors := buildVendorCharts(hostRows)

			rd := ReportData{
				Data:              time.Now().Format("02/01/2006 15:04"),
				Duration:          duration,
				TotalHosts:        len(hostRows),
				TotalOpen:         totalOpen,
				RiskLabel:         overallRisk,
				VulnCount:         vulnCount,
				SafeCount:         safeCount,
				MedCount:          medCount,
				Hosts:             hostRows,
				Vulns:             vulnEntries,
				Recommendations:   recommendations,
				AIAnalysis:        aiAnalysis,
				RemoteAccessCount: remoteAccessCount,
				VendorLabels:      vendorLabels,
				VendorCounts:      vendorCounts,
				VendorColors:      vendorColors,
				VendorTypeLabels:  vendorTypeLabels,
				VendorTypePct:     vendorTypePct,
				VendorTypeColors:  vendorTypeColors,
				DonutLabels:       jsArr(donutLabels),
				DonutData:         jsIntArr(donutData),
				DonutColors:       jsArr(donutColors),
				BarLabels:         jsArr(barLabels),
				BarScores:         jsIntArr(barScores),
				BarColors:         jsArr(barColors),
			}

			outFile, err := os.Create("Relatorio_Final_Zebyte.html")
			if err == nil {
				tmpl := template.Must(template.New("report").Parse(htmlTmpl))
				tmpl.Execute(outFile, rd)
				outFile.Close()
			}

			status.SetText(fmt.Sprintf("Concluído em %s! Relatório gerado.", duration))
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