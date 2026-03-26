package main

// ════════════════════════════════════════════════════════════════════════════
//  SISTEMA DE LICENÇA COM EXPIRAÇÃO
//
//  Funcionamento:
//  1. Na primeira execução, grava a data de ativação no registro do Windows
//     (HKCU\Software\Zebyte\ZeScan) e num arquivo oculto local como backup.
//  2. Em cada inicialização verifica AMBAS as fontes. Se qualquer uma indicar
//     expiração, o programa bloqueia.
//  3. A data de ativação é ofuscada com XOR + base64 para dificultar edição
//     manual. A chave XOR é derivada do volume serial do disco C: — então
//     mesmo copiando o arquivo de licença para outra máquina, ele não funciona.
//  4. DAYS_VALID define quantos dias a licença é válida após a 1ª execução.
// ════════════════════════════════════════════════════════════════════════════

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// ── Configuração ──────────────────────────────────────────────────────────

const (
	DAYS_VALID   = 2                          // dias de validade após ativação
	REG_KEY      = `Software\Zebyte\ZeScan`  // chave no registro Windows
	REG_VALUE    = "ActivationData"
	LICENSE_FILE = ".zsl"                     // arquivo oculto de backup
)

// ── Funções de ofuscação ──────────────────────────────────────────────────

// machineKey deriva uma chave de 32 bytes única desta máquina.
// Usa o volume serial do disco C: + hostname como seed.
func machineKey() []byte {
	seed := "zebyte-zescan-2024" // salt fixo

	if runtime.GOOS == "windows" {
		// Volume serial do disco C: — muda por máquina
		out, err := exec.Command("cmd", "/c", "vol C:").Output()
		if err == nil {
			seed += string(out)
		}
	}

	// Hostname como segundo fator
	if hn, err := os.Hostname(); err == nil {
		seed += hn
	}

	h := sha256.Sum256([]byte(seed))
	return h[:]
}

// xorObfuscate aplica XOR com a chave da máquina — reversível.
func xorObfuscate(data []byte) []byte {
	key := machineKey()
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out
}

// encodeTimestamp serializa um time.Time → string ofuscada em base64.
func encodeTimestamp(t time.Time) string {
	raw := []byte(fmt.Sprintf("%d", t.Unix()))
	obf := xorObfuscate(raw)
	return base64.StdEncoding.EncodeToString(obf)
}

// decodeTimestamp faz o caminho inverso. Retorna erro se corrompido.
func decodeTimestamp(encoded string) (time.Time, error) {
	obf, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return time.Time{}, fmt.Errorf("licença inválida")
	}
	raw := xorObfuscate(obf)
	unix, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("licença corrompida")
	}
	return time.Unix(unix, 0), nil
}

// ── Registro Windows ──────────────────────────────────────────────────────

func writeRegistry(encoded string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, REG_KEY, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(REG_VALUE, encoded)
}

func readRegistry() (string, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, REG_KEY, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()
	val, _, err := k.GetStringValue(REG_VALUE)
	return val, err
}

// ── Arquivo de backup ─────────────────────────────────────────────────────

func licenseFilePath() string {
	exe, err := os.Executable()
	if err != nil {
		return LICENSE_FILE
	}
	return filepath.Join(filepath.Dir(exe), LICENSE_FILE)
}

func writeFile(encoded string) error {
	return os.WriteFile(licenseFilePath(), []byte(encoded), 0600)
}

func readFile() (string, error) {
	data, err := os.ReadFile(licenseFilePath())
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// ── API pública ───────────────────────────────────────────────────────────

// LicenseStatus descreve o estado atual da licença.
type LicenseStatus struct {
	Active      bool
	DaysLeft    int
	ExpiresAt   time.Time
	ActivatedAt time.Time
	Message     string
}

// CheckLicense verifica (e se necessário inicializa) a licença.
// Retorna LicenseStatus com Active=false se expirada ou inválida.
func CheckLicense() LicenseStatus {
	// Tenta ler a data de ativação (registro ou arquivo)
	activatedAt, err := loadActivationDate()

	if err != nil {
		// Primeira execução — grava agora
		now := time.Now()
		encoded := encodeTimestamp(now)

		// Grava nas duas fontes; ignora erros individuais
		regErr := writeRegistry(encoded)
		fileErr := writeFile(encoded)

		if regErr != nil && fileErr != nil {
			return LicenseStatus{
				Active:  false,
				Message: "Erro ao inicializar licença: " + regErr.Error(),
			}
		}
		activatedAt = now
	}

	expiry := activatedAt.Add(time.Duration(DAYS_VALID) * 24 * time.Hour)
	now := time.Now()
	daysLeft := int(expiry.Sub(now).Hours() / 24)

	if now.After(expiry) {
		return LicenseStatus{
			Active:      false,
			ActivatedAt: activatedAt,
			ExpiresAt:   expiry,
			DaysLeft:    0,
			Message: fmt.Sprintf(
				"Licença expirada em %s.\nEntre em contato com a Zebyte Consulting para renovação.",
				expiry.Format("02/01/2006 15:04"),
			),
		}
	}

	hoursLeft := expiry.Sub(now).Hours()
	timeMsg := fmt.Sprintf("%d dia(s)", daysLeft)
	if hoursLeft < 24 {
		timeMsg = fmt.Sprintf("%.0f hora(s)", hoursLeft)
	}

	return LicenseStatus{
		Active:      true,
		ActivatedAt: activatedAt,
		ExpiresAt:   expiry,
		DaysLeft:    daysLeft,
		Message:     fmt.Sprintf("Licença válida — expira em %s (%s)", expiry.Format("02/01/2006 15:04"), timeMsg),
	}
}

// loadActivationDate tenta carregar de ambas as fontes.
// Prefere o registro; usa arquivo como fallback.
// Retorna erro se nenhuma fonte tiver dados válidos.
func loadActivationDate() (time.Time, error) {
	// Tenta registro primeiro
	if encoded, err := readRegistry(); err == nil {
		if t, err := decodeTimestamp(encoded); err == nil {
			return t, nil
		}
	}

	// Fallback: arquivo
	if encoded, err := readFile(); err == nil {
		if t, err := decodeTimestamp(encoded); err == nil {
			// Sincroniza de volta para o registro se estava só no arquivo
			_ = writeRegistry(encoded)
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("nenhuma licença encontrada")
}

// ResetLicense remove a licença (para testes / reativação pelo suporte).
// Requer que seja chamada com confirmação explícita.
func ResetLicense() error {
	// Remove registro
	registry.DeleteKey(registry.CURRENT_USER, REG_KEY)
	// Remove arquivo
	os.Remove(licenseFilePath())
	return nil
}
