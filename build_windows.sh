#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════════
#  build_windows.sh
#  Gera ZeScanPro.exe para Windows a partir do Linux (cross-compile)
#
#  Pré-requisitos no Linux (Ubuntu/Debian):
#    sudo apt install gcc-mingw-w64-x86-64 windres zip
#    go install fyne.io/fyne/v2/cmd/fyne@latest
#
#  Uso:
#    chmod +x build_windows.sh
#    ./build_windows.sh
# ════════════════════════════════════════════════════════════════════════════

set -e

APP_NAME="ZeScanPro"
VERSION="1.0.0"
OUTPUT_DIR="dist"
ICON="zescan.ico"

echo "════════════════════════════════════════"
echo "  ZeScan Pro — Build Windows"
echo "  Versão: $VERSION"
echo "════════════════════════════════════════"
echo ""

# ── 1. Verifica dependências ──────────────────────────────────────────────
echo "▶ Verificando dependências..."

check_dep() {
    if ! command -v "$1" &>/dev/null; then
        echo "  ✗ $1 não encontrado. Instale com: $2"
        exit 1
    fi
    echo "  ✓ $1"
}

check_dep "go"          "https://go.dev/dl/"
check_dep "x86_64-w64-mingw32-gcc" "sudo apt install gcc-mingw-w64-x86-64"
check_dep "windres"     "sudo apt install binutils-mingw-w64-x86-64"
check_dep "zip"         "sudo apt install zip"

echo ""

# ── 2. Gera ícone ICO (se não existir, cria um placeholder) ──────────────
if [ ! -f "$ICON" ]; then
    echo "▶ Ícone $ICON não encontrado — gerando placeholder..."
    # Gera um ICO simples via Python (16x16 e 32x32 azuis)
    python3 - <<'PYEOF'
import struct, zlib, os

def png_chunk(name, data):
    c = zlib.crc32(name + data) & 0xffffffff
    return struct.pack(">I", len(data)) + name + data + struct.pack(">I", c)

def make_png(size, color_rgb):
    w = h = size
    r, g, b = color_rgb
    raw = b""
    for _ in range(h):
        row = b"\x00"
        for _ in range(w):
            row += bytes([r, g, b, 255])
        raw += row
    compressed = zlib.compress(raw)
    png = b"\x89PNG\r\n\x1a\n"
    png += png_chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
    png += png_chunk(b"IDAT", compressed)
    png += png_chunk(b"IEND", b"")
    return png

# Cria ICO com 16x16 e 32x32 em azul Zebyte (#01579b)
png16 = make_png(16, (1, 87, 155))
png32 = make_png(32, (1, 87, 155))
png48 = make_png(48, (1, 87, 155))

# Formato ICO: header + directory entries + image data
imgs = [png16, png32, png48]
sizes = [16, 32, 48]

header = struct.pack("<HHH", 0, 1, len(imgs))  # reserved, type=1 (icon), count
dir_offset = 6 + len(imgs) * 16
img_data = b""
entries = b""
for i, (img, sz) in enumerate(zip(imgs, sizes)):
    offset = dir_offset + sum(len(imgs[j]) for j in range(i))
    entries += struct.pack("<BBBBHHII", sz, sz, 0, 0, 1, 32, len(img), offset)
    img_data += img

with open("zescan.ico", "wb") as f:
    f.write(header + entries + img_data)

print("  ✓ zescan.ico gerado (placeholder azul)")
PYEOF
fi

# ── 3. Gera o arquivo de recursos Windows (.syso) ─────────────────────────
echo "▶ Compilando recursos Windows (ícone + metadados)..."
windres zescan.rc -O coff -o zescan.syso \
    --target=pe-x86-64 \
    -F pe-x86-64 2>/dev/null || {
    echo "  Aviso: windres falhou, tentando sem target..."
    windres zescan.rc -O coff -o zescan.syso || echo "  Aviso: recursos sem ícone"
}
echo "  ✓ zescan.syso"

# ── 4. Baixa dependências Go ──────────────────────────────────────────────
echo "▶ Baixando dependências Go..."
go mod tidy
echo "  ✓ go.sum atualizado"

# ── 5. Cross-compila para Windows ─────────────────────────────────────────
echo "▶ Compilando para Windows (amd64)..."
mkdir -p "$OUTPUT_DIR"

CGO_ENABLED=1 \
GOOS=windows \
GOARCH=amd64 \
CC=x86_64-w64-mingw32-gcc \
go build \
    -ldflags="-H windowsgui -s -w -X main.buildVersion=$VERSION" \
    -o "$OUTPUT_DIR/$APP_NAME.exe" \
    . 2>&1

if [ $? -eq 0 ]; then
    SIZE=$(du -sh "$OUTPUT_DIR/$APP_NAME.exe" | cut -f1)
    echo "  ✓ $APP_NAME.exe ($SIZE)"
else
    echo "  ✗ Compilação falhou!"
    exit 1
fi

# ── 6. Cria o pacote de distribuição ─────────────────────────────────────
echo "▶ Criando pacote de distribuição..."
DIST_DIR="$OUTPUT_DIR/ZeScanPro_v${VERSION}_Windows"
mkdir -p "$DIST_DIR"

# Copia o executável
cp "$OUTPUT_DIR/$APP_NAME.exe" "$DIST_DIR/"

# Copia o ícone
cp "$ICON" "$DIST_DIR/" 2>/dev/null || true

# Copia o logo se existir
cp logo.png "$DIST_DIR/" 2>/dev/null || echo "  Aviso: logo.png não encontrado (opcional)"

# Cria o instalador/launcher PowerShell
cat > "$DIST_DIR/Instalar_ZeScanPro.ps1" << 'PSEOF'
# ═══════════════════════════════════════════════════════════════════
#  Instalar_ZeScanPro.ps1
#  Instalador automático do ZeScan Pro para Windows
#  Execute como Administrador: clique direito → "Executar como admin"
# ═══════════════════════════════════════════════════════════════════

param([switch]$Uninstall)

$APP_NAME    = "ZeScan Pro"
$INSTALL_DIR = "$env:ProgramFiles\Zebyte\ZeScanPro"
$SCRIPT_DIR  = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "  ██████╗ ███████╗██████╗ ██╗   ██╗████████╗███████╗" -ForegroundColor Cyan
Write-Host "  ╚══███╔╝██╔════╝██╔══██╗╚██╗ ██╔╝╚══██╔══╝██╔════╝" -ForegroundColor Cyan
Write-Host "    ███╔╝ █████╗  ██████╔╝ ╚████╔╝    ██║   █████╗  " -ForegroundColor Cyan
Write-Host "   ███╔╝  ██╔══╝  ██╔══██╗  ╚██╔╝     ██║   ██╔══╝  " -ForegroundColor Cyan
Write-Host "  ███████╗███████╗██████╔╝   ██║       ██║   ███████╗" -ForegroundColor Cyan
Write-Host "  ╚══════╝╚══════╝╚═════╝    ╚═╝       ╚═╝   ╚══════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  $APP_NAME — Instalador" -ForegroundColor White
Write-Host "  Zebyte Consulting" -ForegroundColor Gray
Write-Host ""

# Verifica privilégio de administrador
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "  [ERRO] Execute como Administrador!" -ForegroundColor Red
    Write-Host "  Clique direito no script e selecione 'Executar como administrador'" -ForegroundColor Yellow
    pause
    exit 1
}

if ($Uninstall) {
    Write-Host "  Desinstalando $APP_NAME..." -ForegroundColor Yellow
    if (Test-Path $INSTALL_DIR) { Remove-Item $INSTALL_DIR -Recurse -Force }
    $desktop = [Environment]::GetFolderPath("Desktop")
    $shortcut = "$desktop\ZeScan Pro.lnk"
    if (Test-Path $shortcut) { Remove-Item $shortcut -Force }
    # Remove entradas do registro de licença
    Remove-Item "HKCU:\Software\Zebyte\ZeScan" -Recurse -ErrorAction SilentlyContinue
    Write-Host "  ✓ Desinstalado com sucesso!" -ForegroundColor Green
    pause
    exit 0
}

# ── Passo 1: Instala Nmap ────────────────────────────────────────────────
Write-Host "  [1/4] Verificando Nmap..." -ForegroundColor Cyan

$nmapPath = Get-Command nmap -ErrorAction SilentlyContinue
if ($nmapPath) {
    Write-Host "  ✓ Nmap já instalado: $($nmapPath.Source)" -ForegroundColor Green
} else {
    Write-Host "  Nmap não encontrado. Instalando..." -ForegroundColor Yellow
    
    # Tenta winget primeiro
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        Write-Host "  Instalando via winget..." -ForegroundColor Gray
        winget install --id Insecure.Nmap --silent --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  ✓ Nmap instalado via winget!" -ForegroundColor Green
        }
    }
    
    # Fallback: download direto
    if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) {
        $nmapUrl      = "https://nmap.org/dist/nmap-7.95-setup.exe"
        $nmapInstaller = "$env:TEMP\nmap-setup.exe"
        
        Write-Host "  Baixando Nmap (~30 MB)..." -ForegroundColor Gray
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            (New-Object Net.WebClient).DownloadFile($nmapUrl, $nmapInstaller)
            Write-Host "  Executando instalador Nmap..." -ForegroundColor Gray
            Start-Process $nmapInstaller -ArgumentList "/S" -Wait
            Remove-Item $nmapInstaller -Force -ErrorAction SilentlyContinue
            
            # Atualiza PATH da sessão
            $env:PATH += ";C:\Program Files (x86)\Nmap"
            Write-Host "  ✓ Nmap instalado!" -ForegroundColor Green
        } catch {
            Write-Host "  ✗ Falha ao instalar Nmap: $_" -ForegroundColor Red
            Write-Host "  Baixe manualmente em: https://nmap.org/download.html" -ForegroundColor Yellow
        }
    }
}

# ── Passo 2: Instala o ZeScan Pro ────────────────────────────────────────
Write-Host ""
Write-Host "  [2/4] Instalando ZeScan Pro em $INSTALL_DIR..." -ForegroundColor Cyan

New-Item -ItemType Directory -Force -Path $INSTALL_DIR | Out-Null
Copy-Item "$SCRIPT_DIR\ZeScanPro.exe" $INSTALL_DIR -Force
Copy-Item "$SCRIPT_DIR\zescan.ico"    $INSTALL_DIR -Force -ErrorAction SilentlyContinue
Copy-Item "$SCRIPT_DIR\logo.png"      $INSTALL_DIR -Force -ErrorAction SilentlyContinue

# Cria script de desinstalação
$uninstallScript = "$INSTALL_DIR\Desinstalar.ps1"
Copy-Item $MyInvocation.MyCommand.Path $uninstallScript -Force
Write-Host "  ✓ Arquivos copiados" -ForegroundColor Green

# ── Passo 3: Cria atalho na Área de Trabalho ─────────────────────────────
Write-Host ""
Write-Host "  [3/4] Criando atalho na Área de Trabalho..." -ForegroundColor Cyan

$desktop     = [Environment]::GetFolderPath("Desktop")
$shortcutPath = "$desktop\ZeScan Pro.lnk"
$iconPath    = "$INSTALL_DIR\zescan.ico"

$WshShell   = New-Object -comObject WScript.Shell
$Shortcut   = $WshShell.CreateShortcut($shortcutPath)
$Shortcut.TargetPath       = "$INSTALL_DIR\ZeScanPro.exe"
$Shortcut.WorkingDirectory = $INSTALL_DIR
$Shortcut.IconLocation     = $iconPath
$Shortcut.Description      = "ZeScan Pro — Auditoria de Rede"

# Pede privilégio elevado ao iniciar (necessário para raw sockets do Nmap)
$Shortcut.Save()

# Marca o atalho para "Executar como administrador" via flags
$bytes = [System.IO.File]::ReadAllBytes($shortcutPath)
$bytes[0x15] = $bytes[0x15] -bor 0x20   # bit RunAsAdmin
[System.IO.File]::WriteAllBytes($shortcutPath, $bytes)

Write-Host "  ✓ Atalho criado: $shortcutPath" -ForegroundColor Green

# ── Passo 4: Adiciona ao PATH do sistema ─────────────────────────────────
Write-Host ""
Write-Host "  [4/4] Adicionando ao PATH do sistema..." -ForegroundColor Cyan

$currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($currentPath -notlike "*ZeScanPro*") {
    [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$INSTALL_DIR", "Machine")
    Write-Host "  ✓ PATH atualizado" -ForegroundColor Green
} else {
    Write-Host "  ✓ Já no PATH" -ForegroundColor Green
}

# ── Resumo ───────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ══════════════════════════════════════" -ForegroundColor Cyan
Write-Host "   ✅  ZeScan Pro instalado com sucesso!" -ForegroundColor Green
Write-Host "  ══════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "  • Atalho criado na Área de Trabalho" -ForegroundColor White
Write-Host "  • Instalado em: $INSTALL_DIR" -ForegroundColor White
Write-Host "  • Execute sempre como Administrador" -ForegroundColor Yellow
Write-Host "  • Licença válida por 2 dias a partir da 1ª execução" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Para desinstalar, execute:" -ForegroundColor Gray
Write-Host "  powershell -File '$uninstallScript' -Uninstall" -ForegroundColor Gray
Write-Host ""

$launch = Read-Host "  Deseja iniciar o ZeScan Pro agora? (S/N)"
if ($launch -match "^[Ss]") {
    Start-Process "$INSTALL_DIR\ZeScanPro.exe" -Verb RunAs
}

pause
PSEOF

# ── 7. Cria README ────────────────────────────────────────────────────────
cat > "$DIST_DIR/LEIAME.txt" << 'RMEOF'
ZeScan Pro v1.0 — Auditoria de Rede
Zebyte Consulting
════════════════════════════════════════

INSTALAÇÃO AUTOMÁTICA (Windows):
─────────────────────────────────
1. Clique direito em "Instalar_ZeScanPro.ps1"
2. Selecione "Executar com PowerShell como administrador"
3. O instalador irá:
   • Instalar o Nmap automaticamente (via winget ou download)
   • Copiar o ZeScan Pro para Arquivos de Programas
   • Criar atalho "ZeScan Pro" na Área de Trabalho
   • Configurar execução automática como administrador

LICENÇA:
────────
• A licença é válida por 2 dias a partir da primeira execução.
• Após expirar, entre em contato com a Zebyte Consulting.
• A licença é vinculada a esta máquina específica.

REQUISITOS:
───────────
• Windows 10/11 (64-bit)
• Conexão com a internet (para instalar Nmap e baixar base OUI)
• Privilégio de administrador (necessário para scan raw de rede)

SUPORTE:
────────
contato@zebyte.com.br
RMEOF

# ── 8. Compacta para distribuição ────────────────────────────────────────
echo "▶ Compactando pacote de distribuição..."
cd "$OUTPUT_DIR"
zip -r "ZeScanPro_v${VERSION}_Windows.zip" "ZeScanPro_v${VERSION}_Windows/"
cd ..

ZIP_SIZE=$(du -sh "$OUTPUT_DIR/ZeScanPro_v${VERSION}_Windows.zip" | cut -f1)
echo "  ✓ ZeScanPro_v${VERSION}_Windows.zip ($ZIP_SIZE)"

# ── Resumo final ──────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════"
echo "  ✅  Build concluído!"
echo "════════════════════════════════════════"
echo ""
echo "  Arquivos gerados:"
echo "  • $OUTPUT_DIR/$APP_NAME.exe"
echo "  • $OUTPUT_DIR/ZeScanPro_v${VERSION}_Windows.zip"
echo ""
echo "  Conteúdo do pacote:"
ls -la "$DIST_DIR/"
echo ""
echo "  Para distribuir: envie o ZIP ao cliente."
echo "  O cliente descompacta e executa:"
echo "  Instalar_ZeScanPro.ps1 (como administrador)"
echo ""
