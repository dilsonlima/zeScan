# 1. Eleva privilégios para Administrador
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Write-Host "--- Configurando Ambiente Zebyte Consulting ---" -ForegroundColor Cyan

# 2. Instala o Nmap e Npcap via Winget (Nativo do Windows 10/11)
Write-Host "Instalando Nmap e Drivers de Rede..."
winget install --id Insecure.Nmap --silent --accept-package-agreements --accept-source-agreements

# 3. Cria o atalho na Área de Trabalho
$TargetFile = "$PSScriptRoot\ZeScanPro.exe"
$ShortcutFile = "$env:USERPROFILE\Desktop\ZeScan Pro.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $TargetFile
$Shortcut.IconLocation = "$TargetFile,0"
$Shortcut.Save()

Write-Host "✅ Tudo pronto! O atalho foi criado na sua Área de Trabalho." -ForegroundColor Green
Pause