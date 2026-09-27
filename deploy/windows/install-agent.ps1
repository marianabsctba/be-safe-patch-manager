param(
  [Parameter(Mandatory=$true)][string]$ServerUrl,
  [string]$EnrollmentToken = "",
  [string[]]$Tags = @("piloto"),
  [string]$ClientCertificatePath = "",
  [string]$ClientKeyPath = "",
  [string]$CaCertificatePath = "",
  [string]$UpdatePublicKeyPath = ""
)
$ErrorActionPreference = "Stop"

if (-not $ServerUrl.StartsWith("https://", [System.StringComparison]::OrdinalIgnoreCase)) {
  throw "ServerUrl deve usar https://."
}

if ([string]::IsNullOrWhiteSpace($EnrollmentToken)) {
  $SecureEnrollmentToken = Read-Host "Enrollment token" -AsSecureString
  $Bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureEnrollmentToken)
  try {
    $EnrollmentToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Bstr)
  }
  finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr)
  }
}

if ([string]::IsNullOrWhiteSpace($EnrollmentToken)) {
  throw "Enrollment token vazio."
}

if (
  ([string]::IsNullOrWhiteSpace($ClientCertificatePath) -and -not [string]::IsNullOrWhiteSpace($ClientKeyPath)) -or
  (-not [string]::IsNullOrWhiteSpace($ClientCertificatePath) -and [string]::IsNullOrWhiteSpace($ClientKeyPath))
) {
  throw "ClientCertificatePath e ClientKeyPath devem ser informados juntos."
}

foreach ($PathItem in @($ClientCertificatePath, $ClientKeyPath, $CaCertificatePath, $UpdatePublicKeyPath)) {
  if (-not [string]::IsNullOrWhiteSpace($PathItem) -and -not (Test-Path -LiteralPath $PathItem -PathType Leaf)) {
    throw "Arquivo TLS não encontrado: $PathItem"
  }
}

$Base = "C:\ProgramData\PatchManager"
$TlsBase = Join-Path $Base "tls"
$UpdateTrustBase = Join-Path $Base "update-trust"
$UpdateStagingBase = Join-Path $Base "updates"
$ConfigPath = Join-Path $Base "agent.json"
New-Item -ItemType Directory -Force -Path $Base | Out-Null
New-Item -ItemType Directory -Force -Path $TlsBase | Out-Null
New-Item -ItemType Directory -Force -Path $UpdateTrustBase | Out-Null
New-Item -ItemType Directory -Force -Path $UpdateStagingBase | Out-Null

Copy-Item "$PSScriptRoot\..\..\agent\patch_agent.py" "$Base\patch_agent.py" -Force
Copy-Item "$PSScriptRoot\..\..\agent\requirements.txt" "$Base\requirements.txt" -Force
python -m venv "$Base\.venv"
& "$Base\.venv\Scripts\python.exe" -m pip install --upgrade pip
& "$Base\.venv\Scripts\pip.exe" install -r "$Base\requirements.txt"

$ClientCertTarget = ""
$ClientKeyTarget = ""
$CaCertTarget = ""

if (-not [string]::IsNullOrWhiteSpace($ClientCertificatePath)) {
  $ClientCertTarget = Join-Path $TlsBase "agent.crt"
  $ClientKeyTarget = Join-Path $TlsBase "agent.key"
  Copy-Item -LiteralPath $ClientCertificatePath -Destination $ClientCertTarget -Force
  Copy-Item -LiteralPath $ClientKeyPath -Destination $ClientKeyTarget -Force
}

if (-not [string]::IsNullOrWhiteSpace($CaCertificatePath)) {
  $CaCertTarget = Join-Path $TlsBase "server-ca.crt"
  Copy-Item -LiteralPath $CaCertificatePath -Destination $CaCertTarget -Force
}

$UpdatePublicKeyTarget = ""
if (-not [string]::IsNullOrWhiteSpace($UpdatePublicKeyPath)) {
  $UpdatePublicKeyTarget = Join-Path $UpdateTrustBase "agent-update-public.pem"
  Copy-Item -LiteralPath $UpdatePublicKeyPath -Destination $UpdatePublicKeyTarget -Force
}

@{
  server_url=$ServerUrl
  enrollment_token=$EnrollmentToken
  agent_id=""
  agent_token=""
  tags=$Tags
  poll_seconds=60
  scan_every_seconds=1800
  tls_verify=$true
  ca_cert=$CaCertTarget
  client_cert=$ClientCertTarget
  client_key=$ClientKeyTarget
  update_public_key=$UpdatePublicKeyTarget
  update_check_seconds=21600
  update_staging_dir=$UpdateStagingBase
} | ConvertTo-Json | Set-Content -Encoding UTF8 $ConfigPath

# Restrict credential-bearing files to LocalSystem and Administrators.
foreach ($ProtectedPath in @($ConfigPath, $ClientKeyTarget)) {
  if (-not [string]::IsNullOrWhiteSpace($ProtectedPath) -and (Test-Path -LiteralPath $ProtectedPath)) {
    & icacls.exe $ProtectedPath /inheritance:r | Out-Null
    & icacls.exe $ProtectedPath /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
  }
}

foreach ($ProtectedDirectory in @($UpdateStagingBase, $UpdateTrustBase)) {
  & icacls.exe $ProtectedDirectory /inheritance:r | Out-Null
  & icacls.exe $ProtectedDirectory /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' | Out-Null
}

$EnrollmentToken = $null
$SecureEnrollmentToken = $null

$PythonExe = Join-Path $Base ".venv\Scripts\python.exe"
$AgentScript = Join-Path $Base "patch_agent.py"
$TaskArguments = '"'+ $AgentScript + '" --config "' + $ConfigPath + '"'
$Action = New-ScheduledTaskAction -Execute $PythonExe -Argument $TaskArguments
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -RestartCount 99 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 3650)
Register-ScheduledTask -TaskName "PatchManagerAgent" -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName "PatchManagerAgent"
Write-Host "Patch Manager Agent instalado e iniciado."
