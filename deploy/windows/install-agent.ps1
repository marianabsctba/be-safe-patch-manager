param(
  [Parameter(Mandatory=$true)][string]$ServerUrl,
  [string]$EnrollmentToken = "",
  [string[]]$Tags = @("piloto")
)
$ErrorActionPreference = "Stop"

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

$Base = "C:\ProgramData\PatchManager"
$ConfigPath = Join-Path $Base "agent.json"
New-Item -ItemType Directory -Force -Path $Base | Out-Null
Copy-Item "$PSScriptRoot\..\..\agent\patch_agent.py" "$Base\patch_agent.py" -Force
Copy-Item "$PSScriptRoot\..\..\agent\requirements.txt" "$Base\requirements.txt" -Force
python -m venv "$Base\.venv"
& "$Base\.venv\Scripts\python.exe" -m pip install --upgrade pip
& "$Base\.venv\Scripts\pip.exe" install -r "$Base\requirements.txt"
@{
  server_url=$ServerUrl
  enrollment_token=$EnrollmentToken
  agent_id=""
  agent_token=""
  tags=$Tags
  poll_seconds=60
  scan_every_seconds=1800
  tls_verify=$true
} | ConvertTo-Json | Set-Content -Encoding UTF8 $ConfigPath

# Remove inherited permissions and restrict the credential-bearing config to
# LocalSystem and the built-in Administrators group by SID (locale independent).
& icacls.exe $ConfigPath /inheritance:r | Out-Null
& icacls.exe $ConfigPath /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
$EnrollmentToken = $null
$SecureEnrollmentToken = $null

$Action = New-ScheduledTaskAction -Execute "$Base\.venv\Scripts\python.exe" -Argument "`"$Base\patch_agent.py`" --config `"$ConfigPath`""
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -RestartCount 99 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 3650)
Register-ScheduledTask -TaskName "PatchManagerAgent" -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName "PatchManagerAgent"
Write-Host "Patch Manager Agent instalado e iniciado."
