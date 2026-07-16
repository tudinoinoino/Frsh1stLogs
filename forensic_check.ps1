$flags = @()

Write-Host "SYSTEM BOOT TIME" -ForegroundColor Cyan
$os = Get-CimInstance Win32_OperatingSystem
$boot = $os.LastBootUpTime
$uptime = (Get-Date) - $boot
Write-Host "  Last Boot: $boot"
Write-Host "  Uptime: $($uptime.Days) days, $($uptime.Hours):$($uptime.Minutes):$($uptime.Seconds)"

Write-Host "`nCONNECTED DRIVES" -ForegroundColor Cyan
Get-CimInstance Win32_LogicalDisk | ForEach-Object {
    Write-Host "  $($_.DeviceID) $($_.FileSystem)"
}

Write-Host "`nSERVICE STATUS" -ForegroundColor Cyan
$svcNames = @{
    SysMain   = "Superfetch/SysMain"
    PcaSvc    = "Program Compatibility Assistant"
    Bam       = "Background Activity Moderator"
    Schedule  = "Task Scheduler"
    EventLog  = "Windows Event Log"
    Dusmsvc   = "Data Usage"
    DPS       = "Diagnostic Policy Service"
    CDPSvc    = "Connected Devices Platform"
}
foreach ($name in $svcNames.Keys) {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Host "  $name : NOT FOUND" -ForegroundColor DarkGray
        continue
    }
    $color = if ($svc.Status -eq 'Running') { 'Green' } else { 'Red' }
    Write-Host "  $name ($($svcNames[$name])): $($svc.Status) / StartType=$($svc.StartType)" -ForegroundColor $color
    if ($svc.StartType -eq 'Disabled') {
        $flags += "$name e' impostato su Disabled (start type), non solo fermo - anomalia forte"
    } elseif ($svc.Status -ne 'Running') {
        $flags += "$name risulta fermo (potrebbe essere normale o indicare interferenza)"
    }
}

Write-Host "`nREGISTRY" -ForegroundColor Cyan
$cmdDisabled = (Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\System" -Name DisableCMD -ErrorAction SilentlyContinue).DisableCMD
Write-Host "  CMD Disabled policy: $(if ($cmdDisabled) {$cmdDisabled} else {'Not Set'})"
if ($cmdDisabled -eq 1 -or $cmdDisabled -eq 2) { $flags += "CMD risulta disabilitato via policy" }

$psLog = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
Write-Host "  PowerShell ScriptBlock Logging: $(if ($psLog -eq 1) {'Enabled'} else {'Disabled/Not Set'})"
if ($psLog -ne 1) { $flags += "PowerShell ScriptBlock Logging non abilitato - riduce visibilita' su comandi eseguiti" }

$prefetch = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name EnablePrefetcher -ErrorAction SilentlyContinue).EnablePrefetcher
Write-Host "  Prefetch Enabled: $(if ($prefetch -gt 0) {'Enabled'} else {'Disabled'})"
if ($prefetch -eq 0) { $flags += "Prefetch disabilitato - riduce evidenza di esecuzione programmi" }

Write-Host "`nEVENT LOGS" -ForegroundColor Cyan
$secCleared = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 5 -ErrorAction SilentlyContinue
if ($secCleared) {
    foreach ($e in $secCleared) { Write-Host "  Security log cleared at: $($e.TimeCreated)" -ForegroundColor Red }
    $flags += "Security event log risulta svuotato manualmente (Event ID 1102)"
} else {
    Write-Host "  Security log: nessuna cancellazione registrata (Event ID 1102 non trovato)"
}

$sysCleared = Get-WinEvent -FilterHashtable @{LogName='System'; Id=104} -MaxEvents 5 -ErrorAction SilentlyContinue
if ($sysCleared) {
    foreach ($e in $sysCleared) { Write-Host "  System log cleared at: $($e.TimeCreated)" -ForegroundColor Red }
    $flags += "System event log risulta svuotato manualmente (Event ID 104)"
} else {
    Write-Host "  System log: nessuna cancellazione registrata (Event ID 104 non trovato)"
}

$shutdown = Get-WinEvent -FilterHashtable @{LogName='System'; Id=1074,6006} -MaxEvents 1 -ErrorAction SilentlyContinue
if ($shutdown) { Write-Host "  Last PC Shutdown at: $($shutdown.TimeCreated)" }

$timeChange = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4616} -MaxEvents 1 -ErrorAction SilentlyContinue
if ($timeChange) {
    Write-Host "  System time changed at: $($timeChange.TimeCreated)" -ForegroundColor Yellow
    $flags += "Rilevato cambio manuale dell'orologio di sistema (Event ID 4616) - possibile tentativo di alterare timestamp"
}

$usn = fsutil usn queryjournal C: 2>&1
if ($usn -match "not found" -or $usn -match "non trovato" -or $LASTEXITCODE -ne 0) {
    Write-Host "  USN Journal: non trovato/vuoto" -ForegroundColor Red
    $flags += "USN Journal assente - potrebbe essere stato cancellato (fsutil usn deletejournal) per rimuovere tracce filesystem"
} else {
    Write-Host "  USN Journal: presente"
}

Write-Host "`nPREFETCH INTEGRITY" -ForegroundColor Cyan
$pfPath = "$env:WINDIR\Prefetch"
if (Test-Path $pfPath) {
    $pfFiles = Get-ChildItem -Path $pfPath -Filter *.pf -File -ErrorAction SilentlyContinue
    Write-Host "  File .pf trovati: $($pfFiles.Count)"
    $hidden = $pfFiles | Where-Object { $_.Attributes -match 'Hidden' }
    $ro = $pfFiles | Where-Object { $_.IsReadOnly }
    Write-Host "  Hidden Files: $($hidden.Count)"
    Write-Host "  Read-Only Files: $($ro.Count)"
    if ($pfFiles.Count -eq 0) { $flags += "Cartella Prefetch vuota - possibile pulizia manuale o Prefetch disabilitato da tempo" }
} else {
    Write-Host "  Cartella Prefetch non accessibile" -ForegroundColor Red
}

Write-Host "`nRECYCLE BIN" -ForegroundColor Cyan
$shell = New-Object -ComObject Shell.Application
$recycleBin = $shell.Namespace(0xA)
$items = $recycleBin.Items()
Write-Host "  Total Items: $($items.Count)"
if ($items.Count -eq 0) {
    Write-Host "  Cestino vuoto" -ForegroundColor Yellow
    $flags += "Cestino completamente vuoto - possibile svuotamento manuale recente (verificare se coerente con l'uso normale)"
}

Write-Host "`nCONSOLE HOST HISTORY" -ForegroundColor Cyan
$histPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $histPath) {
    $hist = Get-Item $histPath
    Write-Host "  Last Modified: $($hist.LastWriteTime)"
    Write-Host "  Size: $([math]::Round($hist.Length/1KB,2)) KB"
    if ($hist.Length -eq 0) { $flags += "ConsoleHost_history.txt esiste ma e' vuoto - possibile svuotamento manuale della history PowerShell" }
} else {
    Write-Host "  File non trovato" -ForegroundColor Yellow
    $flags += "ConsoleHost_history.txt assente - history PowerShell mai creata o rimossa"
}

Write-Host "`nVERDICT" -ForegroundColor Cyan
if ($flags.Count -eq 0) {
    Write-Host "  Nessuna anomalia rilevata su questi indicatori." -ForegroundColor Green
} else {
    Write-Host "  $($flags.Count) anomalie rilevate:" -ForegroundColor Red
    $flags | ForEach-Object { Write-Host "   - $_" -ForegroundColor Red }
}
