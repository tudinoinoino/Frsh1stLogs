$flags = @()
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Nota: sessione non elevata - la lettura del Security event log potrebbe risultare incompleta. Solo lettura, nessuna modifica verra' applicata." -ForegroundColor DarkYellow
}

Write-Host "SYSTEM BOOT TIME" -ForegroundColor Cyan
$os = Get-CimInstance Win32_OperatingSystem
$boot = $os.LastBootUpTime
$uptime = (Get-Date) - $boot
Write-Host "  Last Boot (WMI): $boot"
Write-Host "  Uptime (WMI): $($uptime.Days) days, $($uptime.Hours):$($uptime.Minutes):$($uptime.Seconds)"

$coreEventIds = 6005,6006,6008,6013,1074,41,12,13,104,7036,1102,4616
$coreEvents = Get-WinEvent -FilterHashtable @{LogName='System','Security'; Id=$coreEventIds} -MaxEvents 400 -ErrorAction SilentlyContinue
$bootEvents = $coreEvents | Where-Object { $_.LogName -eq 'System' -and $_.Id -in 6005,6006,6008,6013,1074,41,12,13 }

$lastStart12   = $bootEvents | Where-Object { $_.Id -eq 12 -and $_.ProviderName -eq 'Microsoft-Windows-Kernel-General' } | Sort-Object TimeCreated -Descending | Select-Object -First 1
$lastStop13    = $bootEvents | Where-Object { $_.Id -eq 13 -and $_.ProviderName -eq 'Microsoft-Windows-Kernel-General' } | Sort-Object TimeCreated -Descending | Select-Object -First 1
$lastEvtStart6005 = $bootEvents | Where-Object { $_.Id -eq 6005 } | Sort-Object TimeCreated -Descending | Select-Object -First 1
$lastEvtStop6006  = $bootEvents | Where-Object { $_.Id -eq 6006 } | Sort-Object TimeCreated -Descending | Select-Object -First 1
$lastDirty6008    = $bootEvents | Where-Object { $_.Id -eq 6008 } | Sort-Object TimeCreated -Descending | Select-Object -First 1
$lastUnexpected41 = $bootEvents | Where-Object { $_.Id -eq 41 }   | Sort-Object TimeCreated -Descending | Select-Object -First 1
$last1074      = $bootEvents | Where-Object { $_.Id -eq 1074 } | Sort-Object TimeCreated -Descending | Select-Object -First 1
$last6013      = $bootEvents | Where-Object { $_.Id -eq 6013 } | Sort-Object TimeCreated -Descending | Select-Object -First 1

$reliableBoot = $null
$reliableSource = $null
if ($lastStart12) {
    $reliableBoot = $lastStart12.TimeCreated
    $reliableSource = "Event ID 12 (Kernel-General, avvio kernel)"
} elseif ($lastEvtStart6005) {
    $reliableBoot = $lastEvtStart6005.TimeCreated
    $reliableSource = "Event ID 6005 (avvio servizio Event Log)"
} else {
    $reliableBoot = $boot
    $reliableSource = "WMI Win32_OperatingSystem.LastBootUpTime (nessun evento 12/6005 disponibile)"
}

Write-Host "  Ultimo Boot (piu' affidabile): $reliableBoot" -ForegroundColor Green
Write-Host "  Fonte: $reliableSource"

$deltaWmi = [math]::Abs(($reliableBoot - $boot).TotalSeconds)
if ($deltaWmi -gt 60) {
    Write-Host "  Discrepanza tra boot time da evento e da WMI: $([math]::Round($deltaWmi,1))s" -ForegroundColor Red
    $flags += "Il Last Boot Time da evento log ($reliableSource) differisce di oltre 60s da quello riportato da WMI - possibile manipolazione dell'orologio di sistema o del log"
}

if ($lastUnexpected41 -and $lastUnexpected41.TimeCreated -lt $reliableBoot -and ((New-TimeSpan -Start $lastUnexpected41.TimeCreated -End $reliableBoot).TotalMinutes -lt 15)) {
    Write-Host "  Riavvio precedente non pulito (Event ID 41 - Kernel-Power) rilevato poco prima dell'ultimo boot: $($lastUnexpected41.TimeCreated)" -ForegroundColor Yellow
    $flags += "Rilevato spegnimento anomalo/non pianificato (Event ID 41, Kernel-Power) poco prima dell'ultimo avvio - possibile crash, distacco alimentazione o hard reset"
}

if ($lastDirty6008) {
    Write-Host "  Precedente spegnimento inaspettato rilevato (Event ID 6008): $($lastDirty6008.TimeCreated)" -ForegroundColor Yellow
    $flags += "Rilevato spegnimento inaspettato precedente (Event ID 6008) - il sistema non e' stato chiuso correttamente in un'occasione passata"
}

if ($last1074) {
    Write-Host "  Ultimo arresto/riavvio pianificato dall'utente (Event ID 1074): $($last1074.TimeCreated)"
}
if ($lastEvtStop6006) {
    Write-Host "  Ultimo arresto pulito registrato (Event ID 6006): $($lastEvtStop6006.TimeCreated)"
}
if ($last6013) {
    Write-Host "  Ultimo report uptime giornaliero (Event ID 6013): $($last6013.TimeCreated)"
}
if (-not $bootEvents) {
    Write-Host "  Nessun evento di boot/shutdown (6005/6006/6008/6013/1074/41/12/13) trovato nel System log" -ForegroundColor DarkGray
}

$explorer = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | Select-Object -First 1
if ($explorer) {
    $explorerStart = $explorer.CreationDate
    $delay = $explorerStart - $reliableBoot
    $suspicious = $delay.TotalMinutes -gt 5
    $c = if ($suspicious) { 'Red' } else { 'Green' }
    Write-Host "  Explorer.exe avviato: $explorerStart (dopo $([math]::Round($delay.TotalSeconds,1))s dal boot)" -ForegroundColor $c
    if ($suspicious) { $flags += "Explorer.exe avviato con oltre 5 minuti di ritardo dal boot - possibile avvio manuale/ritardato o sessione anomala" }
} else {
    Write-Host "  Explorer.exe non in esecuzione" -ForegroundColor Red
    $flags += "explorer.exe non risulta in esecuzione"
}

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
$sysCleared = $coreEvents | Where-Object { $_.LogName -eq 'System' -and $_.Id -eq 104 }
$shutdown = $last1074, $lastEvtStop6006 | Where-Object { $_ } | Sort-Object TimeCreated -Descending | Select-Object -First 1

$secCleared = $coreEvents | Where-Object { $_.LogName -eq 'Security' -and $_.Id -eq 1102 }
$timeChange = $coreEvents | Where-Object { $_.LogName -eq 'Security' -and $_.Id -eq 4616 } | Select-Object -First 1

if ($secCleared) {
    foreach ($e in $secCleared) { Write-Host "  Security log cleared at: $($e.TimeCreated)" -ForegroundColor Red }
    $flags += "Security event log risulta svuotato manualmente (Event ID 1102) - FONDAMENTALE: se coincide con l'orario del controllo, e' BAN per pulizia"
} else {
    Write-Host "  Security log: nessuna cancellazione registrata (Event ID 1102 non trovato)"
}

if ($sysCleared) {
    foreach ($e in $sysCleared) { Write-Host "  System log cleared at: $($e.TimeCreated)" -ForegroundColor Red }
    $flags += "System event log risulta svuotato manualmente (Event ID 104) - FONDAMENTALE: se coincide con l'orario del controllo, e' BAN per pulizia"
} else {
    Write-Host "  System log: nessuna cancellazione registrata (Event ID 104 non trovato)"
}

if ($shutdown) { Write-Host "  Last PC Shutdown at: $($shutdown.TimeCreated)" }

if ($timeChange) {
    Write-Host "  System time changed at: $($timeChange.TimeCreated)" -ForegroundColor Yellow
    $flags += "Rilevato cambio manuale dell'orologio di sistema (Event ID 4616) - possibile tentativo di alterare timestamp per camuffare i log"
}

Write-Host "`nPROCESS CREATION (Event ID 4688)" -ForegroundColor Cyan
$procEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 50 -ErrorAction SilentlyContinue
if ($procEvents) {
    $suspiciousProcPattern = 'cmd\.exe|powershell\.exe|pwsh\.exe|\.bat$|\.ps1$|cheat|inject'
    $suspiciousProcs = $procEvents | Where-Object { $_.Message -match $suspiciousProcPattern }
    foreach ($e in ($suspiciousProcs | Select-Object -First 10)) {
        $nameLine = ($e.Message -split "`n" | Select-String 'New Process Name' | Select-Object -First 1)
        Write-Host "  $($e.TimeCreated): $($nameLine -replace '^\s+','')" -ForegroundColor Yellow
    }
    if ($suspiciousProcs) {
        $flags += "Rilevati avvii di processi sospetti (cmd/powershell/script .bat/.ps1/cheat) via Event ID 4688 - $($suspiciousProcs.Count) occorrenze"
    } else {
        Write-Host "  Nessun processo sospetto rilevato tra gli ultimi eventi 4688"
    }
} else {
    Write-Host "  Nessun evento 4688 trovato (Auditing avvio processi probabilmente non attivo su questo PC)" -ForegroundColor DarkGray
}

Write-Host "`nSERVICE STATE CHANGES (Event ID 7036)" -ForegroundColor Cyan
$svcEvents = $coreEvents | Where-Object { $_.LogName -eq 'System' -and $_.Id -eq 7036 }
if ($svcEvents) {
    $criticalSvcPattern = 'Windows Event Log|Windows Defender|Security Center|Sense|WinDefend'
    $criticalSvcStops = $svcEvents | Where-Object { $_.Message -match $criticalSvcPattern -and $_.Message -match 'stopped' }
    foreach ($e in ($criticalSvcStops | Select-Object -First 10)) {
        $msgOneLine = $e.Message -replace "`n", ' '
        Write-Host "  $($e.TimeCreated): $msgOneLine" -ForegroundColor Red
    }
    if ($criticalSvcStops) {
        $flags += "Rilevato arresto forzato di servizi critici di log/sicurezza (Event ID 7036) - $($criticalSvcStops.Count) occorrenze"
    } else {
        Write-Host "  Nessun arresto sospetto di servizi critici tra gli ultimi eventi 7036"
    }
} else {
    Write-Host "  Nessun evento 7036 trovato" -ForegroundColor DarkGray
}

Write-Host "`nUSB REMOVABLE STORAGE (Event ID 2003/2102)" -ForegroundColor Cyan
$usbEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DriverFrameworks-UserMode/Operational'; Id=2003,2102} -MaxEvents 20 -ErrorAction SilentlyContinue
if ($usbEvents) {
    foreach ($e in $usbEvents) {
        $action = if ($e.Id -eq 2003) { 'Inserita' } else { 'Rimossa' }
        Write-Host "  $($e.TimeCreated): chiavetta USB $action (Event ID $($e.Id))" -ForegroundColor Yellow
    }
    $flags += "Rilevati $($usbEvents.Count) eventi di inserimento/rimozione USB (ID 2003/2102) - verificare se coincidono con l'orario del controllo (possibile chiavetta con cheat)"
} else {
    Write-Host "  Nessun evento USB trovato nel log DriverFrameworks-UserMode/Operational" -ForegroundColor DarkGray
}

$fsutilPath = "$env:WINDIR\System32\fsutil.exe"
$usn = & $fsutilPath usn queryjournal C: 2>&1
$lastDeleted = $null
if ($usn -match "not found" -or $usn -match "non trovato" -or $LASTEXITCODE -ne 0) {
    Write-Host "  USN Journal: non trovato/vuoto" -ForegroundColor Red
    $flags += "USN Journal assente - potrebbe essere stato cancellato (fsutil usn deletejournal) per rimuovere tracce filesystem"
} else {
    Write-Host "  USN Journal: presente"
    $nextUsnLine = $usn | Select-String "Next Usn"
    if ($nextUsnLine -and $isAdmin) {
        $nextUsn = ($nextUsnLine -replace '\D', '')
        $startUsn = [int64]$nextUsn - 1500000
        if ($startUsn -lt 0) { $startUsn = 0 }
        $raw = & $fsutilPath usn readjournal C: startusn=$startUsn 2>&1
        $blocks = ($raw -join "`n") -split "(?=Usn\s*:)"
        $deletions = foreach ($b in $blocks) {
            if ($b -match 'Reason\s*:\s*.*FileDelete') {
                $fn = if ($b -match 'File name\s*:\s*(.+)') { $matches[1].Trim() } else { $null }
                $ts = if ($b -match 'Time [Ss]tamp\s*:\s*(.+)') { $matches[1].Trim() } else { $null }
                if ($fn -and $ts) {
                    [PSCustomObject]@{ FileName = $fn; TimeStamp = ($ts -as [datetime]) }
                }
            }
        }
        $lastDeleted = $deletions | Sort-Object TimeStamp -Descending | Select-Object -First 1
    } elseif (-not $isAdmin) {
        Write-Host "  (serve sessione Amministratore per leggere il dettaglio del journal ed elencare l'ultimo file eliminato)" -ForegroundColor DarkYellow
    }
}

Write-Host "`nPREFETCH" -ForegroundColor Cyan
$pfPath = "$env:WINDIR\Prefetch"
Write-Host "  Enabled: $(if ($prefetch -gt 0) {'Si'} else {'No'})"
if (Test-Path $pfPath) {
    Write-Host "  Path: $pfPath"
} else {
    Write-Host "  Path non trovato (cartella rinominata/spostata o accesso negato)" -ForegroundColor Yellow
    $flags += "Cartella Prefetch non trovata al percorso standard"
}

Write-Host "`nSTARTUP ITEMS" -ForegroundColor Cyan
$startupItems = Get-CimInstance Win32_StartupCommand
$suspiciousPathPattern = 'AppData\\Local\\Temp|\\Temp\\|Downloads'
foreach ($s in $startupItems) {
    $isSuspicious = $s.Command -match $suspiciousPathPattern
    $c = if ($isSuspicious) { 'Red' } else { 'DarkGray' }
    Write-Host "  [$($s.Location)] $($s.Name): $($s.Command)" -ForegroundColor $c
    if ($isSuspicious) { $flags += "Voce di avvio automatico sospetta: $($s.Name) ($($s.Command))" }
}

Write-Host "`nRECYCLE BIN" -ForegroundColor Cyan
$shell = New-Object -ComObject Shell.Application
$recycleBin = $shell.Namespace(0xA)
$items = $recycleBin.Items()
Write-Host "  Total Items: $($items.Count)"
if ($items.Count -gt 0) {
    if ($items.Count -gt 500) {
        Write-Host "  Troppi elementi ($($items.Count)) per un controllo dettagliato rapido - salto ordinamento per data" -ForegroundColor DarkGray
    } else {
        $lastItem = $items | Sort-Object { $recycleBin.GetDetailsOf($_, 2) -as [datetime] } -Descending | Select-Object -First 1
        if ($lastItem) {
            Write-Host "  Ultimo file eliminato ancora nel cestino: $($lastItem.Name)"
            Write-Host "  Data eliminazione: $($recycleBin.GetDetailsOf($lastItem, 2))"
        }
    }
} else {
    Write-Host "  Cestino vuoto" -ForegroundColor Yellow
    $flags += "Cestino completamente vuoto - possibile svuotamento manuale recente (verificare se coerente con l'uso normale)"
}
if ($lastDeleted) {
    Write-Host "  Ultima cancellazione file rilevata da USN Journal: $($lastDeleted.FileName) alle $($lastDeleted.TimeStamp)" -ForegroundColor Yellow
} elseif ($isAdmin) {
    Write-Host "  Nessuna cancellazione file rilevata nel range del journal analizzato" -ForegroundColor DarkGray
}

Write-Host "`nSYSTEM BINARY INTEGRITY (calc.exe)" -ForegroundColor Cyan
$calcPath = "$env:WINDIR\System32\calc.exe"
if (Test-Path $calcPath) {
    $calcFile = Get-Item $calcPath
    $sig = Get-AuthenticodeSignature -FilePath $calcPath
    Write-Host "  Path: $calcPath"
    Write-Host "  Last Modified: $($calcFile.LastWriteTime)"
    Write-Host "  Size: $([math]::Round($calcFile.Length/1KB,2)) KB"
    $sigColor = if ($sig.Status -eq 'Valid') { 'Green' } else { 'Red' }
    Write-Host "  Firma digitale: $($sig.Status)" -ForegroundColor $sigColor
    if ($sig.Status -ne 'Valid') { $flags += "calc.exe non ha una firma digitale valida (Status=$($sig.Status)) - possibile sostituzione/binary planting" }
} else {
    Write-Host "  calc.exe non trovato al percorso standard - potrebbe essere stato rinominato/spostato" -ForegroundColor Yellow
    $flags += "calc.exe assente dal percorso standard System32 - verificare se rinominato o sostituito"
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
