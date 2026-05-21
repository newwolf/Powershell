#Requires -Version 5.1
<#
.SYNOPSIS
    Windows system check with on-screen progress, [SUSPICIOUS] markers, and malware remnant scans.

.PARAMETER RemnantPaths
    Optional paths (file or folder) for extra checks. Empty = generic scans only.

.PARAMETER RemnantPathsFile
    Text file with one path per line (# = comment). Merged with -RemnantPaths.

.EXAMPLE
    .\Windows-SystemCheck.ps1 -NoPrompt

.EXAMPLE
    .\Windows-SystemCheck.ps1 -RemnantPaths 'D:\Temp\old-site','C:\Tools\suspicious.exe'

.EXAMPLE
    .\Windows-SystemCheck.ps1 -RemnantPathsFile "$env:USERPROFILE\Documents\SystemCheck-RemnantPaths.txt"
#>
[CmdletBinding()]
param(
    [string]$OutputFolder = (Join-Path $env:USERPROFILE 'Documents'),
    [switch]$IncludeBootLogCopy,
    [switch]$NoPrompt,
    [string[]]$RemnantPaths = @(),
    [string]$RemnantPathsFile = ''
)

$ErrorActionPreference = 'SilentlyContinue'
$timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$reportPath = Join-Path $OutputFolder "SystemCheck_$timestamp.txt"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
$TotalSteps = 23
$script:ScreenNotes = [System.Collections.Generic.List[string]]::new()
$SuspiciousFindings = [System.Collections.Generic.List[object]]::new()
$script:SuspiciousFindingKeys = @{}
$RemnantResults = [System.Collections.Generic.List[PSCustomObject]]::new()

# Optional extra paths (no fixed machine-specific list)
$ExtraRemnantPaths = [System.Collections.Generic.List[string]]::new()
foreach ($p in $RemnantPaths) {
    if ($p -and $p.Trim()) { [void]$ExtraRemnantPaths.Add($p.Trim()) }
}
if ($RemnantPathsFile) {
    if (Test-Path -LiteralPath $RemnantPathsFile) {
        Get-Content -LiteralPath $RemnantPathsFile | ForEach-Object {
            $line = $_.Trim()
            if ($line -and $line -notmatch '^#') { [void]$ExtraRemnantPaths.Add($line) }
        }
    } else {
        Write-Host "Warning: RemnantPathsFile not found: $RemnantPathsFile" -ForegroundColor Yellow
    }
}
$ExtraRemnantPaths = @($ExtraRemnantPaths | Select-Object -Unique)

function Write-ProgressStep {
    param(
        [int]$Number,
        [string]$Description
    )
    Write-Host ''
    Write-Host "[$Number/$TotalSteps] $Description" -ForegroundColor Cyan
}

function Write-Section {
    param([string]$Title)
    Add-Content -Path $reportPath -Value ("`n" + ('=' * 80))
    Add-Content -Path $reportPath -Value "  $Title"
    Add-Content -Path $reportPath -Value ('=' * 80)
}

function Write-Block {
    param([object]$Data, [string]$Label = '')
    if ($Label) { Add-Content -Path $reportPath -Value "`n--- $Label ---`n" }
    if ($null -eq $Data -or ($Data -is [System.Array] -and $Data.Count -eq 0)) {
        Add-Content -Path $reportPath -Value '(no data)'
        return
    }
    ($Data | Out-String -Width 220).TrimEnd() | Add-Content -Path $reportPath
}

function Add-ScreenNote {
    param([string]$Line)
    [void]$script:ScreenNotes.Add($Line)
}

function Add-SuspiciousFinding {
    param(
        [ValidateSet('HIGH', 'MEDIUM', 'LOW', 'INFO')]
        [string]$Severity,
        [string]$Category,
        [string]$Subject,
        [string]$Action = '',
        [string]$Detail = '',
        [string]$Advice = ''
    )
    if ($Detail -and -not $Subject) { $Subject = $Detail }
    if ($Advice -and -not $Action) { $Action = $Advice }
    if (-not $Action) { $Action = '-' }

    $key = "$Severity|$Category|$Subject|$Action"
    if ($script:SuspiciousFindingKeys[$key]) { return }
    $script:SuspiciousFindingKeys[$key] = $true

    [void]$SuspiciousFindings.Add([PSCustomObject]@{
        Severity  = $Severity
        Category  = $Category
        Subject  = $Subject.Trim()
        Action   = $Action.Trim()
    })
}

function Write-SuspiciousFindingsReport {
    param([switch]$ToConsole)

    if ($SuspiciousFindings.Count -eq 0) { return }

    $order = @{ HIGH = 0; MEDIUM = 1; LOW = 2; INFO = 3 }
    $items = @($SuspiciousFindings | Sort-Object { $order[$_.Severity] }, Category, Subject)

    $header = ('{0,-8} {1}' -f 'RISK', 'SOURCE')
    $rule   = ('{0,-8} {1}' -f ('-' * 8), ('-' * 26))
    $detailPrefix = '         '

    $writeLine = {
        param([string]$Text, [string]$Color = 'Gray')
        if ($ToConsole) {
            Write-Host $Text -ForegroundColor $Color
        } else {
            Add-Content -Path $reportPath -Value $Text
        }
    }

    & $writeLine ''
    & $writeLine $header 'White'
    & $writeLine $rule 'DarkGray'

    foreach ($item in $items) {
        $color = switch ($item.Severity) {
            'HIGH'   { 'Red' }
            'MEDIUM' { 'Yellow' }
            'INFO'   { 'DarkCyan' }
            default  { 'Gray' }
        }

        $row1 = ('{0,-8} {1}' -f $item.Severity, $item.Category)
        $rowAction  = "${detailPrefix}Action:   $($item.Action)"
        $rowSubject = "${detailPrefix}Subject:  $($item.Subject)"

        & $writeLine $row1 $color
        if ($item.Action -and $item.Action -ne '-') {
            & $writeLine $rowAction 'Gray'
        }
        & $writeLine $rowSubject 'Gray'
        & $writeLine '' 'Gray'
    }
}

function Add-RemnantResult {
    param(
        [string]$Check,
        [ValidateSet('PRESENT', 'NOT_FOUND', 'INFO')]
        [string]$Status,
        [string]$Detail,
        [string[]]$SuspiciousFiles = @()
    )
    $flag = switch ($Status) {
        'PRESENT' { '[SUSPICIOUS]' }
        'NOT_FOUND' { '[OK]' }
        'INFO' { '[INFO]' }
    }
    if ($Status -eq 'PRESENT' -and $SuspiciousFiles.Count -gt 0) {
        foreach ($file in $SuspiciousFiles) {
            $filePath = Get-PathFromSuspiciousMessage -Message $file
            $sev = if ($filePath) { Get-SeverityForSuspiciousPath -FilePath $filePath } else { 'HIGH' }
            Add-SuspiciousFinding -Severity $sev -Category 'Remnant' -Subject $file `
                -Action (Get-ActionForSuspiciousMessage -Message $file)
        }
    }
    [void]$RemnantResults.Add([PSCustomObject]@{
        Flag   = $flag
        Check  = $Check
        Status = $Status
        Detail = $Detail
    })
    if ($SuspiciousFiles.Count -gt 0) {
        Add-Content -Path $reportPath -Value "  $flag $Check"
        Add-Content -Path $reportPath -Value "      Status: $Status"
        Add-Content -Path $reportPath -Value "      $Detail"
        Add-Content -Path $reportPath -Value '      Suspicious files:'
        foreach ($file in $SuspiciousFiles) {
            Add-Content -Path $reportPath -Value "        - $file"
        }
    }
}

# File names/paths that indicate malware or web shells
$script:SuspiciousFileRules = @(
    @{ Regex = 'AcPowerNotification\.exe$'; Reason = 'Known malware (AcPowerNotification)' }
    @{ Regex = 'perl\.alfa$|\.alfa$|alfa\.php|alfa\.php\.filepart'; Reason = 'Alfa PHP web shell' }
    @{ Regex = 'ALFA_DATA|alfacgiapi'; Reason = 'Alfa web shell structure' }
    @{ Regex = '\\cats$|\\cats\\'; Reason = 'Suspicious folder from Alfa incident' }
    @{ Regex = 'MAS_AIO|keygen|crack|activat'; Reason = 'Activator/crack tool' }
    @{ Regex = 'ChipGenius|YouTube Downloader|Sidify'; Reason = 'Program previously flagged by Defender' }
)

function Get-DefenderResourceFiles {
    param([object]$Resources)
    $paths = [System.Collections.Generic.List[string]]::new()
    $sources = @($Resources)
    foreach ($res in $sources) {
        if ($null -eq $res) { continue }
        $text = $res.ToString()
        foreach ($m in [regex]::Matches($text, 'file:_((?:[A-Za-z]:\\)[^,}]+)')) {
            [void]$paths.Add($m.Groups[1].Value.Trim())
        }
        foreach ($m in [regex]::Matches($text, 'behavior:_process:\s*([^,]+?)(?=,|\s+pid:|\s+process:)')) {
            $p = $m.Groups[1].Value.Trim()
            if ($p -match '\.exe$') { [void]$paths.Add($p) }
        }
    }
    return @($paths | Select-Object -Unique)
}

function Get-SuspiciousFileAction {
    param(
        [string]$FilePath,
        [switch]$WithScan
    )
    if ([string]::IsNullOrWhiteSpace($FilePath)) {
        return 'Review manually based on the subject line'
    }
    if (Test-Path -LiteralPath $FilePath) {
        $item = Get-Item -LiteralPath $FilePath -Force -ErrorAction SilentlyContinue
        if ($item -and $item.PSIsContainer) {
            $actionText = 'Review this folder contents; remove only suspicious files, not the entire folder'
        } else {
            $actionText = 'Delete this specific file (not the parent folder)'
        }
        if ($WithScan) { $actionText += '; then run a full Defender scan' }
        return $actionText
    }
    return 'No removal needed: file is no longer on disk (Defender history only). Run a full scan to confirm the system is clean'
}

function Get-PathFromSuspiciousMessage {
    param([string]$Message)
    if ($Message -match 'Defender history only \(not on disk\): ([^|]+)') { return $Matches[1].Trim() }
    if ($Message -match 'File \(no longer present\): ([^|]+)') { return $Matches[1].Trim() }
    if ($Message -match '\| (?:File|Folder \(review contents only\)) : ([^|(]+)') { return $Matches[1].Trim() }
    return $null
}

function Get-ActionForSuspiciousMessage {
    param([string]$Message)
    if ($Message -match '^Task:') { return 'Disable or remove the task in taskschd.msc' }
    if ($Message -match '^Process:') { return 'End the process in Task Manager; then delete the exe at the listed path' }
    $filePath = Get-PathFromSuspiciousMessage -Message $Message
    if ($filePath) { return Get-SuspiciousFileAction -FilePath $filePath -WithScan }
    return 'Review manually based on the subject line'
}

function Get-SeverityForSuspiciousPath {
    param(
        [string]$FilePath,
        [ValidateSet('HIGH', 'MEDIUM', 'LOW', 'INFO')]
        [string]$IfPresent = 'HIGH',
        [ValidateSet('HIGH', 'MEDIUM', 'LOW', 'INFO')]
        [string]$IfAbsent = 'INFO'
    )
    if ($FilePath -and (Test-Path -LiteralPath $FilePath)) { return $IfPresent }
    return $IfAbsent
}

function Format-SuspiciousFileMessage {
    param(
        [string]$FilePath,
        [string]$Reason
    )
    if (-not (Test-Path -LiteralPath $FilePath)) {
        return "Defender history only (not on disk): $FilePath | $Reason"
    }
    $item = Get-Item -LiteralPath $FilePath -Force
    $folderPath = if ($item.PSIsContainer) { $item.FullName } else { $item.DirectoryName }
    $type = if ($item.PSIsContainer) { 'Folder (review contents only)' } else { 'File' }
    $sizeSuffix = if (-not $item.PSIsContainer -and $item.Length) { " ($([math]::Round($item.Length / 1KB, 1)) KB)" } else { '' }
    return "Folder: $folderPath | $type : $($item.FullName)$sizeSuffix | $Reason"
}

function Test-SuspiciousFile {
    param([System.IO.FileSystemInfo]$Item)
    $filePath = $Item.FullName
    foreach ($rule in $script:SuspiciousFileRules) {
        if ($filePath -match $rule.Regex -or $Item.Name -match $rule.Regex) {
            return $rule.Reason
        }
    }
    return $null
}

function Get-SuspiciousFilesInPath {
    param(
        [string]$RootPath,
        [int]$MaxFiles = 50
    )
    if (-not (Test-Path -LiteralPath $RootPath)) { return @() }

    $results = [System.Collections.Generic.List[string]]::new()
    $rootItem = Get-Item -LiteralPath $RootPath -Force

    if (-not $rootItem.PSIsContainer) {
        $reason = Test-SuspiciousFile $rootItem
        if (-not $reason) { $reason = Get-SuspiciousPathReason $rootItem.FullName }
        if (-not $reason) { $reason = 'File at a known suspicious location' }
        [void]$results.Add((Format-SuspiciousFileMessage -FilePath $rootItem.FullName -Reason $reason))
        return $results.ToArray()
    }

    Get-ChildItem -LiteralPath $RootPath -Recurse -Force -File -ErrorAction SilentlyContinue | ForEach-Object {
        $reason = Test-SuspiciousFile $_
        if ($reason) {
            [void]$results.Add((Format-SuspiciousFileMessage -FilePath $_.FullName -Reason $reason))
        }
    }

    return $results | Select-Object -First $MaxFiles
}

function Register-RemnantPath {
    param(
        [string]$TargetPath,
        [string]$Context = ''
    )
    $label = if ($Context) { $Context } else { "Path: $TargetPath" }

    if (-not (Test-Path -LiteralPath $TargetPath)) {
        Add-RemnantResult -Check $label -Status NOT_FOUND -Detail "Full path not found: $TargetPath"
        return
    }

    $item = Get-Item -LiteralPath $TargetPath -Force
    $suspicious = @(Get-SuspiciousFilesInPath -RootPath $item.FullName)

    if ($item.PSIsContainer) {
        $checkLabel = "Folder: $($item.FullName)"
        if ($suspicious.Count -gt 0) {
            $summary = "Folder exists | $($suspicious.Count) suspicious file(s) - remove only these files, not the whole folder"
            Add-RemnantResult -Check $checkLabel -Status PRESENT -Detail $summary -SuspiciousFiles $suspicious
        } else {
            Add-RemnantResult -Check $checkLabel -Status INFO -Detail 'Folder exists; no files match known malware patterns - do not delete the whole folder'
        }
    } else {
        Add-RemnantResult -Check "File: $($item.FullName)" -Status PRESENT -Detail 'File exists on disk' -SuspiciousFiles $suspicious
    }
}

function Test-IsLocalAddress {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return $true }
    return $Address -match '^(127\.|::1|0\.0\.0\.0|localhost)' -or $Address -eq '::'
}

function Get-SuspiciousPathReason {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    if ($Path -match 'AcPowerNotification\.exe') {
        return 'AcPowerNotification.exe (common malware, fake NVIDIA/Adobe folders)'
    }
    if ($Path -match '\\AppData\\Roaming\\NVIDIA\\Storage\\IndexDB\\') {
        return 'Exe in fake NVIDIA IndexDB folder under Roaming'
    }
    if ($Path -match '\\AppData\\Roaming\\Adobe\\Security\\TrustStore\\[0-9a-f]{10,}\\') {
        return 'Exe in fake Adobe TrustStore folder under Roaming'
    }
    if ($Path -match '\\AppData\\Local\\Temp\\.*\.exe$' -and $Path -notmatch 'CodeSetup|vscode-stable|is-[A-Z0-9]+\.tmp|Cursor') {
        return 'Exe in Temp outside known installers'
    }
    if ($Path -match '\\Downloads\\.*(Keygen|crack|patch|activat|MAS_AIO|ChipGenius|YouTube Downloader|Sidify)', 'IgnoreCase') {
        return 'Suspicious file in Downloads'
    }
    return $null
}

function Test-SuspiciousScheduledTask {
    param($TaskName, [string]$TaskAction)
    if ([string]::IsNullOrWhiteSpace($TaskAction)) { return $null }
    $reason = Get-SuspiciousPathReason $TaskAction
    if ($reason) { return $reason }
    if ($TaskName -notmatch '\\Microsoft\\' -and $TaskAction -match '\\AppData\\Roaming\\[^\\]+\\.*\.exe') {
        if ($TaskAction -notmatch '\\AppData\\Roaming\\(Microsoft|Adobe\\Acrobat|NVIDIA Corporation)\\') {
            return 'Task launches exe from Roaming (non-standard path)'
        }
    }
    if ($TaskName -match 'Afforda|Wise Mapping|Score Adopt') {
        return 'Task name matches AcPowerNotification malware'
    }
    return $null
}

$script:RunKeyRelativePath = 'Software\Microsoft\Windows\CurrentVersion\Run'

function Get-RunKeyRegeditPath {
    param([string]$HiveLabel)
    switch ($HiveLabel) {
        'HKLM RunOnce' { return 'HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce' }
        default { return "$HiveLabel\$script:RunKeyRelativePath" }
    }
}

function Test-SuspiciousRunValue {
    param([string]$Name, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return "Empty value (often harmless leftover, e.g. GOG Galaxy client)"
    }
    return Get-SuspiciousPathReason $Value
}

function Get-DisableBlockAtFirstSeenStatus {
    $spynetPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
    if (-not (Test-Path -LiteralPath $spynetPath)) {
        return @{ Active = $false; Detail = 'Spynet registry key does not exist (normal on a clean PC)' }
    }
    $pol = Get-ItemProperty -LiteralPath $spynetPath -ErrorAction SilentlyContinue
    if ($pol.DisableBlockAtFirstSeen -eq 1) {
        return @{ Active = $true; Detail = 'DisableBlockAtFirstSeen = 1 (Defender weakened)' }
    }
    return @{ Active = $false; Detail = 'Key exists; DisableBlockAtFirstSeen is not 1' }
}

function Show-FinalScreenSummary {
    param([string]$ReportFile)

    Write-Host ''
    Write-Host ('=' * 72) -ForegroundColor DarkGray
    Write-Host '  SYSTEM CHECK SUMMARY' -ForegroundColor White
    Write-Host ('=' * 72) -ForegroundColor DarkGray

    Write-Host "Report file: $ReportFile" -ForegroundColor Cyan

    if (-not $isAdmin) {
        Write-Host 'Note: not run as Administrator (some paths may be missing).' -ForegroundColor Yellow
    }

    foreach ($note in $script:ScreenNotes) {
        Write-Host "  $note" -ForegroundColor Gray
    }

    Write-Host ''
    Write-Host '--- Remnant checks (section 21) ---' -ForegroundColor White
    if ($RemnantResults.Count -eq 0) {
        Write-Host '  No remnant checks were run.' -ForegroundColor Gray
    } else {
        foreach ($r in $RemnantResults) {
            $color = switch ($r.Status) {
                'PRESENT'       { 'Red' }
                'NOT_FOUND'  { 'Green' }
                default          { 'DarkYellow' }
            }
            Write-Host "  $($r.Flag) $($r.Check): $($r.Detail)" -ForegroundColor $color
        }
        $presentCount = @($RemnantResults | Where-Object { $_.Status -eq 'PRESENT' }).Count
        if ($presentCount -gt 0) {
            Write-Host "  >> $presentCount remnant(s) still PRESENT on disk/processes/tasks" -ForegroundColor Red
        } else {
            Write-Host '  >> No known remnants on disk (Defender history may still list items)' -ForegroundColor Green
        }
    }

    Write-Host ''
    Write-Host '--- [SUSPICIOUS] findings (section 22) ---' -ForegroundColor White
    if ($SuspiciousFindings.Count -eq 0) {
        Write-Host '  No suspicious markings.' -ForegroundColor Green
    } else {
        Write-SuspiciousFindingsReport -ToConsole
        $highCount = @($SuspiciousFindings | Where-Object { $_.Severity -eq 'HIGH' }).Count
        $mediumCount = @($SuspiciousFindings | Where-Object { $_.Severity -eq 'MEDIUM' }).Count
        Write-Host "  Total: $($SuspiciousFindings.Count) (HIGH: $highCount, MEDIUM: $mediumCount)" -ForegroundColor $(if ($highCount -gt 0) { 'Red' } else { 'Yellow' })
    }

    Write-Host ''
    Write-Host ('=' * 72) -ForegroundColor DarkGray
    if (@($SuspiciousFindings | Where-Object { $_.Severity -eq 'HIGH' }).Count -gt 0 -or
        @($RemnantResults | Where-Object { $_.Status -eq 'PRESENT' }).Count -gt 0) {
        Write-Host '  Advice: remove [SUSPICIOUS] remnants, then run a full Defender scan.' -ForegroundColor Red
    } else {
        Write-Host '  No acute remnants; periodic rescans are still recommended.' -ForegroundColor Green
    }
    Write-Host ('=' * 72) -ForegroundColor DarkGray
    Write-Host ''
}

# --- Start ---
Clear-Host
Write-Host 'WINDOWS SYSTEM CHECK' -ForegroundColor White
Write-Host "Computer: $env:COMPUTERNAME | User: $env:USERNAME | Admin: $isAdmin"
Write-Host "Writing report to: $reportPath"
Write-ProgressStep 0 'Initializing report...'

@(
    'WINDOWS SYSTEM CHECK - ANALYSIS REPORT'
    "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    "Computer:    $env:COMPUTERNAME"
    "User:        $env:USERDOMAIN\$env:USERNAME"
    "Admin:       $isAdmin"
    "Script:      $PSCommandPath"
    "Report:      $reportPath"
    ''
    'SECTIONS: 1-20 analysis | 21 malware remnants | 22 summary [SUSPICIOUS] | end'
) | Set-Content -Path $reportPath -Encoding UTF8

# --- 1 ---
Write-ProgressStep 1 'Collecting system information...'
Write-Section '1. SYSTEM INFORMATION'
try {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $uptime = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1)
    Write-Block ([PSCustomObject]@{
        OS = "$($os.Caption) $($os.Version) build $($os.BuildNumber)"
        Architecture = $os.OSArchitecture
        LastBoot = $os.LastBootUpTime
        UptimeHours = $uptime
        Manufacturer = $cs.Manufacturer
        Model = $cs.Model
        BIOS = $bios.SMBIOSBIOSVersion
        MemoryGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
        Domain = $cs.Domain
    })
    Add-ScreenNote "System: $($cs.Manufacturer) $($cs.Model) | Uptime: ${uptime}h"
} catch { Write-Block $_.Exception.Message 'Error' }

# --- 2 ---
Write-ProgressStep 2 'Windows Defender status and threats...'
Write-Section '2. WINDOWS DEFENDER'
try {
    $mpStatus = Get-MpComputerStatus
    Write-Block ([PSCustomObject]@{
        RealTimeProtectionEnabled = $mpStatus.RealTimeProtectionEnabled
        AntivirusEnabled = $mpStatus.AntivirusEnabled
        QuickScanAgeDays = $mpStatus.QuickScanAge
        FullScanAgeDays = $mpStatus.FullScanAge
        SignatureAgeDays = $mpStatus.AntivirusSignatureAge
        ProductVersion = $mpStatus.AMProductVersion
    }) 'Status'

    $rt = if ($mpStatus.RealTimeProtectionEnabled) { 'ON' } else { 'OFF' }
    Add-ScreenNote "Defender real-time: $rt | Signatures: $($mpStatus.AntivirusSignatureAge)d old"

    $threats = @(Get-MpThreatDetection)
    if ($threats.Count -gt 0) {
        Write-Block ($threats | Select-Object ThreatName, InitialDetectionTime, ActionSuccess, Resources, ProcessName) 'Detected threats (history)'
    } else {
        Add-Content -Path $reportPath -Value 'No threats via Get-MpThreatDetection.'
    }

    $threatCat = @(Get-MpThreat)
    if ($threatCat.Count -gt 0) {
        Write-Block ($threatCat | Select-Object ThreatName, SeverityID, IsActive) 'Threat catalog'
        foreach ($t in $threatCat | Where-Object { $_.IsActive }) {
            Add-SuspiciousFinding -Severity HIGH -Category 'Defender' -Detail "Active threat: $($t.ThreatName)" -Advice 'Full scan + quarantine'
        }
    }

    if ($mpStatus.FullScanAge -ge 30 -or $mpStatus.FullScanAge -gt 1000000) {
        Add-SuspiciousFinding -Severity MEDIUM -Category 'Defender' -Detail 'No recent full scan' -Advice 'Windows Security -> Full scan'
    }

    $processedHistoryPaths = @{}
    foreach ($td in $threats) {
        $files = Get-DefenderResourceFiles -Resources $td.Resources
        foreach ($bf in $files) {
            if ($processedHistoryPaths[$bf]) { continue }
            $processedHistoryPaths[$bf] = $true
            $reason = Get-SuspiciousPathReason $bf
            if (-not $reason) { $reason = Test-SuspiciousFile (Get-Item -LiteralPath $bf -Force -EA 0) }
            if (-not $reason) { $reason = 'Flagged in Defender history' }
            $subject = Format-SuspiciousFileMessage -FilePath $bf -Reason $reason
            $sev = Get-SeverityForSuspiciousPath -FilePath $bf -IfPresent HIGH -IfAbsent INFO
            Add-SuspiciousFinding -Severity $sev -Category 'Defender history' -Subject $subject `
                -Action (Get-SuspiciousFileAction -FilePath $bf -WithScan:($sev -eq 'HIGH'))
        }
        $res = ($td.Resources -join ' ')
        if ($res -match 'DisableBlockAtFirstSeen') {
            $spynet = Get-DisableBlockAtFirstSeenStatus
            $regPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
            if ($spynet.Active) {
                Add-SuspiciousFinding -Severity HIGH -Category 'Defender-registry' `
                    -Subject "Active tampering: $regPath | $($spynet.Detail)" `
                    -Action "In Regedit: remove DisableBlockAtFirstSeen under $regPath (or set to 0)"
            } else {
                Add-SuspiciousFinding -Severity INFO -Category 'Defender history' `
                    -Subject "Mentioned in Defender history only: DisableBlockAtFirstSeen | Current: $($spynet.Detail)" `
                    -Action 'No registry action needed; optional full Defender scan for confirmation'
            }
        }
    }
} catch { Write-Block $_.Exception.Message 'Error' }

# --- 3 ---
Write-ProgressStep 3 'Firewall profiles...'
Write-Section '3. WINDOWS FIREWALL'
try {
    $fw = Get-NetFirewallProfile | Select-Object Name, Enabled
    Write-Block $fw
    $fwOff = @($fw | Where-Object { -not $_.Enabled }).Count
    if ($fwOff -gt 0) { Add-SuspiciousFinding -Severity HIGH -Category 'Firewall' -Detail "$fwOff profile(s) disabled" -Advice 'Re-enable the firewall' }
} catch { Write-Block $_.Exception.Message 'Error' }

# --- 4 ---
Write-ProgressStep 4 'Active network connections and processes...'
Write-Section '4. ACTIVE NETWORK CONNECTIONS (with process)'
try {
    $procById = @{}; Get-Process | ForEach-Object { $procById[$_.Id] = $_ }
    $connections = Get-NetTCPConnection -State Established -ErrorAction Stop |
        Where-Object { -not (Test-IsLocalAddress $_.RemoteAddress) } |
        ForEach-Object {
            $proc = $procById[$_.OwningProcess]
            $path = $proc.Path
            if (-not $path -and $isAdmin) {
                $path = (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.OwningProcess)").ExecutablePath
            }
            $flag = ''; $reason = Get-SuspiciousPathReason $path
            if ($reason) {
                $flag = '[SUSPICIOUS] '
                Add-SuspiciousFinding -Severity HIGH -Category 'Network' -Detail "$reason | $($proc.ProcessName)" -Advice 'Stop the process; remove the path'
            }
            [PSCustomObject]@{ Flag = $flag; Remote = "$($_.RemoteAddress):$($_.RemotePort)"; PID = $_.OwningProcess; Process = $proc.ProcessName; Path = $path }
        } | Sort-Object Process, Remote -Unique
    Write-Block $connections
    Add-ScreenNote "Active external connections: $($connections.Count)"
} catch { Write-Block $_.Exception.Message 'Error' }

# --- 5 ---
Write-ProgressStep 5 'Listening ports...'
Write-Section '5. LISTENING PORTS (LISTEN)'
try {
    $listen = Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        $path = $proc.Path; $flag = ''; $reason = Get-SuspiciousPathReason $path
        if ($reason) {
            $flag = '[SUSPICIOUS] '
            Add-SuspiciousFinding -Severity HIGH -Category 'Listening port' -Detail "$reason | port $($_.LocalPort)" -Advice 'Remove the service/task'
        } elseif ($path -match 'VPNNederland' -and $_.LocalAddress -eq '0.0.0.0') { $flag = '[INFO] ' }
        [PSCustomObject]@{ Flag = $flag; LocalPort = $_.LocalPort; LocalAddress = $_.LocalAddress; Process = $proc.ProcessName; Path = $path }
    }
    Write-Block ($listen | Select-Object -Unique LocalPort, LocalAddress, Process, Path, Flag)
} catch { Write-Block $_.Exception.Message 'Error' }

# --- 6 ---
Write-ProgressStep 6 'DNS, proxy, and hosts file...'
Write-Section '6. DNS, PROXY, AND HOSTS'
try {
    Write-Block (Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | Select-Object InterfaceAlias, ServerAddresses) 'DNS'
    $proxy = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    Write-Block ([PSCustomObject]@{ ProxyEnable = $proxy.ProxyEnable; ProxyServer = $proxy.ProxyServer }) 'Proxy'
    if ($proxy.ProxyEnable -eq 1) {
        Add-SuspiciousFinding -Severity MEDIUM -Category 'Proxy' -Detail "Proxy ON: $($proxy.ProxyServer)" -Advice 'Verify if expected'
    }
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    Add-Content -Path $reportPath -Value "`nHosts: $hostsPath"
    if (Test-Path $hostsPath) {
        Get-Content $hostsPath | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() -ne '' } | ForEach-Object {
            $line = $_
            if ($line -notmatch 'privacy\.sexy' -and $line -match '0\.0\.0\.0|::1') {
                Add-SuspiciousFinding -Severity MEDIUM -Category 'Hosts' -Detail "Unknown redirect: $line" -Advice 'Review hosts file'
                $line = "[SUSPICIOUS] $line"
            }
            Add-Content -Path $reportPath -Value "  $line"
        }
    }
} catch { Write-Block $_.Exception.Message 'Error' }

# --- 7 ---
Write-ProgressStep 7 'Svchost services with internet...'
Write-Section '7. SVCHOST - SERVICES WITH INTERNET CONNECTION'
try {
    $extPids = Get-NetTCPConnection -State Established | Where-Object { -not (Test-IsLocalAddress $_.RemoteAddress) } | Select-Object -ExpandProperty OwningProcess -Unique
    $svchostServices = foreach ($procId in $extPids) {
        if ((Get-Process -Id $procId -EA 0).ProcessName -ne 'svchost') { continue }
        Get-CimInstance Win32_Service | Where-Object { $_.ProcessId -eq $procId } | Select-Object @{N='PID';E={$procId}}, Name, DisplayName, PathName
    }
    if ($svchostServices) { Write-Block ($svchostServices | Sort-Object PID, Name -Unique) }
    else { Add-Content -Path $reportPath -Value 'No svchost with external connection.' }
} catch { Write-Block $_.Exception.Message 'Error' }

# --- 8 ---
Write-ProgressStep 8 'Startup items and Registry Run...'
Write-Section '8. STARTUP ITEMS'
try {
    $startup = Get-CimInstance Win32_StartupCommand | ForEach-Object {
        $reason = Get-SuspiciousPathReason $_.Command
        $flag = if ($reason) { Add-SuspiciousFinding -Severity HIGH -Category 'Startup' -Detail "$($_.Name): $reason" -Advice 'Remove'; '[SUSPICIOUS] ' } else { '' }
        [PSCustomObject]@{ Flag = $flag; Name = $_.Name; Command = $_.Command; Location = $_.Location }
    }
    Write-Block ($startup | Sort-Object Location, Name)
    Add-Content -Path $reportPath -Value "`n--- Registry Run-keys ---"
    foreach ($hive in @(
        @{ Hive = 'HKCU'; Path = 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run' }
        @{ Hive = 'HKLM'; Path = 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run' }
        @{ Hive = 'HKLM RunOnce'; Path = 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce' }
    )) {
        Add-Content -Path $reportPath -Value "`n[$($hive.Hive)]"
        if (Test-Path $hive.Path) {
            $props = Get-ItemProperty $hive.Path
            $regPath = Get-RunKeyRegeditPath -HiveLabel $hive.Hive
            $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                $val = $_.Value.ToString()
                $reason = Test-SuspiciousRunValue -Name $_.Name -Value $val
                $prefix = if ($reason) {
                    $isEmptyValue = [string]::IsNullOrWhiteSpace($val)
                    $sev = if ($isEmptyValue) { 'INFO' } else { 'HIGH' }
                    $actionText = if ($isEmptyValue) {
                        "Optional in Regedit: $regPath -> remove value '$($_.Name)' if you do not use that software"
                    } else {
                        "In Regedit: $regPath -> remove value '$($_.Name)' or review the path"
                    }
                    Add-SuspiciousFinding -Severity $sev -Category 'Startup Registry' `
                        -Subject "$regPath | value '$($_.Name)' = '$val' | $reason" -Action $actionText
                    if ($sev -eq 'HIGH') { '[SUSPICIOUS] ' } else { '[INFO] ' }
                } else { '' }
                Add-Content -Path $reportPath -Value "  $prefix$($_.Name) = $val"
            }
        }
    }
} catch { Write-Block $_.Exception.Message 'Error' }

# --- 9 ---
Write-ProgressStep 9 'Scanning scheduled tasks...'
Write-Section '9. SCHEDULED TASKS (notable paths)'
try {
    Get-ScheduledTask -EA Stop | ForEach-Object {
        $taskAction = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
        $reason = Test-SuspiciousScheduledTask -TaskName ($_.TaskPath + $_.TaskName) -TaskAction $taskAction
        if ($reason) {
            Add-SuspiciousFinding -Severity HIGH -Category 'Scheduled task' -Detail "$($_.TaskPath)$($_.TaskName) | $reason" -Advice 'Remove the task in taskschd.msc'
        }
    }
    $tasksMarked = Get-ScheduledTask -EA Stop | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
        $info = $_ | Get-ScheduledTaskInfo -EA 0
        $taskAction = ($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join ' | '
        [PSCustomObject]@{
            TaskPath = $_.TaskPath
            TaskName = $_.TaskName
            LastRun  = $info.LastRunTime
            Action   = $taskAction.Trim()
        }
    } | Where-Object {
        $_.Action -and $_.Action -notmatch '\\Windows\\|\\Microsoft\\|Program Files\\Windows|\\WMI\\|MicrosoftEdgeUpdate'
    } | ForEach-Object {
        $reason = Test-SuspiciousScheduledTask -TaskName ($_.TaskPath + $_.TaskName) -TaskAction $_.Action
        $flag = if ($reason) { '[SUSPICIOUS] ' } else { '' }
        [PSCustomObject]@{ Flag = $flag; TaskName = $_.TaskPath + $_.TaskName; LastRun = $_.LastRun; Action = $_.Action }
    }
    if ($tasksMarked) { Write-Block ($tasksMarked | Sort-Object TaskName) }
    else { Add-Content -Path $reportPath -Value 'No notable non-Microsoft tasks.' }
} catch { Write-Block $_.Exception.Message 'Error' }

# --- 10 ---
Write-ProgressStep 10 'Services outside System32...'
Write-Section '10. SERVICES (Automatic, path outside System32)'
try {
    $servicesMarked = Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -eq 'Running' } | ForEach-Object {
        $exe = $_.PathName -replace '^"|"$',''
        if ($exe -match '^(.+\.exe)') { $exe = $Matches[1] }
        if ($exe -notmatch '\\Windows\\System32\\|\\Windows\\SysWOW64\\|\\Windows\\SystemApps\\') {
            $reason = Get-SuspiciousPathReason $exe
            $flag = if ($reason) { Add-SuspiciousFinding -Severity HIGH -Category 'Service' -Detail "$($_.Name): $reason" -Advice 'Remove'; '[SUSPICIOUS] ' } else { '' }
            [PSCustomObject]@{ Flag = $flag; Name = $_.Name; DisplayName = $_.DisplayName; PathName = $_.PathName }
        }
    }
    Write-Block ($servicesMarked | Sort-Object Name)
} catch { Write-Block $_.Exception.Message 'Error' }

# --- 11 ---
Write-ProgressStep 11 'Processes in Temp and Downloads...'
Write-Section '11. PROCESSES IN TEMP / DOWNLOADS'
try {
    $suspicious = Get-Process | Where-Object { $_.Path -match '\\Temp\\|\\Downloads\\' } | ForEach-Object {
        $flag = '[SUSPICIOUS] '; $sev = 'MEDIUM'
        if ($_.Path -match 'CodeSetup|Cursor|vscode') { $flag = '[INFO] '; $sev = 'INFO' }
        else { Add-SuspiciousFinding -Severity $sev -Category 'Process' -Detail "$($_.ProcessName): $($_.Path)" -Advice 'End if unknown' }
        [PSCustomObject]@{ Flag = $flag; Id = $_.Id; ProcessName = $_.ProcessName; Path = $_.Path }
    }
    if ($suspicious) { Write-Block $suspicious } else { Add-Content -Path $reportPath -Value 'No processes in Temp/Downloads.' }
} catch { Write-Block $_.Exception.Message 'Error' }

# --- 12 ---
Write-ProgressStep 12 'Network adapters and VPN...'
Write-Section '12. NETWORK ADAPTERS AND VPN'
try {
    Write-Block (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object Name, InterfaceDescription, LinkSpeed) 'Active'
    Write-Block (Get-NetAdapter | Where-Object { $_.InterfaceDescription -match 'VPN|TAP|Tun|SSL' } | Select-Object Name, Status, InterfaceDescription) 'VPN'
} catch { Write-Block $_.Exception.Message 'Error' }

# --- 13 ---
Write-ProgressStep 13 'Local users and administrators...'
Write-Section '13. LOCAL USERS AND ADMINISTRATORS'
try {
    Write-Block (Get-LocalUser | Select-Object Name, Enabled, LastLogon) 'Accounts'
    Write-Block (Get-LocalGroupMember -Group 'Administrators' -EA 0 | Select-Object Name, PrincipalSource) 'Administrators'
} catch { Write-Block $_.Exception.Message 'Error' }

# --- 14 ---
Write-ProgressStep 14 'Recently installed programs...'
Write-Section '14. RECENTLY INSTALLED PROGRAMS (30 days)'
try {
    $cutoff = (Get-Date).AddDays(-30)
    $recent = foreach ($key in @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )) {
        Get-ItemProperty $key -EA 0 | Where-Object { $_.DisplayName -and $_.InstallDate } | ForEach-Object {
            $raw = $_.InstallDate.ToString()
            if ($raw.Length -ge 8) {
                try {
                    $dt = [datetime]::ParseExact($raw.Substring(0, 8), 'yyyyMMdd', $null)
                    if ($dt -ge $cutoff) {
                        [PSCustomObject]@{ Name = $_.DisplayName; InstallDate = $dt.ToString('yyyy-MM-dd'); Publisher = $_.Publisher }
                    }
                } catch {}
            }
        }
    }
    if ($recent) { Write-Block ($recent | Sort-Object InstallDate -Descending | Select-Object -Unique Name, InstallDate, Publisher) }
    else { Add-Content -Path $reportPath -Value 'No recent installs (30d) with a date.' }
} catch { Write-Block $_.Exception.Message 'Error' }

# --- 15 ---
Write-ProgressStep 15 'Defender event log...'
Write-Section '15. EVENT LOG - Defender (last 30)'
try {
    Write-Block (Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -MaxEvents 30 |
        Select-Object TimeCreated, Id, LevelDisplayName, @{N='Message';E={($_.Message -split "`n")[0].Substring(0,[Math]::Min(200,($_.Message -split "`n")[0].Length))}})
} catch { Write-Block $_.Exception.Message 'Error' }

# --- 16 ---
Write-ProgressStep 16 'System errors last 24 hours...'
Write-Section '16. EVENT LOG - System errors (24h)'
try {
    $sysErrors = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 2; StartTime = (Get-Date).AddHours(-24) } -MaxEvents 20 -EA Stop
    if ($sysErrors) { Write-Block ($sysErrors | Select-Object TimeCreated, Id, ProviderName) }
    else { Add-Content -Path $reportPath -Value 'No Error events (24h).' }
} catch { Write-Block $_.Exception.Message 'Error' }

# --- 17 ---
Write-ProgressStep 17 'Bootlog ntbtlog.txt...'
Write-Section '17. BOOT LOG (ntbtlog.txt) - SUMMARY'
$bootLog = 'C:\Windows\ntbtlog.txt'
if (Test-Path $bootLog) {
    $lines = Get-Content $bootLog
    Add-Content -Path $reportPath -Value "Last modified: $((Get-Item $bootLog).LastWriteTime)"
    Add-Content -Path $reportPath -Value "LOADED: $(($lines|Select-String 'BOOTLOG_LOADED').Count) | NOT_LOADED: $(($lines|Select-String 'BOOTLOG_NOT_LOADED').Count)"
    $lines | Select-String 'BOOTLOG_NOT_LOADED \\' | ForEach-Object { $_.Line -replace '.*BOOTLOG_NOT_LOADED\s+','' } | Sort-Object -Unique | ForEach-Object { Add-Content -Path $reportPath -Value "  $_" }
    if ($IncludeBootLogCopy) { Copy-Item $bootLog (Join-Path $OutputFolder "ntbtlog_copy_$timestamp.txt") -Force }
} else {
    Add-Content -Path $reportPath -Value 'ntbtlog.txt not found. Run bcdedit /bootlog Yes + reboot'
}

# --- 18 ---
Write-ProgressStep 18 'Filter drivers (fltmc)...'
Write-Section '18. FILTER DRIVERS (fltmc)'
if ($isAdmin) { Write-Block (fltmc 2>&1 | Out-String) } else { Add-Content -Path $reportPath -Value 'Requires Administrator.' }

# --- 19 ---
Write-ProgressStep 19 'Windows Update status...'
Write-Section '19. WINDOWS UPDATE'
try {
    $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
    $searcher.Online = $false
    $pending = $searcher.Search('IsInstalled=0').Updates | Select-Object Title, @{N='SizeMB';E={[math]::Round($_.MaxDownloadSize/1MB,1)}}
    if ($pending) { Write-Block $pending } else { Add-Content -Path $reportPath -Value 'No pending updates in cache.' }
} catch { Add-Content -Path $reportPath -Value "Update COM: $($_.Exception.Message)" }

# --- 20 ---
Write-ProgressStep 20 'UAC, SmartScreen, Defender exclusions...'
Write-Section '20. SECURITY SETTINGS'
try {
    $uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -EA 0
    Write-Block ([PSCustomObject]@{ UAC_EnableLUA = $uac.EnableLUA; UAC_ConsentPrompt = $uac.ConsentPromptBehaviorAdmin })
    $defenderExcl = (Get-MpPreference).ExclusionPath
    if ($defenderExcl) {
        Write-Block ($defenderExcl | ForEach-Object {
            $flag = if ($_ -match 'MAS_AIO|KMS|Activat') {
                Add-SuspiciousFinding -Severity MEDIUM -Category 'Defender exclusion' -Detail "Activator exclusion: $_" -Advice 'Remove the exclusion'
                '[SUSPICIOUS] '
            } else { '' }
            [PSCustomObject]@{ Flag = $flag; Path = $_ }
        }) 'Exclusions'
    }
} catch { Write-Block $_.Exception.Message 'Error' }

# --- 21 MALWARE REMNANTS ---
Write-ProgressStep 21 'Malware remnants and extra checks...'
Write-Section '21. MALWARE REMNANTS AND EXTRA CHECKS'

# Optional extra paths (only when supplied via parameter or file)
Add-Content -Path $reportPath -Value "`n--- Extra path checks (optional) ---"
if ($ExtraRemnantPaths.Count -gt 0) {
    Add-Content -Path $reportPath -Value "Number of paths supplied: $($ExtraRemnantPaths.Count)"
    foreach ($p in $ExtraRemnantPaths) {
        Register-RemnantPath -TargetPath $p
    }
    Add-ScreenNote "Extra remnant paths checked: $($ExtraRemnantPaths.Count)"
} else {
    Add-Content -Path $reportPath -Value @(
        'No extra paths supplied.'
        'Use -RemnantPaths "C:\path\to\folder" or -RemnantPathsFile path-to-list.txt'
        'Generic scans (AcPowerNotification, tasks, downloads, etc.) below always run.'
    )
}
Add-Content -Path $reportPath -Value "`n--- Generic remnant scans (all systems) ---"

# Search for AcPowerNotification.exe under user profile
$acFiles = @(
    Get-ChildItem -Path $env:APPDATA -Filter 'AcPowerNotification.exe' -Recurse -ErrorAction SilentlyContinue
    Get-ChildItem -Path $env:LOCALAPPDATA -Filter 'AcPowerNotification.exe' -Recurse -ErrorAction SilentlyContinue
)
if ($acFiles.Count -gt 0) {
    $files = $acFiles | ForEach-Object {
        Format-SuspiciousFileMessage -FilePath $_.FullName -Reason 'Known malware (AcPowerNotification)'
    }
    Add-RemnantResult -Check 'AcPowerNotification.exe (search under AppData)' -Status PRESENT `
        -Detail "Found: $($acFiles.Count) file(s)" -SuspiciousFiles $files
} else {
    Add-RemnantResult -Check 'AcPowerNotification.exe (search)' -Status NOT_FOUND -Detail 'No files under AppData'
    Add-Content -Path $reportPath -Value '[OK] No AcPowerNotification.exe under AppData'
}

# Scheduled tasks related to AcPower
$badTasks = Get-ScheduledTask -EA 0 | Where-Object {
    ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ' -match 'AcPowerNotification|Afforda|Wise Mapping'
}
if ($badTasks) {
    $tasks = $badTasks | ForEach-Object {
        $taskAction = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
        "Task: $($_.TaskPath)$($_.TaskName) | Action: $taskAction"
    }
    Add-RemnantResult -Check 'Suspicious scheduled tasks' -Status PRESENT `
        -Detail "$($badTasks.Count) task(s)" -SuspiciousFiles $tasks
} else {
    Add-RemnantResult -Check 'Suspicious scheduled tasks' -Status NOT_FOUND -Detail 'No AcPower/Afforda/Wise Mapping tasks'
}

# Running process
$acProc = Get-Process -EA 0 | Where-Object { $_.Path -match 'AcPowerNotification' }
if ($acProc) {
    $processLines = $acProc | ForEach-Object { "Process: $($_.ProcessName) | PID: $($_.Id) | File: $($_.Path)" }
    Add-RemnantResult -Check 'Process AcPowerNotification' -Status PRESENT -Detail 'Running now' -SuspiciousFiles $processLines
} else {
    Add-RemnantResult -Check 'Process AcPowerNotification' -Status NOT_FOUND -Detail 'Not running'
}

# Registry Defender tampering (live check, separate from history)
$spynetStatus = Get-DisableBlockAtFirstSeenStatus
if ($spynetStatus.Active) {
    Add-RemnantResult -Check 'Registry DisableBlockAtFirstSeen (live)' -Status PRESENT -Detail $spynetStatus.Detail
} else {
    Add-RemnantResult -Check 'Registry DisableBlockAtFirstSeen (live)' -Status NOT_FOUND -Detail $spynetStatus.Detail
}

# User Startup folder
$startupFolder = [Environment]::GetFolderPath('Startup')
$userStartup = Get-ChildItem $startupFolder -EA 0
if ($userStartup) {
    foreach ($item in $userStartup) {
        $reason = Get-SuspiciousPathReason $item.FullName
        if ($reason) {
            Add-RemnantResult -Check "Startup folder: $($item.Name)" -Status PRESENT -Detail $reason
        }
    }
    Add-Content -Path $reportPath -Value "Startup folder: $startupFolder ($(@($userStartup).Count) items)"
} else {
    Add-Content -Path $reportPath -Value "[OK] Startup folder empty: $startupFolder"
}

# PowerShell profiles
$psProfiles = @(
    $PROFILE
    "$PSHOME\Profile.ps1"
    "$env:APPDATA\Microsoft\Windows\PowerShell\Profile.ps1"
) | Where-Object { $_ -and (Test-Path $_) }
if ($psProfiles) {
    foreach ($pp in $psProfiles) {
        $c = Get-Content $pp -Raw -EA 0
        if ($c -match 'Invoke-Expression|DownloadString|FromBase64String|AcPowerNotification') {
            Add-RemnantResult -Check "PowerShell profile: $pp" -Status PRESENT -Detail 'Suspicious content in profile'
            Add-Content -Path $reportPath -Value "[SUSPICIOUS] Profile: $pp"
        } else {
            Add-Content -Path $reportPath -Value "[OK] Profile without suspicious patterns: $pp"
        }
    }
} else {
    Add-Content -Path $reportPath -Value '[OK] No PowerShell profiles found'
}

# BITS-jobs
$bits = Get-BitsTransfer -AllUsers -EA 0 | Where-Object { $_.JobState -in 'Transferring','Connecting','Queued' }
if ($bits) {
    Write-Block ($bits | Select-Object DisplayName, JobState, FileList) 'Active BITS transfers'
    Add-SuspiciousFinding -Severity MEDIUM -Category 'BITS' -Detail 'Active background downloads' -Advice 'Review unknown BITS jobs'
} else {
    Add-Content -Path $reportPath -Value '[OK] No active BITS transfers'
}

# Winlogon hijack
$winlogon = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -EA 0
$wlCheck = @($winlogon.Shell, $winlogon.Userinit) -join ' '
if ($wlCheck -notmatch 'explorer\.exe|userinit\.exe') {
    Add-RemnantResult -Check 'Winlogon Shell/Userinit' -Status PRESENT -Detail $wlCheck
} else {
    Add-RemnantResult -Check 'Winlogon Shell/Userinit' -Status NOT_FOUND -Detail 'Default values'
}

# Suspicious files in Downloads
$dlPatterns = @('*ChipGenius*', '*YouTube*Downloader*', '*Sidify*', '*MAS*', '*keygen*', '*crack*')
$dlHits = foreach ($pat in $dlPatterns) {
    Get-ChildItem -Path $env:USERPROFILE\Downloads -Filter $pat -Recurse -EA 0 -ErrorAction SilentlyContinue
}
if ($dlHits) {
    $dlList = $dlHits | Select-Object -First 15 | ForEach-Object {
        Format-SuspiciousFileMessage -FilePath $_.FullName -Reason 'Suspicious name in Downloads'
    }
    Add-RemnantResult -Check 'Downloads (suspicious names)' -Status PRESENT `
        -Detail "$($dlHits.Count) match(es)" -SuspiciousFiles $dlList
} else {
    Add-RemnantResult -Check 'Downloads (suspicious names)' -Status NOT_FOUND -Detail 'No matches on known patterns'
}

# Quarantine history
try {
    $q = Get-MpThreatDetection | Where-Object { $_.ActionSuccess -eq $true } | Select-Object -Last 5 ThreatName, InitialDetectionTime, Resources
    if ($q) { Write-Block $q 'Recent Defender actions (last 5)' }
} catch {}

# SMB shares
try {
    $shares = Get-SmbShare -EA 0 | Where-Object { $_.Name -notin 'IPC$','ADMIN$','C$' }
    if ($shares) { Write-Block ($shares | Select-Object Name, Path, Description) 'Shared folders' }
} catch {}

Write-Block ($RemnantResults | Select-Object Flag, Check, Status, Detail) 'Remnant check overview'

# --- 22 Summary ---
Write-ProgressStep 22 'Writing [SUSPICIOUS] summary to report...'
Write-Section '22. SUMMARY - SUSPICIOUS ITEMS ([SUSPICIOUS])'
if ($SuspiciousFindings.Count -eq 0) {
    Add-Content -Path $reportPath -Value 'No suspicious items marked.'
} else {
    Add-Content -Path $reportPath -Value "Total: $($SuspiciousFindings.Count) finding(s)"
    Write-SuspiciousFindingsReport
}

Write-ProgressStep 23 'Finishing...'
Write-Section 'END OF REPORT'
Add-Content -Path $reportPath -Value @(
    '  * [SUSPICIOUS] and section 22: review promptly.'
    '  * Remnant PRESENT in section 21: remove only listed files, not whole folders blindly.'
    '  * [INFO] = often legitimate (VPN, installers).'
)

Show-FinalScreenSummary -ReportFile $reportPath

if (-not $NoPrompt -and $Host.Name -eq 'ConsoleHost') {
    $open = Read-Host 'Open report in Notepad? (y/n)'
    if ($open -match '^[yYjJ]') { notepad $reportPath }
}
