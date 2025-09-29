<#
.SYNOPSIS
	Powershell ThreatHunter v2.0 for Secure Environments
	An advanced forensic script for hunting malware persistence and IOCs on Windows systems.
.DESCRIPTION
    PThreatHunter v2.0 is an advanced forensic script designed for security analysts, system administrators, and blue teamers to hunt for malware persistence techniques and indicators of compromise (IOCs) on Windows systems.
Its key feature is its full compatibility with PowerShell's Constrained Language Mode (CLM), making it one of the few advanced threat hunting tools capable of running in highly secured and locked-down corporate environments.
.NOTES
    Author: 0xAllow
    Version: 2.0 - In modern, security-conscious environments, PowerShell is often restricted by security policies like AppLocker or Windows Defender Application Control (WDAC). When these policies are active, PowerShell runs in Constrained Language Mode.
    Compatibility: PowerShell 5.1+, requires Administrator privileges.
	Designed for Hostile Environments: What is Constrained Language Mode
	In modern, security-conscious environments, PowerShell is often restricted by security policies like AppLocker or Windows Defender Application Control (WDAC). When these policies are active, PowerShell runs in Constrained Language Mode.
#>

[CmdletBinding()]
param(
    [string]$OutputFolder = "$env:USERPROFILE\PThreatHunter-Report",
    [switch]$Force,
    [switch]$NoColor
)

Set-StrictMode -Off

#region Global Vars and Helper Functions

$SuspiciousPathsRegex = 'AppData|Temp|Public|Users\\[^\\]+\\Downloads'
$SuspiciousKeywordsRegex = 'powershell\.exe -enc|powershell\.exe -e|mshta\.exe|rundll32\.exe|certutil|bitsadmin|iex|Invoke-Expression|DownloadString|whoami|net user'
$ProcessCache = @{}

function Ensure-RunningAsAdmin {
    $isAdmin = $false
    try {
        $groups = whoami.exe /groups 2>$null
        if ($groups -match 'S-1-5-32-544') { $isAdmin = $true }
    } catch { Write-Warning "Could not reliably determine admin status." }
    if (-not $isAdmin) { Write-Warning "Script is not running as Administrator. Some checks may fail." }
}

function Ensure-OutputFolder {
    param($Path)
    try {
        if (-not (Test-Path -Path $Path)) { New-Item -Path $Path -ItemType Directory -Force | Out-Null }
        return (Resolve-Path -Path $Path).Path
    }
    catch { throw ("Failed to create output folder " + $Path + " -- " + $_) }
}

function Write-Log {
    param([Parameter(Mandatory=$true)][string]$Message, [ValidateSet('INFO','WARN','ERROR','DEBUG')][string]$Level = 'INFO')
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; $line = "[$ts] [$Level] $Message"; Write-Output $line
}

function Write-Color {
    param([string]$Text, [ConsoleColor]$Color = 'White')
    if ($NoColor) { Write-Host $Text; return }
    try { Write-Host $Text -ForegroundColor $Color } catch { Write-Host $Text }
}

function Get-FileHashSafe {
    param([string]$FilePath)
    if (-not $FilePath) { return $null }

    # FIX: Use regex to intelligently find file paths (exe, dll, sys) in a command line.
    $pathRegex = '([a-zA-Z]:\\[^:"*?<>|]+\.(?:exe|dll|sys|vbs|ps1))'
    $match = [regex]::Match($FilePath, $pathRegex)
    
    if (-not $match.Success) { return $null }
    $extractedPath = $match.Groups[1].Value

    if (-not (Test-Path $extractedPath -PathType Leaf)) { return "[File Not Found]" }
    
    try {
        return (Get-FileHash -Path $extractedPath -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch {
        return "[Access Denied]"
    }
}

function Get-ProcessInfoByPid {
    param([int]$ProcessId)
    if ($ProcessId -eq 0 -or $ProcessId -eq 4) { return $null }
    if ($ProcessCache[$ProcessId]) { return $ProcessCache[$ProcessId] }
    try {
        $proc = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
        if ($proc) {
            $info = New-Object PSObject -Property @{
                ProcessId = $proc.ProcessId; Name = $proc.Name; Path = $proc.ExecutablePath
            }
            $ProcessCache[$ProcessId] = $info
            return $info
        }
    } catch {}
    return $null
}

#endregion

#region Data Collection Functions

function Get-PersistenceRegistry {
    $results = @(); $locations = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
                 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
    foreach ($loc in $locations) {
        try {
            if (Test-Path $loc) {
                $item = Get-ItemProperty -Path $loc -ErrorAction Stop
                if ($item) {
                    $propNames = $item | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -notmatch '^PS' } | Select-Object -ExpandProperty Name
                    foreach ($name in $propNames) {
                        $value = $item.$name
                        $results += New-Object PSObject -Property @{
                            Type = "Registry"; ThreatScore = 4; Finding = "Autorun: $($name)"; Details = $value; FileHash = Get-FileHashSafe -FilePath $value
                        }
                    }
                }
            }
        } catch { Write-Log ("Failed to read registry path ${loc}: $_") 'WARN' }
    }
    return $results
}

function Get-ServicePersistence {
    $results = @(); try { Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | ForEach-Object {
            $results += New-Object PSObject -Property @{
                Type = "Service"; ThreatScore = 5; Finding = "Service: $($_.Name)"; Details = $_.PathName; Account = $_.StartName; FileHash = Get-FileHashSafe -FilePath $_.PathName
            }
    }} catch { Write-Log ("Failed to enumerate services: $_") 'WARN' }; return $results
}

function Get-ScheduledTaskPersistence {
    $results = @(); try { Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
            $actions = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
            $results += New-Object PSObject -Property @{
                Type = "ScheduledTask"; ThreatScore = 6; Finding = "Task: $($_.TaskPath)"; Details = $actions; FileHash = Get-FileHashSafe -FilePath $actions
            }
    }} catch { Write-Log ("Failed to enumerate scheduled tasks: $_") 'WARN' }; return $results
}

function Get-WmiPersistence {
    $results = @(); $WmiAllowList = @("SCM Event Log Consumer", "SCM Event Log Filter")
    try { $bindings = Get-CimInstance -Namespace "root\subscription" -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue
        if ($bindings) { foreach ($binding in $bindings) {
                $consumerName = ($binding.Consumer -split '"')[1]; $filterName = ($binding.Filter -split '"')[1]
                if ($consumerName -in $WmiAllowList -or $filterName -in $WmiAllowList) { continue }
                $filterDetails = Get-CimInstance -Namespace "root\subscription" -Query "SELECT * FROM __EventFilter WHERE Name='$filterName'"
                $results += New-Object PSObject -Property @{
                    Type = "WMI"; ThreatScore = 10; Finding = "WMI Persistence: $consumerName"; Details = "Filter Query: $($filterDetails.Query)"
                }
    }}} catch { Write-Log ("Failed to query WMI persistence: $_") 'WARN' }; return $results
}

function Get-ComHijacking {
    $results = @(); $clsidPath = 'HKCU:\Software\Classes\CLSID'; if (-not(Test-Path $clsidPath)) { return $results }
    try { Get-ChildItem -Path $clsidPath -Recurse -ErrorAction SilentlyContinue | Where-Object { ($_.Name -split '\\')[-1] -eq 'InprocServer32' } | ForEach-Object {
            $defaultValue = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).'(Default)'
            if ($defaultValue) {
                 $results += New-Object PSObject -Property @{
                    Type = "COM Hijack"; ThreatScore = 9; Finding = "InprocServer32 Entry"; Details = "CLSID $($_.PSParentPath -replace '.*\\') points to $defaultValue"; FileHash = Get-FileHashSafe -FilePath $defaultValue
                }
            }
    }} catch { Write-Log ("Failed to scan for COM Hijacking: $_") 'WARN' }; return $results
}

function Get-PsProfilePersistence {
    $results = @(); $profilePaths = $PROFILE | Get-Member -MemberType NoteProperty | ForEach-Object { $PROFILE.($_.Name) } | Select-Object -Unique
    foreach ($path in $profilePaths) { if (Test-Path $path) {
            $results += New-Object PSObject -Property @{
                Type = "PS Profile"; ThreatScore = 7; Finding = "PowerShell Profile Script Exists"; Details = "Path: $path. Review content manually."
            }
    }}; return $results
}

function Get-NetworkConnections {
    $results = @()
    try { $tcp = Get-NetTCPConnection -State Established -ErrorAction Stop
        foreach ($t in $tcp) {
            $procInfo = Get-ProcessInfoByPid -ProcessId $t.OwningProcess
            $results += New-Object PSObject -Property @{
                Type = 'Network'; ThreatScore = 2; Finding = "Process: $(if ($procInfo) { $procInfo.Name } else { 'N/A' }) (PID: $($t.OwningProcess))";
                Details = "$($t.LocalAddress):$($t.LocalPort) -> $($t.RemoteAddress):$($t.RemotePort)"; ProcessPath = if ($procInfo) { $procInfo.Path } else { 'N/A' }
            }
        }
    }
    catch { Write-Log ("Get-NetTCPConnection failed. Using netstat. Reason: $_") 'WARN'
        $netstat = netstat -ano -p TCP | Select-String "ESTABLISHED"
        foreach ($line in $netstat) {
            $parts = ($line -replace '^\s+') -split '\s+'; if ($parts.Count -ge 4) {
                $procInfo = Get-ProcessInfoByPid -ProcessId $parts[4]
                $results += New-Object PSObject -Property @{
                    Type = 'Network'; ThreatScore = 2; Finding = "Process: $(if ($procInfo) { $procInfo.Name } else { 'N/A' }) (PID: $($parts[4]))";
                    Details = "$($parts[1]) -> $($parts[2])"; ProcessPath = if ($procInfo) { $procInfo.Path } else { 'N/A' }
                }
            }
        }
    }
    return $results
}

#endregion

#region Reporting and Analysis

function Export-Results {
    param([Parameter(Mandatory=$true)]$Object, [Parameter(Mandatory=$true)][string]$BaseName, [string]$Folder)
    if (-not $Object -or $Object.Count -eq 0) { return }
    try {
        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $jsonPath = Join-Path -Path $Folder -ChildPath ($BaseName + "-" + $timestamp + ".json")
        $csvPath  = Join-Path -Path $Folder -ChildPath ($BaseName + "-" + $timestamp + ".csv")
        $Object | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding utf8
        $Object | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8
    }
    catch { Write-Log ("Failed to export ${BaseName}: $_") 'ERROR' }
}

function Show-SuspiciousSummary {
    param($AllData)
    Write-Color "`n----------- SMART SUMMARY OF POTENTIAL IOCs (Sorted by Threat Score) -----------" 'Magenta'
    $filteredData = @()
    foreach($item in $AllData){
        if( ($item.Type -in @('WMI','COM Hijack','PS Profile')) -or 
            ($item.Details -match $SuspiciousPathsRegex) -or 
            ($item.Details -match $SuspiciousKeywordsRegex) -or
            ($item.PSObject.Properties['ProcessPath'] -and $item.ProcessPath -match $SuspiciousPathsRegex) ){
            $filteredData += $item
        }
    }
    if ($filteredData) {
        $filteredData | Sort-Object ThreatScore -Descending | Format-Table -Property @{N="Score";E={$_.ThreatScore}},Type,Finding,Details -Wrap
    } else { Write-Color "No high-confidence suspicious items found based on heuristics." 'Green' }
    Write-Color "-------------------------------- END OF SUMMARY --------------------------------" 'Magenta'
    Write-Color "A full report with all collected artifacts (including file hashes) has been saved." 'Cyan'
    Write-Color "For suspicious items, investigate the corresponding FileHash in the exported files on VirusTotal." 'Cyan'
}
#endregion

# ------------------ MAIN -------------------
try {
    Ensure-RunningAsAdmin
    $out = Ensure-OutputFolder -Path $OutputFolder
    Write-Color ("PThreatHunter v2.0 (CLM Compatible) - Report folder: $out") 'Cyan'
    $allData = @()

    Write-Log "Starting scan..."
    Write-Color "Enumerating registry persistence..." 'Yellow'; $allData += Get-PersistenceRegistry
    Write-Color "Enumerating services..." 'Yellow'; $allData += Get-ServicePersistence
    Write-Color "Enumerating scheduled tasks..." 'Yellow'; $allData += Get-ScheduledTaskPersistence
    Write-Color "Enumerating WMI persistence..." 'Yellow'; $allData += Get-WmiPersistence
    Write-Color "Scanning for COM Hijacking..." 'Yellow'; $allData += Get-ComHijacking
    Write-Color "Checking PowerShell Profiles..." 'Yellow'; $allData += Get-PsProfilePersistence
    # FIX: Network connections are now being scanned.
    Write-Color "Collecting network connections..." 'Yellow'; $allData += Get-NetworkConnections
    # Event Log analysis is disabled by default due to performance impact, but can be re-enabled.
    # Write-Color "Analyzing Event Logs (this may take a moment)..." 'Yellow'; $allData += Analyze-EventLogs

    Write-Log "Scan complete. Found $($allData.Count) total artifacts."
    Write-Color "Exporting full report..." 'Yellow'
    Export-Results -Object $allData -BaseName 'full-report' -Folder $out
    Show-SuspiciousSummary -AllData $allData
    Write-Color "`nDone. Full report (JSON/CSV) written to: $out" 'Green'
}
catch {
    Write-Log ("Fatal error: $_") 'ERROR'
    Write-Color "An error occurred. See output folder for partial results if any." 'Red'
}
# EOF