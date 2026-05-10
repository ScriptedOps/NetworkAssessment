<#
.SYNOPSIS
    Read-only network and domain assessment starter tool for authorised MSP prospecting/onboarding.

.DESCRIPTION
    SB Network Assessment collects safe inventory, Active Directory, common port, and optional Windows health data.
    It generates CSV, JSON and HTML outputs suitable for engineer review and client-facing reporting.

    The tool is intentionally read-only. It does not exploit systems, collect passwords, brute force credentials,
    attempt default logins, or make configuration changes.

.PARAMETER ClientName
    Name used in report titles and output folder naming.

.PARAMETER Mode
    Lite performs safe local/AD/network discovery. Deep adds authenticated Windows health collection over PowerShell Remoting.

.PARAMETER Subnets
    CIDR subnets to ping sweep. Example: 192.168.1.0/24. Keep scope tight and authorised.

.PARAMETER AcceptScope
    Required acknowledgement that you have written authorisation and agreed scope.

.EXAMPLE
    .\Invoke-SBNetworkAssessment.ps1 -ClientName "Contoso" -Mode Lite -Subnets 192.168.1.0/24 -AcceptScope

.EXAMPLE
    .\Invoke-SBNetworkAssessment.ps1 -ClientName "Contoso" -Mode Deep -Subnets 192.168.1.0/24 -AcceptScope -PortTimeoutMs 600
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ClientName,
    [ValidateSet('Lite','Deep')][string]$Mode = 'Lite',
    [string[]]$Subnets = @(),
    [int[]]$Ports = @(),
    [string]$OutputRoot = (Join-Path $PSScriptRoot 'output'),
    [int]$MaxHostsPerSubnet = 512,
    [int]$PortTimeoutMs = 400,
    [int]$StaleDays = 90,
    [switch]$SkipAD,
    [switch]$SkipNetwork,
    [switch]$SkipLocalWindows,
    [switch]$AcceptScope
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $AcceptScope) {
    throw "Run aborted. Re-run with -AcceptScope only after written client authorisation and a defined assessment scope."
}

$modulePath = Join-Path $PSScriptRoot 'modules'
Import-Module (Join-Path $modulePath 'SBNA.Common.psm1') -Force
Import-Module (Join-Path $modulePath 'SBNA.AD.psm1') -Force
Import-Module (Join-Path $modulePath 'SBNA.Network.psm1') -Force
Import-Module (Join-Path $modulePath 'SBNA.Windows.psm1') -Force
Import-Module (Join-Path $modulePath 'SBNA.Report.psm1') -Force

if (-not (Test-Path $OutputRoot)) { New-Item -Path $OutputRoot -ItemType Directory -Force | Out-Null }
$outputPath = New-SBNAOutputFolder -OutputRoot $OutputRoot -ClientName $ClientName
$logPath = Join-Path $outputPath 'assessment.log'

Write-SBNALog -Message "Starting SB Network Assessment for $ClientName in $Mode mode." -Level INFO -LogPath $logPath
Write-SBNALog -Message "Output path: $outputPath" -Level INFO -LogPath $logPath

if (-not (Test-SBNAIsAdmin)) {
    Write-SBNALog -Message 'PowerShell is not running elevated. Some local Windows checks may be incomplete.' -Level WARN -LogPath $logPath
}

if (-not $Ports -or $Ports.Count -eq 0) {
    $Ports = @((Get-SBNACommonPorts).Port)
}

$assessment = [ordered]@{
    Tool            = 'SB Network Assessment'
    ToolVersion     = '0.1.0'
    ClientName      = $ClientName
    Mode            = $Mode
    StartedAt       = (Get-Date).ToString('s')
    CompletedAt     = $null
    Scope           = [pscustomobject]@{
        Subnets            = $Subnets
        Ports              = $Ports
        MaxHostsPerSubnet  = $MaxHostsPerSubnet
        PortTimeoutMs      = $PortTimeoutMs
        StaleDays          = $StaleDays
    }
    LocalNetwork    = $null
    ActiveDirectory = $null
    Dhcp            = $null
    Devices         = @()
    PortInventory   = @()
    WindowsHealth   = @()
    Findings        = @()
    Errors          = @()
}

try {
    if (-not $SkipLocalWindows) {
        Write-SBNALog -Message 'Collecting local Windows health.' -Level INFO -LogPath $logPath
        $localHealth = Get-SBNALocalWindowsHealth
        $assessment.WindowsHealth += $localHealth
        $assessment.Findings += @(New-SBNAWindowsFindings -WindowsHealth @($localHealth))
        Save-SBNAJson -InputObject $localHealth -Path (Join-Path $outputPath 'raw\local-windows-health.json')
    }

    if (-not $SkipAD) {
        Write-SBNALog -Message 'Collecting Active Directory summary.' -Level INFO -LogPath $logPath
        $adSummary = Get-SBNAADSummary -StaleDays $StaleDays
        $assessment.ActiveDirectory = $adSummary
        $assessment.Findings += @($adSummary.Findings)
        Save-SBNAJson -InputObject $adSummary -Path (Join-Path $outputPath 'raw\active-directory-summary.json')

        $adComputers = @(Get-SBNAADComputers)
        if ($adComputers.Count -gt 0) {
            $adComputers | Export-Csv -Path (Join-Path $outputPath 'csv\ad-computers.csv') -NoTypeInformation
        }
    }

    if (-not $SkipNetwork) {
        Write-SBNALog -Message 'Collecting local network information.' -Level INFO -LogPath $logPath
        $assessment.LocalNetwork = Get-SBNALocalNetworkInfo
        Save-SBNAJson -InputObject $assessment.LocalNetwork -Path (Join-Path $outputPath 'raw\local-network.json')

        Write-SBNALog -Message 'Collecting ARP table.' -Level INFO -LogPath $logPath
        $arp = @(Get-SBNAArpTable)
        if ($arp.Count -gt 0) { $arp | Export-Csv -Path (Join-Path $outputPath 'csv\arp-table.csv') -NoTypeInformation }

        Write-SBNALog -Message 'Collecting DHCP summary if available.' -Level INFO -LogPath $logPath
        $assessment.Dhcp = Get-SBNADhcpSummary
        Save-SBNAJson -InputObject $assessment.Dhcp -Path (Join-Path $outputPath 'raw\dhcp-summary.json')

        $discovered = New-Object System.Collections.Generic.List[object]

        if ($Subnets.Count -gt 0) {
            Write-SBNALog -Message "Running scoped ping sweep across $($Subnets -join ', ')." -Level INFO -LogPath $logPath
            foreach ($d in @(Get-SBNAPingSweep -Subnets $Subnets -MaxHostsPerSubnet $MaxHostsPerSubnet)) {
                $discovered.Add([pscustomobject]@{
                    IPAddress = $d.IPAddress
                    Hostname  = $d.Hostname
                    Source    = 'PingSweep'
                })
            }
        }
        else {
            Write-SBNALog -Message 'No subnets supplied. Network discovery will use AD computer IPs and ARP table only.' -Level WARN -LogPath $logPath
        }

        foreach ($entry in $arp) {
            if ($entry.IPAddress -and -not ($discovered | Where-Object IPAddress -eq $entry.IPAddress)) {
                $name = Resolve-SBNAReverseDns -IPAddress $entry.IPAddress
                $discovered.Add([pscustomobject]@{
                    IPAddress = $entry.IPAddress
                    Hostname  = $name
                    Source    = 'ARP'
                })
            }
        }

        if ($assessment.ActiveDirectory) {
            foreach ($computer in @(Get-SBNAADComputers)) {
                if ($computer.IPv4Address -and -not ($discovered | Where-Object IPAddress -eq $computer.IPv4Address)) {
                    $discovered.Add([pscustomobject]@{
                        IPAddress = $computer.IPv4Address
                        Hostname  = $computer.DNSHostName
                        Source    = 'ActiveDirectory'
                    })
                }
            }
        }

        $uniqueDevices = @($discovered | Sort-Object IPAddress -Unique)
        Write-SBNALog -Message "Checking common ports on $($uniqueDevices.Count) discovered device(s)." -Level INFO -LogPath $logPath
        $portsOpen = @(Get-SBNAPortInventory -Devices $uniqueDevices -Ports $Ports -TimeoutMs $PortTimeoutMs)
        $assessment.PortInventory = $portsOpen
        $assessment.Findings += @(New-SBNANetworkFindings -PortInventory $portsOpen)

        $deviceRows = foreach ($device in $uniqueDevices) {
            $open = @($portsOpen | Where-Object IPAddress -eq $device.IPAddress)
            $openPortNums = @($open.Port)
            [pscustomobject]@{
                IPAddress  = $device.IPAddress
                Hostname   = $device.Hostname
                Source     = $device.Source
                DeviceType = Get-SBNADeviceTypeGuess -Name $device.Hostname -OpenPorts $openPortNums
                OpenPorts  = ($open | ForEach-Object { "$($_.Port)/$($_.Service)" }) -join ', '
            }
        }
        $assessment.Devices = @($deviceRows)

        if ($assessment.Devices.Count -gt 0) { $assessment.Devices | Export-Csv -Path (Join-Path $outputPath 'csv\devices.csv') -NoTypeInformation }
        if ($assessment.PortInventory.Count -gt 0) { $assessment.PortInventory | Export-Csv -Path (Join-Path $outputPath 'csv\open-ports.csv') -NoTypeInformation }
    }

    if ($Mode -eq 'Deep') {
        Write-SBNALog -Message 'Deep mode selected. Attempting authenticated Windows health checks over PowerShell Remoting.' -Level INFO -LogPath $logPath
        $windowsTargets = @()
        if ($assessment.ActiveDirectory) {
            $windowsTargets = @(Get-SBNAADComputers | Where-Object { $_.Enabled -eq $true -and $_.DNSHostName } | Select-Object -ExpandProperty DNSHostName -Unique)
        }
        elseif ($assessment.Devices.Count -gt 0) {
            $windowsTargets = @($assessment.Devices | Where-Object { $_.OpenPorts -match '5985|5986' -and $_.Hostname } | Select-Object -ExpandProperty Hostname -Unique)
        }

        if ($windowsTargets.Count -gt 0) {
            $remoteHealth = @(Get-SBNARemoteWindowsHealth -ComputerName $windowsTargets)
            $assessment.WindowsHealth += $remoteHealth
            $assessment.Findings += @(New-SBNAWindowsFindings -WindowsHealth $remoteHealth)
            Save-SBNAJson -InputObject $remoteHealth -Path (Join-Path $outputPath 'raw\remote-windows-health.json')
            $flatHealth = foreach ($h in $remoteHealth) {
                if ($h.PSObject.Properties.Name -contains 'Error') { [pscustomobject]@{ ComputerName=$h.ComputerName; Error=$h.Error } }
                else { [pscustomobject]@{ ComputerName=$h.ComputerName; Manufacturer=$h.Manufacturer; Model=$h.Model; Domain=$h.Domain; OS=$h.OS; OSVersion=$h.OSVersion; BuildNumber=$h.BuildNumber; UptimeDays=$h.UptimeDays; SerialNumber=$h.SerialNumber } }
            }
            $flatHealth | Export-Csv -Path (Join-Path $outputPath 'csv\windows-health-summary.csv') -NoTypeInformation
        }
        else {
            Write-SBNALog -Message 'No Windows targets found for Deep mode.' -Level WARN -LogPath $logPath
        }
    }

    $assessment.CompletedAt = (Get-Date).ToString('s')
    Save-SBNAJson -InputObject ([pscustomobject]$assessment) -Path (Join-Path $outputPath 'raw\assessment-full.json')
    if ($assessment.Findings.Count -gt 0) {
        $assessment.Findings | Export-Csv -Path (Join-Path $outputPath 'csv\findings.csv') -NoTypeInformation
    }

    $reportPath = Join-Path $outputPath 'assessment-report.html'
    New-SBNAHtmlReport -ClientName $ClientName -Mode $Mode -Assessment ([pscustomobject]$assessment) -OutputPath $reportPath | Out-Null

    Write-SBNALog -Message "Assessment complete. Report: $reportPath" -Level SUCCESS -LogPath $logPath
    [pscustomobject]@{
        ClientName = $ClientName
        Mode       = $Mode
        OutputPath = $outputPath
        Report     = $reportPath
        Findings   = $assessment.Findings.Count
        Devices    = $assessment.Devices.Count
    }
}
catch {
    $assessment.Errors += $_.Exception.Message
    Save-SBNAJson -InputObject ([pscustomobject]$assessment) -Path (Join-Path $outputPath 'raw\assessment-error.json')
    Write-SBNALog -Message $_.Exception.Message -Level ERROR -LogPath $logPath
    throw
}
