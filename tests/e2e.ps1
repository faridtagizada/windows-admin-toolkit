#Requires -Version 5.1
<#
.SYNOPSIS
    End-to-end test of WinAdminToolkit.ps1 on a real Windows machine.

.DESCRIPTION
    This test CHANGES THE MACHINE: it creates three local accounts and four firewall rules, exports
    event logs, and removes the accounts and rules again at the end. Run it only on a throw-away
    machine (a VM snapshot or a CI runner), as Administrator, in Windows PowerShell 5.1:

        powershell -ExecutionPolicy Bypass -File .\tests\e2e.ps1 -ThrowAwayMachine

    If PowerShell 7 (pwsh) is installed, the firewall and log actions are run with it as well.
#>
[CmdletBinding()]
param(
    [switch]$ThrowAwayMachine
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $ThrowAwayMachine) {
    throw 'This test creates accounts and firewall rules. Run it only on a throw-away machine and pass -ThrowAwayMachine.'
}

$root = Split-Path -Path $PSScriptRoot -Parent
$tool = Join-Path -Path $root -ChildPath 'WinAdminToolkit.ps1'
$sampleUsers = Join-Path -Path $root -ChildPath 'samples\users.csv'
$sampleRules = Join-Path -Path $root -ChildPath 'samples\firewall-rules.csv'
$workDirectory = Join-Path -Path $env:SystemDrive -ChildPath 'AdminToolkitE2E'
$ruleGroup = 'WinAdminToolkitE2E'
$userNames = @('ali.mammadov', 'leyla.huseynova', 'tecrubeci01')
$scratch = Join-Path -Path $env:TEMP -ChildPath ('wat-e2e-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -Path $scratch -ItemType Directory
$failures = [System.Collections.Generic.List[string]]::new()

function Write-Check {
    param(
        [bool]$Condition,
        [string]$Message
    )
    if ($Condition) {
        Write-Information -MessageData ('ok   - ' + $Message) -InformationAction Continue
    }
    else {
        Write-Information -MessageData ('FAIL - ' + $Message) -InformationAction Continue
        $script:failures.Add($Message)
    }
}

function Invoke-Toolkit {
    param(
        [hashtable]$Parameters,
        [string]$Shell = 'powershell'
    )
    Write-Information -MessageData ('>>> {0} {1}' -f $Shell, (($Parameters.GetEnumerator() | Sort-Object -Property Key | ForEach-Object { '-{0} {1}' -f $_.Key, $_.Value }) -join ' ')) -InformationAction Continue
    if ($Shell -eq 'powershell') {
        & $tool @Parameters | Out-Host
    }
    else {
        $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $tool)
        foreach ($entry in $Parameters.GetEnumerator()) {
            if ($entry.Value -is [bool]) {
                if ($entry.Value) { $arguments += ('-' + $entry.Key) }
            }
            else {
                $arguments += @(('-' + $entry.Key), [string]$entry.Value)
            }
        }
        & $Shell @arguments | Out-Host
    }
    return $LASTEXITCODE
}

function Get-NewestRunDirectory {
    param([string]$Action)
    return Get-ChildItem -LiteralPath $workDirectory -Directory |
        Where-Object { $_.Name -like ('*_' + $Action) } |
        Sort-Object -Property Name |
        Select-Object -Last 1
}

function New-TestCsv {
    param(
        [string]$Name,
        [string[]]$Lines
    )
    $path = Join-Path -Path $scratch -ChildPath $Name
    [System.IO.File]::WriteAllLines($path, $Lines, (New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $true))
    return $path
}

try {
    # ---- 1) Dry runs change nothing ------------------------------------------------------------
    $code = Invoke-Toolkit @{ Action = 'CreateUsers'; CsvPath = $sampleUsers; WorkDirectory = $workDirectory; WhatIf = $true }
    Write-Check ($code -eq 0) "CreateUsers -WhatIf exits with 0 (got $code)"
    Write-Check (@(Get-LocalUser | Where-Object { $userNames -contains $_.Name }).Count -eq 0) 'CreateUsers -WhatIf creates no account'

    $code = Invoke-Toolkit @{ Action = 'ConfigureFirewall'; CsvPath = $sampleRules; RuleGroup = $ruleGroup; WorkDirectory = $workDirectory; WhatIf = $true }
    Write-Check ($code -eq 0) "ConfigureFirewall -WhatIf exits with 0 (got $code)"
    Write-Check (@(Get-NetFirewallRule -Group $ruleGroup -ErrorAction SilentlyContinue).Count -eq 0) 'ConfigureFirewall -WhatIf adds no rule'

    # ---- 2) Accounts ---------------------------------------------------------------------------
    $code = Invoke-Toolkit @{ Action = 'CreateUsers'; CsvPath = $sampleUsers; WorkDirectory = $workDirectory; Force = $true }
    Write-Check ($code -eq 0) "CreateUsers exits with 0 (got $code)"
    foreach ($name in $userNames) {
        $user = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
        Write-Check ($null -ne $user -and $user.Enabled) "$name exists and is enabled"
        if ($user) {
            $adsiUser = [ADSI]('WinNT://{0}/{1},user' -f $env:COMPUTERNAME, $name)
            Write-Check ([int]$adsiUser.InvokeGet('PasswordExpired') -eq 1) "$name has to change the password at the next logon"
        }
    }
    $rdpMembers = @(Get-LocalGroupMember -SID 'S-1-5-32-555' | Where-Object { $_.Name -like '*\leyla.huseynova' })
    Write-Check ($rdpMembers.Count -eq 1) 'leyla.huseynova is in Remote Desktop Users'
    $intern = Get-LocalUser -Name 'tecrubeci01' -ErrorAction SilentlyContinue
    Write-Check ($null -ne $intern -and $null -ne $intern.AccountExpires -and $intern.AccountExpires.Date -eq [datetime]'2030-09-01') 'tecrubeci01 expires at the end of 2030-08-31'

    $runDirectory = Get-NewestRunDirectory -Action 'CreateUsers'
    $credentials = @()
    if ($runDirectory) {
        $credentialFile = Join-Path -Path $runDirectory.FullName -ChildPath 'credentials.csv'
        if (Test-Path -LiteralPath $credentialFile) {
            $credentials = @(Import-Csv -LiteralPath $credentialFile -Delimiter ([System.Globalization.CultureInfo]::CurrentCulture.TextInfo.ListSeparator))
        }
    }
    Write-Check (@($credentials | Where-Object { $_.Status -eq 'OK' }).Count -eq 3) 'credentials.csv lists the three new accounts'

    $code = Invoke-Toolkit @{ Action = 'CreateUsers'; CsvPath = $sampleUsers; WorkDirectory = $workDirectory; Force = $true }
    Write-Check ($code -eq 0) "a second CreateUsers run skips the existing accounts and exits with 0 (got $code)"

    $kelvinCsv = New-TestCsv -Name 'kelvin-users.csv' -Lines @('UserName,FullName,Description,Groups,AccountExpires', ('test' + [char]0x212A + ',,,Users,'))
    $code = Invoke-Toolkit @{ Action = 'CreateUsers'; CsvPath = $kelvinCsv; WorkDirectory = $workDirectory; Force = $true }
    Write-Check ($code -eq 2) "a user name with the Kelvin sign is refused (exit 2, got $code)"

    # ---- 3) Firewall rules ---------------------------------------------------------------------
    $code = Invoke-Toolkit @{ Action = 'ConfigureFirewall'; CsvPath = $sampleRules; RuleGroup = $ruleGroup; WorkDirectory = $workDirectory; Force = $true }
    Write-Check ($code -eq 0) "ConfigureFirewall exits with 0 (got $code)"
    $rules = @(Get-NetFirewallRule -Group $ruleGroup -PolicyStore PersistentStore -ErrorAction SilentlyContinue)
    Write-Check ($rules.Count -eq 4) "the four sample rules are in the group (got $($rules.Count))"
    $ping = Get-NetFirewallRule -Name 'WAT-Ping-In' -PolicyStore PersistentStore -ErrorAction SilentlyContinue
    if ($ping) {
        $pingFilter = $ping | Get-NetFirewallPortFilter
        Write-Check ((@($pingFilter.IcmpType) -join ',') -eq '8') "the ping rule allows ICMP type 8 only (got '$(@($pingFilter.IcmpType) -join ',')')"
    }
    else {
        Write-Check $false 'the ping rule exists'
    }
    $https = Get-NetFirewallRule -Name 'WAT-HTTPS-In' -PolicyStore PersistentStore -ErrorAction SilentlyContinue
    Write-Check ($null -ne $https -and [string]$https.Profile -eq 'Domain, Private') 'the HTTPS rule is limited to the Domain and Private profiles'

    $halvesCsv = New-TestCsv -Name 'halves.csv' -Lines @('Name,Direction,Action,Protocol,RemoteAddress', 'WAT-E2E-Halves,Inbound,Allow,TCP,0.0.0.0/1|128.0.0.0/1')
    $code = Invoke-Toolkit @{ Action = 'ConfigureFirewall'; CsvPath = $halvesCsv; RuleGroup = $ruleGroup; WorkDirectory = $workDirectory; Force = $true }
    Write-Check ($code -eq 2) "'all ports from 0.0.0.0/1|128.0.0.0/1' needs -AllowRiskyRules (exit 2, got $code)"
    Write-Check ($null -eq (Get-NetFirewallRule -Name 'WAT-E2E-Halves' -ErrorAction SilentlyContinue)) 'that rule was not added'

    $code = Invoke-Toolkit @{ Action = 'RemoveFirewallRules'; RuleGroup = $ruleGroup; WorkDirectory = $workDirectory; Force = $true }
    Write-Check ($code -eq 0) "RemoveFirewallRules exits with 0 (got $code)"
    Write-Check (@(Get-NetFirewallRule -Group $ruleGroup -ErrorAction SilentlyContinue).Count -eq 0) 'every rule of the group is removed'

    # ---- 4) Logs -------------------------------------------------------------------------------
    $code = Invoke-Toolkit @{ Action = 'CollectLogs'; Days = 1; WorkDirectory = $workDirectory }
    Write-Check ($code -eq 0) "CollectLogs exits with 0 (got $code)"
    $runDirectory = Get-NewestRunDirectory -Action 'CollectLogs'
    $zip = $null
    if ($runDirectory) {
        $zip = Get-ChildItem -LiteralPath $runDirectory.FullName -Filter '*_logs_*.zip' | Select-Object -First 1
    }
    Write-Check ($null -ne $zip) 'the ZIP was written'
    if ($zip) {
        $checksumBytes = [System.IO.File]::ReadAllBytes($zip.FullName + '.sha256')
        Write-Check ($checksumBytes[0] -ne 0xEF) 'the checksum file has no BOM'
        $expected = '{0} *{1}' -f (Get-FileHash -LiteralPath $zip.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $zip.Name
        Write-Check ([System.Text.Encoding]::ASCII.GetString($checksumBytes).TrimEnd() -eq $expected) 'the checksum line matches the ZIP'
        Write-Check (-not (Test-Path -LiteralPath (Join-Path -Path $runDirectory.FullName -ChildPath 'data'))) 'the unpacked data folder is gone'
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::OpenRead($zip.FullName)
        try { $entries = @($archive.Entries | ForEach-Object { $_.FullName }) }
        finally { $archive.Dispose() }
        foreach ($entry in @('System.evtx', 'Security.evtx', 'local-users.csv', 'system-info.txt')) {
            Write-Check ($entries -contains $entry) "the ZIP contains $entry"
        }
    }

    # ---- 5) PowerShell 7 -----------------------------------------------------------------------
    if (Get-Command -Name 'pwsh' -ErrorAction SilentlyContinue) {
        $code = Invoke-Toolkit -Shell 'pwsh' -Parameters @{ Action = 'CreateUsers'; CsvPath = $sampleUsers; WorkDirectory = $workDirectory; Force = $true }
        Write-Check ($code -eq 2) "CreateUsers stops in PowerShell 7 (exit 2, got $code)"
        $code = Invoke-Toolkit -Shell 'pwsh' -Parameters @{ Action = 'ConfigureFirewall'; CsvPath = $sampleRules; RuleGroup = $ruleGroup; WorkDirectory = $workDirectory; Force = $true }
        Write-Check ($code -eq 0) "ConfigureFirewall works in PowerShell 7 (got $code)"
        Write-Check (@(Get-NetFirewallRule -Group $ruleGroup -ErrorAction SilentlyContinue).Count -eq 4) 'PowerShell 7 added the four rules'
        $code = Invoke-Toolkit -Shell 'pwsh' -Parameters @{ Action = 'RemoveFirewallRules'; RuleGroup = $ruleGroup; WorkDirectory = $workDirectory; Force = $true }
        Write-Check ($code -eq 0) "RemoveFirewallRules works in PowerShell 7 (got $code)"
        $code = Invoke-Toolkit -Shell 'pwsh' -Parameters @{ Action = 'CollectLogs'; Days = 1; WorkDirectory = $workDirectory }
        Write-Check ($code -eq 0) "CollectLogs works in PowerShell 7 (got $code)"
    }
}
finally {
    foreach ($name in $userNames) {
        Remove-LocalUser -Name $name -ErrorAction SilentlyContinue
    }
    Get-NetFirewallRule -Group $ruleGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    throw ('{0} check(s) failed:{1}{2}' -f $failures.Count, [Environment]::NewLine, ($failures -join [Environment]::NewLine))
}
Write-Information -MessageData 'All end-to-end checks passed.' -InformationAction Continue
