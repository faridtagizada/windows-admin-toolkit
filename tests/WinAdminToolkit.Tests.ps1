#Requires -Version 5.1
# Unit tests for the input checks of WinAdminToolkit.ps1 (Pester 5).
#
# The script is dot-sourced with WAT_SKIP_MAIN=1: that defines its functions and stops before the
# main part, so nothing on the machine is changed. Run from the repository folder:
#     Invoke-Pester -Path .\tests -Output Detailed
#
# Non-ASCII characters are built with [char] so that this file stays plain ASCII.

BeforeAll {
    $env:WAT_SKIP_MAIN = '1'
    try {
        . (Join-Path -Path $PSScriptRoot -ChildPath '..\WinAdminToolkit.ps1') -Action CollectLogs
    }
    finally {
        Remove-Item -Path 'Env:WAT_SKIP_MAIN' -ErrorAction SilentlyContinue
    }

    $kelvinSign = [string][char]0x212A          # looks like K
    $dottedCapitalI = [string][char]0x0130      # I with a dot (Turkish, Azerbaijani)
    $arabicPort = -join @([char]0x0664, [char]0x0664, [char]0x0663)   # 443 in Arabic-Indic digits

    function New-RuleRow {
        param([hashtable]$Values)
        $row = [ordered]@{ SourceLine = 2 }
        foreach ($column in $script:FirewallColumns) { $row[$column] = '' }
        foreach ($key in $Values.Keys) { $row[$key] = $Values[$key] }
        return [pscustomobject]$row
    }

    function Get-RulePlan {
        param([hashtable]$Values)
        $errors = [System.Collections.Generic.List[string]]::new()
        $rule = ConvertTo-FirewallRulePlan -Row (New-RuleRow -Values $Values) -Line 2 -Errors $errors
        return [pscustomobject]@{ Rule = $rule; Errors = $errors.ToArray() }
    }
}

Describe 'Test-LocalUserName' {
    It 'accepts <Name>' -TestCases @(
        @{ Name = 'ali.mammadov' }
        @{ Name = 'tecrubeci01' }
        @{ Name = 'A_b-c' }
    ) {
        Test-LocalUserName -Name $Name | Should -BeNullOrEmpty
    }

    It 'rejects the Kelvin sign, which -match took for a K' {
        Test-LocalUserName -Name ('admin' + $kelvinSign) | Should -Not -BeNullOrEmpty
    }

    It 'rejects a dotted capital I, which -match took for an I' {
        Test-LocalUserName -Name ($dottedCapitalI + 'lkin') | Should -Not -BeNullOrEmpty
    }

    It 'rejects <Name>' -TestCases @(
        @{ Name = '' }
        @{ Name = '-ali' }
        @{ Name = '.ali' }
        @{ Name = 'ali.' }
        @{ Name = 'a' * 21 }
        @{ Name = 'ali mammadov' }
    ) {
        Test-LocalUserName -Name $Name | Should -Not -BeNullOrEmpty
    }
}

Describe 'Test-PortSpec' {
    It 'accepts <Value>' -TestCases @(
        @{ Value = '1' }
        @{ Value = '443' }
        @{ Value = '65535' }
        @{ Value = '8000-8080' }
    ) {
        Test-PortSpec -Value $Value | Should -BeTrue
    }

    It 'rejects <Value>' -TestCases @(
        @{ Value = '0' }
        @{ Value = '65536' }
        @{ Value = '8080-8000' }
        @{ Value = 'http' }
        @{ Value = '' }
    ) {
        Test-PortSpec -Value $Value | Should -BeFalse
    }

    It 'rejects Arabic-Indic digits instead of throwing a .NET error' {
        { Test-PortSpec -Value $arabicPort } | Should -Not -Throw
        Test-PortSpec -Value $arabicPort | Should -BeFalse
    }
}

Describe 'Test-IpAddressText' {
    It 'accepts <Text>' -TestCases @(
        @{ Text = '10.0.0.1' }
        @{ Text = '255.255.255.255' }
        @{ Text = '2001:db8::1' }
        @{ Text = '::1' }
        @{ Text = '::ffff:192.0.2.1' }
    ) {
        Test-IpAddressText -Text $Text | Should -BeTrue
    }

    It 'rejects <Text>' -TestCases @(
        @{ Text = '10.1' }
        @{ Text = '010.0.0.1' }
        @{ Text = '256.0.0.1' }
        @{ Text = '[::1]' }
        @{ Text = '[::1]:3389' }
        @{ Text = 'fe80::1%12' }
        @{ Text = 'example.com' }
    ) {
        Test-IpAddressText -Text $Text | Should -BeFalse
    }

    It 'rejects an IPv4 address written with Arabic-Indic digits' {
        $text = ([char]0x0661 + [char]0x0660) + '.0.0.1'
        Test-IpAddressText -Text $text | Should -BeFalse
    }
}

Describe 'Resolve-RemoteAddressToken' {
    It 'keeps <Token>' -TestCases @(
        @{ Token = '10.0.0.0/8' }
        @{ Token = '192.168.1.0/255.255.255.0' }
        @{ Token = '10.0.0.1-10.0.0.50' }
        @{ Token = '2001:db8::/32' }
        @{ Token = 'LocalSubnet' }
    ) {
        Resolve-RemoteAddressToken -Token $Token | Should -Be $Token
    }

    It 'rejects <Token>' -TestCases @(
        @{ Token = '10.0.0.50-10.0.0.1' }
        @{ Token = '10.0.0.0/33' }
        @{ Token = '192.168.1.0/255.0.255.0' }
        @{ Token = '[::1]' }
        @{ Token = '[::1]:3389' }
    ) {
        Resolve-RemoteAddressToken -Token $Token | Should -BeNullOrEmpty
    }
}

Describe 'Test-AnyAddress (decided by coverage, not by spelling)' {
    It 'treats <Text> as anywhere' -TestCases @(
        @{ Text = '' }
        @{ Text = '0.0.0.0/0' }
        @{ Text = '::/0' }
        @{ Text = '0.0.0.0/0.0.0.0' }
        @{ Text = '0.0.0.0/1|128.0.0.0/1' }
        @{ Text = '0.0.0.1-255.255.255.255' }
        @{ Text = '1.0.0.0-223.255.255.255' }
        @{ Text = '2000::/3' }
        @{ Text = 'Internet' }
        @{ Text = '10.0.0.0/8|0.0.0.0/1|128.0.0.0/2|192.0.0.0/3' }
    ) {
        $addresses = @($Text -split '\|' | Where-Object { $_ -ne '' })
        Test-AnyAddress -Addresses $addresses | Should -BeTrue
    }

    It 'does not treat <Text> as anywhere' -TestCases @(
        @{ Text = '10.0.0.0/8|192.168.0.0/16' }
        @{ Text = '0.0.0.0/2|128.0.0.0/1' }
        @{ Text = '0.0.0.0/1' }
        @{ Text = 'LocalSubnet' }
        @{ Text = '2001:db8::/32' }
        @{ Text = '203.0.113.7' }
    ) {
        $addresses = @($Text -split '\|' | Where-Object { $_ -ne '' })
        Test-AnyAddress -Addresses $addresses | Should -BeFalse
    }
}

Describe 'Get-FirewallRuleRisk' {
    It 'needs -AllowRiskyRules for "all ports from everywhere" written as two halves' {
        $plan = Get-RulePlan -Values @{ Name = 'T1'; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'TCP'; RemoteAddress = '0.0.0.0/1|128.0.0.0/1' }
        $plan.Errors | Should -BeNullOrEmpty
        $plan.Rule.Risk | Should -Not -BeNullOrEmpty
    }

    It 'needs -AllowRiskyRules for "all ports from the Internet"' {
        $plan = Get-RulePlan -Values @{ Name = 'T2'; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'TCP'; RemoteAddress = 'Internet' }
        $plan.Errors | Should -BeNullOrEmpty
        $plan.Rule.Risk | Should -Not -BeNullOrEmpty
    }

    It 'lets a LAN-only rule through' {
        $plan = Get-RulePlan -Values @{ Name = 'T3'; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'TCP'; LocalPort = '1433'; RemoteAddress = '10.0.0.0/8' }
        $plan.Errors | Should -BeNullOrEmpty
        $plan.Rule.Risk | Should -BeNullOrEmpty
    }
}

Describe 'ConvertTo-FirewallRulePlan' {
    It 'keeps an ICMP type for ICMPv4' {
        $plan = Get-RulePlan -Values @{ Name = 'Ping'; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'ICMPv4'; RemoteAddress = 'LocalSubnet'; IcmpType = '8' }
        $plan.Errors | Should -BeNullOrEmpty
        ($plan.Rule.IcmpType -join ',') | Should -Be '8'
    }

    It 'accepts type:code and several values' {
        $plan = Get-RulePlan -Values @{ Name = 'Icmp'; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'ICMPv6'; IcmpType = '128|1:4' }
        $plan.Errors | Should -BeNullOrEmpty
        ($plan.Rule.IcmpType -join ',') | Should -Be '128,1:4'
    }

    It 'reads an empty IcmpType and Any as all types' -TestCases @(
        @{ Value = '' }
        @{ Value = 'Any' }
    ) {
        $plan = Get-RulePlan -Values @{ Name = 'Icmp'; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'ICMPv4'; IcmpType = $Value }
        $plan.Errors | Should -BeNullOrEmpty
        @($plan.Rule.IcmpType).Count | Should -Be 0
    }

    It 'rejects IcmpType <Value> with <Protocol>' -TestCases @(
        @{ Protocol = 'TCP'; Value = '8' }
        @{ Protocol = 'ICMPv4'; Value = '256' }
        @{ Protocol = 'ICMPv4'; Value = '8:256' }
        @{ Protocol = 'ICMPv4'; Value = 'echo' }
        @{ Protocol = 'ICMPv4'; Value = 'Any|8' }
    ) {
        $plan = Get-RulePlan -Values @{ Name = 'Icmp'; Direction = 'Inbound'; Action = 'Allow'; Protocol = $Protocol; IcmpType = $Value }
        $plan.Errors | Should -Not -BeNullOrEmpty
        $plan.Rule | Should -BeNullOrEmpty
    }

    It 'rejects a rule name with the Kelvin sign' {
        $plan = Get-RulePlan -Values @{ Name = ('Web' + $kelvinSign); Direction = 'Inbound'; Action = 'Allow'; Protocol = 'TCP'; LocalPort = '443'; RemoteAddress = '10.0.0.0/8' }
        $plan.Errors | Should -Not -BeNullOrEmpty
    }

    It 'gives a validation error, not a .NET error, for a port in Arabic-Indic digits' {
        { Get-RulePlan -Values @{ Name = 'Web'; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'TCP'; LocalPort = $arabicPort; RemoteAddress = '10.0.0.0/8' } } | Should -Not -Throw
        $plan = Get-RulePlan -Values @{ Name = 'Web'; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'TCP'; LocalPort = $arabicPort; RemoteAddress = '10.0.0.0/8' }
        $plan.Errors | Should -Not -BeNullOrEmpty
    }

    It 'rejects a bracketed IPv6 address' {
        $plan = Get-RulePlan -Values @{ Name = 'Web'; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'TCP'; LocalPort = '443'; RemoteAddress = '[::1]:3389' }
        $plan.Errors | Should -Not -BeNullOrEmpty
    }
}

Describe 'Write-Utf8File' {
    It 'writes a BOM by default' {
        $path = Join-Path -Path $TestDrive -ChildPath 'bom.txt'
        Write-Utf8File -Path $path -Content 'abc'
        $bytes = [System.IO.File]::ReadAllBytes($path)
        ($bytes[0..2] -join ',') | Should -Be '239,187,191'
    }

    It 'writes no BOM with -NoBom, so sha256sum can read the checksum file' {
        $path = Join-Path -Path $TestDrive -ChildPath 'nobom.txt'
        Write-Utf8File -Path $path -Content "abc *file.zip`n" -NoBom
        $bytes = [System.IO.File]::ReadAllBytes($path)
        $bytes[0] | Should -Be ([byte][char]'a')
        $bytes.Length | Should -Be 14
    }
}

Describe 'Other helpers' {
    It 'neutralises CSV cells that Excel would run as a formula' -TestCases @(
        @{ Text = '=1+1'; Expected = "'=1+1" }
        @{ Text = '@SUM(A1)'; Expected = "'@SUM(A1)" }
        @{ Text = 'plain'; Expected = 'plain' }
    ) {
        ConvertTo-CsvSafeText -Text $Text | Should -Be $Expected
    }

    It 'reads both expiry date formats and nothing else' {
        ConvertTo-ExpiryDate -Text '2030-08-31' | Should -Be ([datetime]'2030-08-31')
        ConvertTo-ExpiryDate -Text '31.08.2030' | Should -Be ([datetime]'2030-08-31')
        ConvertTo-ExpiryDate -Text '08/31/2030' | Should -BeNullOrEmpty
    }

    It 'makes passwords of the requested length without the forbidden words' {
        $password = Get-RandomPassword -Length 20 -Forbidden @('mammadov')
        $password.Length | Should -Be 20
        $password | Should -Not -Match 'mammadov'
        $password | Should -MatchExactly '[A-Z]'
        $password | Should -MatchExactly '[a-z]'
        $password | Should -Match '[0-9]'
    }
}
