# windows-admin-toolkit

A PowerShell script for routine Windows administration: create local user accounts from a CSV file, add Windows Defender Firewall rules from a CSV file, and collect event logs and basic diagnostics into a ZIP. One script, four actions.

Every row of a CSV is checked before anything changes. If even one row is wrong, nothing is changed at all. `-WhatIf` shows the plan without touching the system.

It creates accounts and changes firewall rules, and a firewall mistake can cut you off from a remote server. Snapshot the VM and try it there first, and keep a console session open (not only RDP) while you test firewall rules.

The script's messages and built-in help are in Azerbaijani: `Get-Help .\WinAdminToolkit.ps1 -Full`.

## Actions

| Action | What it does |
|---|---|
| `CreateUsers` | Creates local accounts from a CSV, adds them to groups and gives each a random temporary password that must be changed at first logon |
| `ConfigureFirewall` | Backs up the whole firewall policy, then adds rules from a CSV |
| `RemoveFirewallRules` | Removes only the rules this script added (everything in its rule group) |
| `CollectLogs` | Exports event logs and diagnostics into a ZIP with a SHA-256 checksum |

## Safeguards

- All input is checked first. Unknown or duplicate columns, a wrong number of fields, line breaks inside cells and invalid values are errors, and one error means nothing changes.
- The plan is shown and you're asked to confirm before any change. The default answer is No, so just pressing Enter does nothing. `-Force` skips the prompt for automation.
- Existing accounts and rules are skipped, never modified.
- There are no passwords in the CSV. Each account gets a cryptographically random temporary password and has to change it at first logon. The password is never passed to a PowerShell cmdlet, so it doesn't end up in Module Logging (event 4103).
- Accounts are created disabled and enabled only after they've been added to their groups. If a step fails, the half-created account is deleted.
- Adding anyone to Administrators, Backup Operators or Hyper-V Administrators needs `-AllowPrivilegedGroups`.
- Rules that could lock you out or open everything need `-AllowRiskyRules`: any inbound block that covers port 22, 3389, 5985 or 5986 or all ports (even when an address is given), blocking `svchost.exe`, `System` or `sshd.exe`, blocking all outbound traffic, and allowing all ports from anywhere.
- Allow rules go to the Domain and Private profiles by default, not Public.
- Before the firewall is touched, the full policy is exported with `netsh advfirewall export`. If one rule fails, the rules added in that run are removed again.
- The output folder (`-WorkDirectory`, default `C:\AdminToolkit`) and its parents are checked. If other users can write to them or rename them, the script stops. Each run gets a new folder that only Administrators and SYSTEM can open, from the moment it's created.
- `netsh`, `wevtutil` and `ipconfig` are started by full path from the system directory, not through `PATH`.
- Groups are looked up by SID, so it also works on Russian, Turkish or other localized Windows.
- Cells in the CSV files it writes that start with `=`, `+`, `-` or `@` get a `'` in front, so Excel doesn't treat them as formulas.

## Requirements

- Windows 10/11 or Windows Server 2016+
- An elevated session (Run as administrator)
- Windows PowerShell 5.1 or PowerShell 7.2+. `CreateUsers` only works in Windows PowerShell 5.1 (`powershell.exe`).

## Usage

```powershell
git clone https://github.com/faridtagizada/windows-admin-toolkit.git
cd windows-admin-toolkit

# 1) Dry run first: shows the plan, changes nothing
.\WinAdminToolkit.ps1 -Action CreateUsers -CsvPath .\samples\users.csv -WhatIf

# 2) Real run: shows the plan and asks you to confirm
.\WinAdminToolkit.ps1 -Action CreateUsers -CsvPath .\samples\users.csv

# Firewall rules, the same way
.\WinAdminToolkit.ps1 -Action ConfigureFirewall -CsvPath .\samples\firewall-rules.csv -WhatIf
.\WinAdminToolkit.ps1 -Action ConfigureFirewall -CsvPath .\samples\firewall-rules.csv

# Remove every rule this script added
.\WinAdminToolkit.ps1 -Action RemoveFirewallRules

# Last 3 days of the System, Application and Security logs
.\WinAdminToolkit.ps1 -Action CollectLogs -Days 3
```

On Windows 10/11 the default execution policy blocks all scripts. `Set-ExecutionPolicy -Scope Process RemoteSigned` allows them for the current window only. If you downloaded the ZIP instead of cloning, read the script first and then run `Unblock-File .\WinAdminToolkit.ps1`.

## Output

Each run writes to its own folder, `C:\AdminToolkit\<date-time>_<Action>\`:

- `run.log`: everything the run did
- `credentials.csv` (`CreateUsers`): the temporary passwords. Hand them over securely, then delete the file.
- `firewall-backup_<date-time>.wfw` (`ConfigureFirewall`): the full policy backup. `netsh advfirewall import` restores it, but that replaces all local rules.
- `<COMPUTER>_logs_<date-time>.zip` and `.sha256` (`CollectLogs`): `.evtx` exports, CSV summaries (key Security events, errors and warnings from the other logs), system info, hotfixes, automatic services that aren't running, listening ports, `ipconfig /all`, firewall profiles, local users and local administrators. It contains sensitive data.

Exit codes: `0` success, `1` some items failed, `2` stopped (see the log), `3` you answered No and nothing was changed.

## CSV format

Comma or semicolon, detected automatically, saved as UTF-8 ("CSV UTF-8" in Excel). Lists are separated with `|`. Every row needs as many fields as the header, so leave empty fields empty: `ali.mammadov,Əli,,Users,`.

Users ([samples/users.csv](samples/users.csv)):

| Column | Notes |
|---|---|
| `UserName` | Required. 1–20 characters: Latin letters, digits, `.`, `_`, `-` |
| `FullName` | Can contain Azerbaijani letters |
| `Description` | Up to 48 characters |
| `Groups` | For example `Users\|Remote Desktop Users`. English name, localized name or SID. Every new account also goes into Users |
| `AccountExpires` | Last active day, `yyyy-MM-dd` or `dd.MM.yyyy`. Empty means never |

Firewall rules ([samples/firewall-rules.csv](samples/firewall-rules.csv)):

| Column | Notes |
|---|---|
| `Name` | Required. Unique ID: Latin letters, digits, `.`, `_`, `-` |
| `DisplayName` | Defaults to `Name` |
| `Direction` | Required. `Inbound` or `Outbound` |
| `Action` | Required. `Allow` or `Block` |
| `Protocol` | Required. `TCP`, `UDP`, `ICMPv4`, `ICMPv6` or `Any` |
| `LocalPort`, `RemotePort` | `443`, `80\|443` or `8000-8080` (TCP and UDP only) |
| `RemoteAddress` | IP, CIDR (`10.0.0.0/8`), range (`10.0.0.1-10.0.0.50`), mask (`192.168.1.0/255.255.255.0`) or a keyword such as `LocalSubnet`. Empty means anywhere |
| `Profile` | `Domain\|Private\|Public\|Any`. Empty means `Domain\|Private` for Allow and `Any` for Block |
| `Program` | Full path (for example `%ProgramFiles%\App\app.exe`) or `System` |
| `Description` | Free text |

## Testing

- PSScriptAnalyzer reports nothing, including the compatibility rules for Windows PowerShell 5.1 (Server 2016, Windows 10 1809) and PowerShell 7.
- 253 unit, 28 end-to-end and 7 interruption (Ctrl+C) tests pass on PowerShell 7.4 with the Windows cmdlets mocked. The CSV parser was also fuzzed against Python's `csv` module. These tests aren't in the repo yet.
- It hasn't been run on a real Windows machine yet. Local accounts, the firewall cmdlets, ACLs, `netsh` and `wevtutil` have only been exercised through mocks, so treat it as untested on Windows.

## Known issues

Found in the last review and not fixed yet:

- **Firewall rollback gap.** If Ctrl+C lands while a rule is being created or checked, that rule can stay behind, enabled, and the log doesn't mention it. Remove it with `Remove-NetFirewallRule -Name <name>`, or remove the whole group with `-Action RemoveFirewallRules`.
- **Ctrl+C inside `New-LocalUser`.** The account can be left disabled with an unknown password. The script warns about it but doesn't delete it.
- **Misleading advice after a race.** If someone else creates an account with the same name between the check and the creation, the log suggests deleting it. It isn't yours, so don't.
- **"Anywhere" is matched by spelling.** `0.0.0.0/1|128.0.0.0/1`, `0.0.0.1-255.255.255.255` or the `Internet` keyword don't trigger the `-AllowRiskyRules` check the way `Any` does.
- **Non-ASCII digits.** A port written as `٤٤٣` stops the script with a raw .NET error instead of a validation message (nothing is changed), and some IPv4 addresses written that way pass validation.
- **The Latin-only checks accept `İ` and `K` (the Kelvin sign)** in user names, rule names and `-RuleGroup`, because `-match` ignores case.
- **Bracketed IPv6** such as `[::1]` or `[::1]:3389` passes validation and is handed to Windows unchanged.

## Layout

```
windows-admin-toolkit/
├── WinAdminToolkit.ps1       # the script (UTF-8 with BOM, CRLF)
└── samples/
    ├── users.csv
    └── firewall-rules.csv
```

If you edit the script, save it as UTF-8 with BOM. Without the BOM, Windows PowerShell 5.1 garbles the Azerbaijani text.

## TODO

- fix the known issues above
- add the test suite to the repo
- sign the script (Authenticode)

## License

MIT
