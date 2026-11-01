#Requires -Version 5.1

<#
.SYNOPSIS
    Windows üçün təhlükəsiz inzibatçılıq skripti: yerli istifadəçi hesabları yaradır,
    firewall qaydaları qurur və hadisə jurnallarını (log-ları) toplayır.

.DESCRIPTION
    Rejimlər (-Action):
      CreateUsers          CSV faylından yerli istifadəçi hesabları yaradır.
      ConfigureFirewall    CSV faylından Windows Defender Firewall qaydaları əlavə edir.
      RemoveFirewallRules  Yalnız bu skriptin qrupundakı (-RuleGroup) qaydaları silir (geri qaytarma).
      CollectLogs          Hadisə jurnallarını və diaqnostika məlumatlarını ZIP arxivə yığır.

    Təhlükəsizlik prinsipləri:
      - Əvvəlcə BÜTÜN giriş məlumatı yoxlanılır: naməlum sütun, əksik və ya artıq sahə, xanada
        sətir keçidi və yanlış dəyər xəta sayılır. Bir xəta belə varsa, heç nə dəyişdirilmir.
      - -WhatIf ilə simulyasiya: nə ediləcəyini göstərir, heç nəyi dəyişmir.
      - Dəyişiklikdən əvvəl plan göstərilir və təsdiq soruşulur. Standart cavab "Xeyr"dir:
        yalnız Enter basmaq heç nə etmir. -Force sorğunu ötürür.
      - Mövcud hesablara və qaydalara toxunulmur - onlar ötürülür.
      - Parollar CSV-də saxlanılmır. Hər hesab üçün kriptoqrafik təsadüfi müvəqqəti parol
        yaradılır və ilk girişdə dəyişdirilməsi məcburi edilir. Parol heç bir PowerShell
        cmdlet-inə ötürülmür, ona görə "Module Logging" jurnalına düşmür.
      - Hesab deaktiv yaradılır və qruplara əlavə edildikdən sonra aktivləşdirilir. Hər hansı
        addım alınmasa (Ctrl+C daxil), yarımçıq hesab avtomatik silinir.
      - Administrators, Backup Operators, Hyper-V Administrators qruplarına əlavə etmək yalnız
        -AllowPrivilegedGroups ilə mümkündür.
      - Bu qaydalar yalnız -AllowRiskyRules ilə qəbul olunur: uzaqdan idarəetmə portlarını
        (22, 3389, 5985, 5986) və ya bütün portları bloklayan istənilən daxil olan Block qaydası
        (ünvan göstərilsə belə), svchost.exe / System / sshd.exe proqramını bloklayan qayda,
        bütün çıxan trafiki bloklayan qayda və hər yerdən bütün portlara icazə verən qayda.
      - Firewall dəyişikliyindən əvvəl siyasətin tam ehtiyat nüsxəsi (netsh advfirewall export)
        alınır. Qaydalardan biri əlavə edilə bilməsə, bu işə salınmada əlavə olunanlar geri silinir.
      - Nəticə qovluğu (-WorkDirectory) və onun üst qovluqları yoxlanılır: başqa istifadəçilər
        oraya yaza və ya onu dəyişə bilirsə, skript dayanır. Hər işə salınma üçün yaradılan yeni
        qovluq elə yaranma anından yalnız Administrators və SYSTEM üçün açıqdır və sonra yoxlanılır.
      - Skript və CSV faylını başqa istifadəçilər dəyişə bilirsə, xəbərdarlıq verilir.
      - Qruplar SID ilə tapılır, ona görə rus, türk və ya başqa dilli Windows-da da işləyir.

.PARAMETER Action
    CreateUsers | ConfigureFirewall | RemoveFirewallRules | CollectLogs

.PARAMETER CsvPath
    CreateUsers və ConfigureFirewall üçün CSV faylı. Ayırıcı vergül (,) və ya nöqtəli vergül (;)
    ola bilər - avtomatik tanınır. Kodlaşdırma: UTF-8 (Excel-də "CSV UTF-8").
    Siyahı tipli dəyərlər (qruplar, portlar, ünvanlar, profillər) | işarəsi ilə ayrılır.
    Yalnız aşağıdakı sütunlar qəbul olunur. Hər sətirdə başlıqdakı qədər sahə olmalıdır: boş
    sahələri də ayırıcı ilə göstərin (məs. ali.mammadov,Əli,,Users,). Excel-in saxladığı CSV bu
    tələbə uyğundur. Xanada sətir keçidi (Alt+Enter) olmamalıdır.

    İstifadəçi CSV sütunları:
      UserName        (məcburi) 1-20 simvol: latın hərfi, rəqəm, nöqtə, alt xətt, defis.
                      Defis və ya nöqtə ilə başlaya, nöqtə ilə bitə bilməz.
      FullName        Tam ad (Azərbaycan hərfləri ola bilər)
      Description     Ən çox 48 simvol
      Groups          Məs.: Users|Remote Desktop Users. İngiliscə ad, yerli (lokallaşdırılmış) ad
                      və ya SID qəbul olunur. Hər yeni hesab avtomatik Users qrupuna da düşür.
      AccountExpires  Son aktiv gün: yyyy-MM-dd və ya dd.MM.yyyy. Boş = müddətsiz.

    Firewall CSV sütunları:
      Name            (məcburi) Qaydanın unikal ID-si: latın hərfi, rəqəm, nöqtə, alt xətt, defis
      DisplayName     Görünən ad (boşdursa Name götürülür)
      Direction       (məcburi) Inbound | Outbound
      Action          (məcburi) Allow | Block
      Protocol        (məcburi) TCP | UDP | ICMPv4 | ICMPv6 | Any
      LocalPort       443, 80|443 və ya 8000-8080 (yalnız TCP/UDP)
      RemotePort      Eyni format (adətən Outbound üçün)
      RemoteAddress   IP, CIDR (10.0.0.0/8), aralıq (10.0.0.1-10.0.0.50), maska
                      (192.168.1.0/255.255.255.0) və ya açar söz: LocalSubnet, Internet, Intranet,
                      DNS, DHCP, WINS, DefaultGateway. Boş = hər yer
      Profile         Domain|Private|Public|Any. Boşdursa: Allow üçün Domain|Private (ictimai
                      şəbəkədə açılmasın deyə), Block üçün Any
      Program         Proqramın tam yolu (məs. %ProgramFiles%\App\app.exe) və ya System
      Description     Təsvir

.PARAMETER AllowPrivilegedGroups
    İstifadəçiləri Administrators, Backup Operators və Hyper-V Administrators qruplarına
    əlavə etməyə icazə verir.

.PARAMETER PasswordLength
    Müvəqqəti parolun uzunluğu (14-64, standart 16).

.PARAMETER AllowRiskyRules
    Uzaqdan idarəetməni (RDP 3389, WinRM 5985/5986, SSH 22) və ya bütün trafiki bağlaya bilən,
    həmçinin hər yerdən bütün portları açan qaydalara icazə verir. Skript sizin hansı ünvandan
    qoşulduğunuzu bilmir: öz ünvanınızın bloklanmadığına əmin olmadan bu açarı işlətməyin.

.PARAMETER RuleGroup
    Skriptin yaratdığı firewall qaydalarının qrupu. Geri qaytarma yalnız bu qrupdakı qaydaları
    silir. Standart: WinAdminToolkit

.PARAMETER LogName
    Toplanacaq jurnallar. Standart: System, Application, Security.

.PARAMETER Days
    Neçə günlük log toplanacaq (1-365, standart 7).

.PARAMETER MaxEvents
    Hər jurnal üçün CSV xülasəsində ən çox neçə hadisə olacaq (standart 5000).
    Tam məlumat həmişə .evtx faylındadır.

.PARAMETER WorkDirectory
    Nəticələrin yazılacağı əsas qovluq. Standart: C:\AdminToolkit
    Qovluq yoxdursa, skript onu qorunan şəkildə yaradır (üst qovluq mövcud olmalıdır).
    Mövcuddursa, ona yalnız Administrators, SYSTEM və sizin hesabınız yaza bilməlidir - əks halda
    skript dayanır. Skripti və CSV fayllarını da belə qorunan qovluqda saxlayın.

.PARAMETER Force
    Ümumi təsdiq sorğusunu ötürür (avtomatlaşdırma üçün). Əvvəlcə -WhatIf ilə yoxlayın.

.EXAMPLE
    .\WinAdminToolkit.ps1 -Action CreateUsers -CsvPath .\users.csv -WhatIf

    Simulyasiya: hansı hesabların yaradılacağını göstərir, heç nəyi dəyişmir.

.EXAMPLE
    .\WinAdminToolkit.ps1 -Action CreateUsers -CsvPath .\users.csv

    Planı göstərir, təsdiq istəyir və hesabları yaradır. Müvəqqəti parollar qorunan
    qovluqdakı credentials.csv faylına yazılır.

.EXAMPLE
    .\WinAdminToolkit.ps1 -Action ConfigureFirewall -CsvPath .\firewall-rules.csv -WhatIf

.EXAMPLE
    .\WinAdminToolkit.ps1 -Action RemoveFirewallRules

    Bu skriptin əlavə etdiyi bütün qaydaları (WinAdminToolkit qrupu) silir.

.EXAMPLE
    .\WinAdminToolkit.ps1 -Action CollectLogs -Days 3

    Son 3 günün System, Application, Security jurnallarını və diaqnostika məlumatlarını toplayır.

.NOTES
    Tələblər : Windows 10/11 və ya Windows Server 2016+, Administrator hüquqları,
               Windows PowerShell 5.1 və ya PowerShell 7.2+.
               CreateUsers yalnız Windows PowerShell 5.1 (powershell.exe) ilə işləyir.
    Çıxış kodu: 0 = uğurlu, 1 = bəzi elementlər alınmadı, 2 = əməliyyat dayandırıldı (log-a baxın),
                3 = istifadəçi təsdiq etmədi (heç nə dəyişdirilmədi).
    Faylı redaktə etsəniz, "UTF-8 with BOM" kodlaşdırmasında saxlayın (Windows PowerShell 5.1 üçün).
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('CreateUsers', 'ConfigureFirewall', 'RemoveFirewallRules', 'CollectLogs')]
    [string]$Action,

    [Parameter(Position = 1)]
    [string]$CsvPath,

    [switch]$AllowPrivilegedGroups,

    [ValidateRange(14, 64)]
    [int]$PasswordLength = 16,

    [switch]$AllowRiskyRules,

    [ValidateScript({
            if ($_ -match '^[A-Za-z0-9._-]{1,64}$') { return $true }
            throw 'RuleGroup yalnız latın hərfi, rəqəm, nöqtə, alt xətt və defisdən ibarət ola bilər (1-64 simvol).'
        })]
    [string]$RuleGroup = 'WinAdminToolkit',

    [ValidateScript({
            if ($_ -match '^[^*?\[\]]+$') { return $true }
            throw 'LogName-də * ? [ ] kimi şablon simvollarına icazə verilmir.'
        })]
    [string[]]$LogName = @('System', 'Application', 'Security'),

    [ValidateRange(1, 365)]
    [int]$Days = 7,

    [ValidateRange(100, 100000)]
    [int]$MaxEvents = 5000,

    [ValidateNotNullOrEmpty()]
    [string]$WorkDirectory = (Join-Path -Path $env:SystemDrive -ChildPath 'AdminToolkit'),

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================================
#  Sabitlər
# ============================================================================
$script:RunStamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$script:LogFile = $null
$script:Utf8Bom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $true
# Excel-in Azərbaycan hərflərini düzgün göstərməsi üçün CSV-lər BOM ilə yazılır
$script:CsvEncoding = if ($PSVersionTable.PSVersion.Major -ge 6) { 'utf8BOM' } else { 'UTF8' }
# Parol faylı Excel-də iki kliklə düzgün açılsın deyə sistemin siyahı ayırıcısı (AZ/RU/TR: ;)
$script:CredentialDelimiter = [System.Globalization.CultureInfo]::CurrentCulture.TextInfo.ListSeparator

# CSV-də icazə verilən sütunlar (hərf səhvi olan sütun səssizcə atılmasın deyə)
$script:UserColumns = @('UserName', 'FullName', 'Description', 'Groups', 'AccountExpires')
$script:FirewallColumns = @('Name', 'DisplayName', 'Direction', 'Action', 'Protocol', 'LocalPort',
    'RemotePort', 'RemoteAddress', 'Profile', 'Program', 'Description')

# Qrupların ingiliscə adı -> SID. Windows başqa dildə olanda qrup adları tərcümə olunur,
# SID isə həmişə eynidir. Ona görə qruplar SID ilə tapılır.
$script:WellKnownGroups = @{
    'Administrators'                  = 'S-1-5-32-544'
    'Users'                           = 'S-1-5-32-545'
    'Guests'                          = 'S-1-5-32-546'
    'Power Users'                     = 'S-1-5-32-547'
    'Backup Operators'                = 'S-1-5-32-551'
    'Remote Desktop Users'            = 'S-1-5-32-555'
    'Network Configuration Operators' = 'S-1-5-32-556'
    'Performance Monitor Users'       = 'S-1-5-32-558'
    'Performance Log Users'           = 'S-1-5-32-559'
    'Distributed COM Users'           = 'S-1-5-32-562'
    'Event Log Readers'               = 'S-1-5-32-573'
    'Hyper-V Administrators'          = 'S-1-5-32-578'
    'Remote Management Users'         = 'S-1-5-32-580'
}
$script:UsersGroupSid = 'S-1-5-32-545'
# Bu qruplar faktiki olaraq inzibatçı səlahiyyəti verir
$script:PrivilegedGroupSids = @('S-1-5-32-544', 'S-1-5-32-551', 'S-1-5-32-578')
$script:TrustedInstallerSid = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'

# Fayl sistemi hüquqları (bit maskaları)
$script:RightsWrite = 0x2 -bor 0x4                              # fayl/alt qovluq yaratmaq, yazmaq
$script:RightsDeleteChild = 0x40                                # içindəkiləri silmək, adını dəyişmək
$script:RightsDelete = 0x10000                                  # özünü silmək, adını dəyişmək
$script:RightsTakeOver = 0x40000 -bor 0x80000 -bor 0x10000000   # icazələri/sahibi dəyişmək, GENERIC_ALL
$script:RightsGenericWrite = 0x40000000
$script:ContainerRightsMask = $script:RightsWrite -bor $script:RightsDeleteChild -bor $script:RightsDelete -bor
    $script:RightsTakeOver -bor $script:RightsGenericWrite

# SSH, RDP, WinRM (HTTP), WinRM (HTTPS)
$script:ManagementPorts = @(22, 3389, 5985, 5986)
# RDP svchost.exe-də, WinRM System (HTTP.sys) prosesində, OpenSSH sshd.exe-də işləyir
$script:ManagementPrograms = @('svchost.exe', 'System', 'sshd.exe')
$script:AddressKeywords = @('Any', 'LocalSubnet', 'LocalSubnet4', 'LocalSubnet6', 'Internet', 'Intranet',
    'IntranetRemoteAccess', 'PlayToDevice', 'DNS', 'DHCP', 'WINS', 'DefaultGateway')
# Bütün ünvanları əhatə edən yazılışlar (risk yoxlamasında "hər yer" sayılır)
$script:MatchAllAddresses = @('0.0.0.0/0', '::/0', '0.0.0.0/0.0.0.0', '0.0.0.0-255.255.255.255')
# Security jurnalından xülasəyə düşən əsas hadisələr (tam jurnal .evtx faylındadır)
$script:SecurityEventIds = @(
    1102, # audit jurnalı təmizləndi
    4625, # uğursuz giriş
    4648, # açıq kimlik məlumatları ilə giriş
    4697, # xidmət quraşdırıldı
    4719, # audit siyasəti dəyişdirildi
    4720, # hesab yaradıldı
    4722, # hesab aktivləşdirildi
    4723, # parol dəyişdirmə cəhdi
    4724, # parol sıfırlama cəhdi
    4725, # hesab deaktiv edildi
    4726, # hesab silindi
    4732, # yerli qrupa üzv əlavə edildi
    4733, # yerli qrupdan üzv çıxarıldı
    4738, # hesab dəyişdirildi
    4740, # hesab bloklandı
    4767  # hesabın bloku açıldı
)

# ============================================================================
#  Ümumi köməkçi funksiyalar
# ============================================================================

function Write-RunLog {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Rəngli konsol çıxışı qəsdən istifadə olunur.')]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet('INFO', 'OK', 'WARN', 'ERROR')]
        [string]$Level,

        [Parameter(Mandatory = $true, Position = 1)]
        [AllowEmptyString()]
        [string]$Message
    )
    $colors = @{ INFO = 'Gray'; OK = 'Green'; WARN = 'Yellow'; ERROR = 'Red' }
    Write-Host ('[{0}] {1}' -f $Level, $Message) -ForegroundColor $colors[$Level]
    if ($script:LogFile) {
        $line = '{0} [{1}] {2}{3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message, [Environment]::NewLine
        [System.IO.File]::AppendAllText($script:LogFile, $line, $script:Utf8Bom)
    }
}

function Test-IsAdministrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList $identity
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-CurrentUserSid {
    return [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}

function Get-TrustedSidList {
    # Administrators, SYSTEM, TrustedInstaller və skripti işə salan hesab
    return @('S-1-5-32-544', 'S-1-5-18', $script:TrustedInstallerSid, (Get-CurrentUserSid))
}

function Invoke-NativeTool {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [string[]]$ArgumentList = @()
    )
    # Tam yol (mühit dəyişənindən yox, sistem API-dən) - PATH-də olan saxta fayl işə düşməsin.
    $exe = Join-Path -Path ([Environment]::SystemDirectory) -ChildPath $Name
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
        throw ('Sistem aləti tapılmadı: {0}' -f $exe)
    }
    # Native proqramın stderr çıxışı PowerShell xətasına çevrilməsin (yalnız bu funksiyanın daxilində).
    $ErrorActionPreference = 'Continue'
    $output = & $exe @ArgumentList 2>&1 | ForEach-Object { [string]$_ }
    return [pscustomobject]@{
        ExitCode = $LASTEXITCODE
        Output   = (@($output) -join [Environment]::NewLine).Trim()
    }
}

function Resolve-SidName {
    param(
        [AllowEmptyString()]
        [string]$Sid
    )
    if ([string]::IsNullOrEmpty($Sid)) { return '(naməlum)' }
    try {
        $identity = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $Sid
        return ('{0} ({1})' -f $identity.Translate([System.Security.Principal.NTAccount]).Value, $Sid)
    }
    catch {
        return $Sid
    }
}

function Get-PathSecurityInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [switch]$IncludeChildCount
    )
    $item = Get-Item -LiteralPath $Path -Force
    $acl = Get-Acl -LiteralPath $Path
    $aces = @(foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            [pscustomobject]@{
                Sid         = [string]$rule.IdentityReference.Value
                Rights      = [int]$rule.FileSystemRights
                Allow       = ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow)
                InheritOnly = (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0)
            }
        })
    $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
    $ownerSid = ''
    if ($owner) { $ownerSid = [string]$owner.Value }
    $isReparsePoint = (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
    $childCount = 0
    if ($IncludeChildCount -and $item.PSIsContainer -and -not $isReparsePoint) {
        $childCount = @(Get-ChildItem -LiteralPath $Path -Force).Count
    }
    return [pscustomobject]@{
        Path           = $Path
        IsDirectory    = [bool]$item.PSIsContainer
        IsReparsePoint = $isReparsePoint
        OwnerSid       = $ownerSid
        IsProtected    = [bool]$acl.AreAccessRulesProtected
        Aces           = $aces
        ChildCount     = $childCount
    }
}

function Get-UntrustedAccess {
    param(
        [Parameter(Mandatory = $true)]
        $Info,

        [Parameter(Mandatory = $true)]
        [string[]]$TrustedSids,

        [Parameter(Mandatory = $true)]
        [int]$RightsMask
    )
    # Etibarlı olmayan hesablara verilmiş təhlükəli hüquqlar (yalnız obyektin özünə aid icazə qeydləri)
    $found = [System.Collections.Generic.List[string]]::new()
    foreach ($ace in @($Info.Aces)) {
        if (-not $ace.Allow -or $ace.InheritOnly) { continue }
        # CREATOR OWNER və OWNER RIGHTS sahibə aiddir; sahib ayrıca yoxlanılır
        if ($TrustedSids -contains $ace.Sid -or $ace.Sid -in @('S-1-3-0', 'S-1-3-4')) { continue }
        if (([int]$ace.Rights -band $RightsMask) -ne 0) {
            $name = Resolve-SidName -Sid $ace.Sid
            if (-not $found.Contains($name)) { $found.Add($name) }
        }
    }
    return $found.ToArray()
}

function Get-DirectoryProblem {
    param(
        [Parameter(Mandatory = $true)]
        $Info,

        [Parameter(Mandatory = $true)]
        [string[]]$TrustedSids,

        [Parameter(Mandatory = $true)]
        [int]$RightsMask,

        [switch]$ExpectOwnAcl,

        [switch]$RequireEmpty
    )
    $problems = [System.Collections.Generic.List[string]]::new()
    if (-not $Info.IsDirectory) { $problems.Add('qovluq deyil') }
    if ($Info.IsReparsePoint) { $problems.Add('qovluq keçiddir (junction/symbolic link)') }
    if ($TrustedSids -notcontains $Info.OwnerSid) {
        $problems.Add(('sahibi etibarlı hesab deyil: {0}' -f (Resolve-SidName -Sid $Info.OwnerSid)))
    }
    foreach ($name in @(Get-UntrustedAccess -Info $Info -TrustedSids $TrustedSids -RightsMask $RightsMask)) {
        $problems.Add(('{0} bu qovluğu dəyişə bilər' -f $name))
    }
    if ($ExpectOwnAcl) {
        if (-not $Info.IsProtected) { $problems.Add('icazə varisliyi söndürülməyib') }
        foreach ($ace in @($Info.Aces)) {
            if ($ace.Sid -notin @('S-1-5-32-544', 'S-1-5-18')) {
                $problems.Add(('gözlənilməyən icazə qeydi: {0}' -f (Resolve-SidName -Sid $ace.Sid)))
            }
        }
    }
    if ($RequireEmpty -and $Info.ChildCount -gt 0) {
        $problems.Add(('qovluq boş deyil ({0} element)' -f $Info.ChildCount))
    }
    return $problems.ToArray()
}

function Assert-TrustedAncestor {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string[]]$TrustedSids
    )
    # Üst qovluqlardan birinin adını dəyişə bilən istifadəçi yolu öz qovluğuna yönləndirə bilər
    $current = Split-Path -Path $Path -Parent
    while ($current) {
        $parentOfCurrent = Split-Path -Path $current -Parent
        $mask = $script:RightsDeleteChild -bor $script:RightsDelete -bor $script:RightsTakeOver
        if (-not $parentOfCurrent -or $parentOfCurrent -eq $current) {
            # Diskin kökü silinə və ya adı dəyişdirilə bilməz: "Delete" hüququ burada təhlükə deyil
            $mask = $script:RightsDeleteChild -bor $script:RightsTakeOver
        }
        if (Test-Path -LiteralPath $current) {
            $info = Get-PathSecurityInfo -Path $current
            $problems = [System.Collections.Generic.List[string]]::new()
            if ($info.IsReparsePoint) { $problems.Add('keçiddir (junction/symbolic link)') }
            if ($TrustedSids -notcontains $info.OwnerSid) {
                $problems.Add(('sahibi etibarlı hesab deyil: {0}' -f (Resolve-SidName -Sid $info.OwnerSid)))
            }
            foreach ($name in @(Get-UntrustedAccess -Info $info -TrustedSids $TrustedSids -RightsMask $mask)) {
                $problems.Add(('{0} onun adını və ya icazələrini dəyişə bilər' -f $name))
            }
            if ($problems.Count -gt 0) {
                throw ('Üst qovluq təhlükəsiz deyil ({0}): {1}. -WorkDirectory üçün başqa yer seçin (məs. C:\AdminToolkit).' -f $current, ($problems -join '; '))
            }
        }
        if ($parentOfCurrent -eq $current) { break }
        $current = $parentOfCurrent
    }
}

function Assert-WorkDirectorySafe {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaseDirectory,

        [Parameter(Mandatory = $true)]
        [string[]]$TrustedSids
    )
    # Qaytarır: $true - qovluq mövcuddur və təhlükəsizdir; $false - yoxdur, yaradıla bilər
    Assert-TrustedAncestor -Path $BaseDirectory -TrustedSids $TrustedSids
    if (Test-Path -LiteralPath $BaseDirectory) {
        $problems = @(Get-DirectoryProblem -Info (Get-PathSecurityInfo -Path $BaseDirectory) -TrustedSids $TrustedSids -RightsMask $script:ContainerRightsMask)
        if ($problems.Count -gt 0) {
            throw ('WorkDirectory təhlükəsiz deyil ({0}): {1}. Bu qovluğa yalnız Administrators və SYSTEM yaza bilməlidir, sahibi də Administrators olmalıdır - əks halda başqa istifadəçi parolları oğurlaya və ya skripti dəyişə bilər. Düzəltmək üçün: icacls "{0}" /inheritance:r /grant:r *S-1-5-32-544:(OI)(CI)F *S-1-5-18:(OI)(CI)F (içindəki faylları da yoxlayın) və ya -WorkDirectory ilə hələ mövcud olmayan qovluq göstərin - skript onu özü qorunan şəkildə yaradacaq.' -f $BaseDirectory, ($problems -join '; '))
        }
        return $true
    }
    $parent = Split-Path -Path $BaseDirectory -Parent
    if (-not $parent -or -not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw ('WorkDirectory-nin üst qovluğu mövcud deyil: {0}. Mövcud qovluğun içində yer seçin.' -f $parent)
    }
    return $false
}

function Initialize-ProtectedDirectory {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleTypes', '', Justification = 'FileSystemAclExtensions yalnız PowerShell 7 budağında çağırılır.')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    # Qovluq elə yaranma anından qorunan icazələrlə yaradılır (arada "açıq" an olmur):
    # varislik söndürülür, yalnız Administrators və SYSTEM tam çıxış alır.
    $security = New-Object -TypeName System.Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    $inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    foreach ($sid in @('S-1-5-32-544', 'S-1-5-18')) {
        $identity = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $sid
        $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
            $identity,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $security.AddAccessRule($rule)
    }
    if ($PSVersionTable.PSEdition -eq 'Core') {
        Add-Type -AssemblyName System.IO.FileSystem.AccessControl
        [System.IO.FileSystemAclExtensions]::Create((New-Object -TypeName System.IO.DirectoryInfo -ArgumentList $Path), $security)
    }
    else {
        $null = [System.IO.Directory]::CreateDirectory($Path, $security)
    }
}

function Initialize-ExclusiveFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [AllowEmptyString()]
        [string]$Content = ''
    )
    # CreateNew: fayl artıq varsa xəta verir - başqasının yaratdığı fayla heç vaxt yazılmır
    $bytes = [byte[]]($script:Utf8Bom.GetPreamble() + $script:Utf8Bom.GetBytes($Content))
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
    }
    finally {
        $stream.Dispose()
    }
}

function Initialize-RunDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaseDirectory,

        [Parameter(Mandatory = $true)]
        [string]$Action
    )
    $trusted = Get-TrustedSidList
    $baseExists = Assert-WorkDirectorySafe -BaseDirectory $BaseDirectory -TrustedSids $trusted
    if (-not $baseExists) {
        Initialize-ProtectedDirectory -Path $BaseDirectory
        $problems = @(Get-DirectoryProblem -Info (Get-PathSecurityInfo -Path $BaseDirectory -IncludeChildCount) -TrustedSids $trusted -RightsMask $script:ContainerRightsMask -ExpectOwnAcl -RequireEmpty)
        if ($problems.Count -gt 0) {
            throw ('Yaradılan qovluq yoxlamadan keçmədi ({0}): {1}' -f $BaseDirectory, ($problems -join '; '))
        }
    }

    $runDirectory = Join-Path -Path $BaseDirectory -ChildPath ('{0}_{1}' -f $script:RunStamp, $Action)
    if (Test-Path -LiteralPath $runDirectory) {
        throw ('Qovluq artıq mövcuddur, istifadə edilmir: {0}' -f $runDirectory)
    }
    Initialize-ProtectedDirectory -Path $runDirectory
    # Qovluq boşdur, sahibi bizik, icazələri dəqiq bizim verdiyimizdir - əks halda kimsə müdaxilə edib
    $problems = @(Get-DirectoryProblem -Info (Get-PathSecurityInfo -Path $runDirectory -IncludeChildCount) -TrustedSids $trusted -RightsMask $script:ContainerRightsMask -ExpectOwnAcl -RequireEmpty)
    if ($problems.Count -gt 0) {
        throw ('Nəticə qovluğu yoxlamadan keçmədi ({0}): {1}. Kimsə qovluğa müdaxilə etmiş ola bilər - ona baxın. Heç nə yazılmadı.' -f $runDirectory, ($problems -join '; '))
    }
    return $runDirectory
}

function Test-InputFileTrust {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )
    # Skripti və ya CSV-ni başqası dəyişə bilirsə, admin bunu bilməlidir (yalnız xəbərdarlıq)
    try {
        $trusted = Get-TrustedSidList
        $fileMask = $script:RightsWrite -bor $script:RightsDelete -bor $script:RightsTakeOver -bor $script:RightsGenericWrite
        $info = Get-PathSecurityInfo -Path $Path
        $risks = [System.Collections.Generic.List[string]]::new()
        if ($trusted -notcontains $info.OwnerSid) { $risks.Add(('sahibi {0}' -f (Resolve-SidName -Sid $info.OwnerSid))) }
        if ($info.IsReparsePoint) { $risks.Add('fayl keçiddir (symbolic link)') }
        foreach ($name in @(Get-UntrustedAccess -Info $info -TrustedSids $trusted -RightsMask $fileMask)) {
            if (-not $risks.Contains($name)) { $risks.Add($name) }
        }
        $parentInfo = Get-PathSecurityInfo -Path (Split-Path -Path $Path -Parent)
        foreach ($name in @(Get-UntrustedAccess -Info $parentInfo -TrustedSids $trusted -RightsMask ($script:RightsDeleteChild -bor $script:RightsTakeOver))) {
            if (-not $risks.Contains($name)) { $risks.Add($name) }
        }
        if ($risks.Count -gt 0) {
            Write-RunLog WARN ('{0} başqaları tərəfindən dəyişdirilə bilər ({1}): {2}. Faylı yalnız Administrators-un yaza bildiyi qovluqda saxlayın və məzmununu yoxlayın.' -f $Label, ($risks -join ', '), $Path)
        }
    }
    catch {
        Write-RunLog WARN ('{0} icazələri yoxlanıla bilmədi ({1}): {2}' -f $Label, $Path, $_.Exception.Message)
    }
}

function Request-Confirmation {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Question
    )
    # Standart cavab "Xeyr"dir: təsadüfi Enter (və ya yapışdırılan boş sətir) heç nə etmir
    $choices = New-Object -TypeName 'System.Collections.ObjectModel.Collection[System.Management.Automation.Host.ChoiceDescription]'
    $choices.Add((New-Object -TypeName System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Bəli', 'Dəyişiklikləri tətbiq et'))
    $choices.Add((New-Object -TypeName System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Xeyr', 'Heç nə etmədən dayan (standart)'))
    try {
        $answer = $Host.UI.PromptForChoice('Təsdiq', $Question, $choices, 1)
    }
    catch {
        throw 'Təsdiq sorğusu göstərilə bilmədi (qeyri-interaktiv rejim?). Avtomatlaşdırmada əvvəlcə -WhatIf ilə yoxlayın, sonra -Force istifadə edin.'
    }
    return ($answer -eq 0)
}

function Read-TextFileAutoEncoding {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        return [System.Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3)
    }
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        return [System.Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
    }
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        return [System.Text.Encoding]::BigEndianUnicode.GetString($bytes, 2, $bytes.Length - 2)
    }
    try {
        # BOM-suz fayl: əvvəlcə ciddi UTF-8 kimi oxumağa cəhd et
        $strictUtf8 = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false, $true
        return $strictUtf8.GetString($bytes)
    }
    catch {
        Write-RunLog WARN ('Fayl UTF-8 deyil, sistemin ANSI kodlaşdırması ilə oxunur: {0}. Hərflər düzgün görünməsə, faylı Excel-də "CSV UTF-8" kimi saxlayın.' -f $Path)
        $ansi = [System.Text.Encoding]::Default
        if ($PSVersionTable.PSEdition -eq 'Core') {
            try {
                $ansi = [System.Text.Encoding]::GetEncoding([System.Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage)
            }
            catch {
                $ansi = [System.Text.Encoding]::Default
            }
        }
        return $ansi.GetString($bytes)
    }
}

function ConvertFrom-CsvText {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text,

        [Parameter(Mandatory = $true)]
        [char]$Delimiter
    )
    # RFC 4180: dırnaqlı sahədə ayırıcı, "" (dırnaq) və sətir keçidi ola bilər. Hər qeyd üçün
    # başladığı fiziki sətrin nömrəsi saxlanılır (xəta mesajlarında dəqiq sətir göstərmək üçün).
    $records = [System.Collections.Generic.List[object]]::new()
    $fields = [System.Collections.Generic.List[string]]::new()
    $field = New-Object -TypeName System.Text.StringBuilder
    $inQuotes = $false
    $atFieldStart = $true
    $line = 1
    $recordLine = 1
    $length = $Text.Length
    $i = 0
    while ($i -lt $length) {
        $c = $Text[$i]
        if ($inQuotes) {
            if ($c -eq '"') {
                if ($i + 1 -lt $length -and $Text[$i + 1] -eq '"') {
                    $null = $field.Append('"')
                    $i += 2
                    continue
                }
                $inQuotes = $false
                $i++
                continue
            }
            if ($c -eq "`n") { $line++ }
            $null = $field.Append($c)
            $i++
            continue
        }
        if ($c -eq '"' -and $atFieldStart) {
            $null = $field.Clear()   # dırnaqdan əvvəlki boşluqlar atılır
            $inQuotes = $true
            $atFieldStart = $false
            $i++
            continue
        }
        if ($c -eq $Delimiter) {
            $fields.Add($field.ToString())
            $null = $field.Clear()
            $atFieldStart = $true
            $i++
            continue
        }
        if ($c -eq "`r" -or $c -eq "`n") {
            $fields.Add($field.ToString())
            $null = $field.Clear()
            $records.Add([pscustomobject]@{ Line = $recordLine; Fields = $fields.ToArray() })
            $fields.Clear()
            if ($c -eq "`r" -and $i + 1 -lt $length -and $Text[$i + 1] -eq "`n") { $i++ }
            $i++
            $line++
            $recordLine = $line
            $atFieldStart = $true
            continue
        }
        $null = $field.Append($c)
        if ($c -ne ' ' -and $c -ne "`t") { $atFieldStart = $false }
        $i++
    }
    if ($inQuotes) {
        throw ('CSV-də bağlanmamış dırnaq var (sətir {0}).' -f $recordLine)
    }
    if ($field.Length -gt 0 -or $fields.Count -gt 0) {
        $fields.Add($field.ToString())
        $records.Add([pscustomobject]@{ Line = $recordLine; Fields = $fields.ToArray() })
    }
    return $records.ToArray()
}

function Import-CsvTable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string[]]$KnownColumns,

        [Parameter(Mandatory = $true)]
        [string[]]$RequiredColumns
    )
    $text = Read-TextFileAutoEncoding -Path $Path
    $firstLine = @($text -split '\r?\n' | Where-Object { $_.Trim() -ne '' } | Select-Object -First 1)
    if ($firstLine.Count -eq 0) {
        throw ('CSV faylı boşdur: {0}' -f $Path)
    }
    # Ayırıcı başlıq sətrinə görə təyin olunur (Excel AZ/RU/TR dil ayarlarında ; yazır)
    $delimiter = ','
    if ($firstLine[0].Split(';').Count -gt $firstLine[0].Split(',').Count) { $delimiter = ';' }

    # Tamamilə boş sətirlər (Excel-in ";;;;" sətirləri daxil) atılır
    $records = @(ConvertFrom-CsvText -Text $text -Delimiter $delimiter | Where-Object {
            @($_.Fields | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -gt 0
        })
    if ($records.Count -lt 2) {
        throw ('CSV faylında başlıq sətri və ən azı bir məlumat sətri olmalıdır: {0}' -f $Path)
    }

    $problems = [System.Collections.Generic.List[string]]::new()
    $header = @($records[0].Fields | ForEach-Object { $_.Trim().TrimStart([char]0xFEFF) })
    $columnMap = @{}
    $seenColumns = @{}
    for ($c = 0; $c -lt $header.Count; $c++) {
        $name = $header[$c]
        if ($name -eq '') {
            # Excel-in boş başlıqlı sütunları: yalnız bütün xanaları boşdursa qəbul olunur
            $withData = @($records | Select-Object -Skip 1 | Where-Object { $c -lt $_.Fields.Count -and $_.Fields[$c].Trim() -ne '' })
            if ($withData.Count -gt 0) {
                $problems.Add(('{0}-ci sütunun başlığı boşdur, amma içində məlumat var' -f ($c + 1)))
            }
            continue
        }
        $canonical = $KnownColumns | Where-Object { $_ -eq $name } | Select-Object -First 1
        if (-not $canonical) {
            $problems.Add(('Naməlum sütun "{0}" (hərf səhvi?). İcazə verilən sütunlar: {1}' -f $name, ($KnownColumns -join ', ')))
            continue
        }
        if ($seenColumns.ContainsKey($canonical)) {
            $problems.Add(('"{0}" sütunu iki dəfə yazılıb' -f $canonical))
            continue
        }
        $seenColumns[$canonical] = $true
        $columnMap[$c] = $canonical
    }
    foreach ($required in $RequiredColumns) {
        if (-not $seenColumns.ContainsKey($required)) {
            $problems.Add(('CSV-də "{0}" sütunu yoxdur' -f $required))
        }
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($record in @($records | Select-Object -Skip 1)) {
        if ($record.Fields.Count -ne $header.Count) {
            $problems.Add(('Sətir {0}: {1} sahə var, başlıqda isə {2} sütun. Boş sahələri də ayırıcı ilə göstərin; mətndə ayırıcı varsa, xananı dırnağa alın.' -f $record.Line, $record.Fields.Count, $header.Count))
            continue
        }
        $row = [ordered]@{ SourceLine = $record.Line }
        foreach ($column in $KnownColumns) { $row[$column] = '' }
        $rowIsValid = $true
        foreach ($index in @($columnMap.Keys)) {
            $value = $record.Fields[$index].Trim()
            if ($value -match '[\x00-\x1F\x7F]') {
                $problems.Add(('Sətir {0}: "{1}" xanasında sətir keçidi və ya idarəetmə simvolu var (Excel-də Alt+Enter istifadə etməyin)' -f $record.Line, $columnMap[$index]))
                $rowIsValid = $false
            }
            $row[$columnMap[$index]] = $value
        }
        if ($rowIsValid) { $rows.Add([pscustomobject]$row) }
    }

    if ($problems.Count -gt 0) {
        foreach ($problem in $problems) { Write-RunLog ERROR $problem }
        throw ('CSV faylında {0} struktur xətası var ({1}). Heç bir dəyişiklik edilmədi.' -f $problems.Count, $Path)
    }
    return $rows.ToArray()
}

function Get-Field {
    param(
        [Parameter(Mandatory = $true)]
        $Row,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    foreach ($property in $Row.PSObject.Properties) {
        if ($property.Name.Trim() -eq $Name) {
            if ($null -eq $property.Value) { return '' }
            return ([string]$property.Value).Trim()
        }
    }
    return ''
}

function Split-ListValue {
    param(
        [AllowEmptyString()]
        [string]$Value
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    $Value -split '[|,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
}

function Format-ListValue {
    param(
        [AllowNull()]
        [object[]]$Value
    )
    $items = @($Value | Where-Object { $null -ne $_ -and [string]$_ -ne '' })
    if ($items.Count -eq 0) { return 'Any' }
    return ($items -join ',')
}

function ConvertTo-CsvSafeText {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Text,

        [int]$MaxLength = 2000
    )
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $clean = ($Text -replace '\s+', ' ').Trim()
    if ($clean.Length -gt $MaxLength) { $clean = $clean.Substring(0, $MaxLength) + '...' }
    # Excel düstur inyeksiyasının qarşısı: =, +, -, @ ilə başlayan xana mətn kimi qalsın
    if ($clean -match '^[=+\-@]') { $clean = "'" + $clean }
    return $clean
}

function ConvertTo-CsvLine {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]$Values,

        [Parameter(Mandatory = $true)]
        [string]$Delimiter
    )
    # Bu sətrə parol da düşür: ona görə heç bir cmdlet (ForEach-Object və s.) istifadə olunmur
    $quoted = foreach ($value in $Values) { '"' + ([string]$value).Replace('"', '""') + '"' }
    return ($quoted -join $Delimiter)
}

function Save-Csv {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Data,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    # Qaytarır: fayl yazıldısa $true, yazılacaq məlumat yoxdursa $false
    $items = @($Data)
    if ($items.Count -eq 0) { return $false }
    # Excel düstur inyeksiyasının qarşısı: bütün xanalar (proses adları da) təmizlənir
    $safeItems = foreach ($item in $items) {
        $copy = [ordered]@{}
        foreach ($property in $item.PSObject.Properties) {
            if ($null -eq $property.Value) { $copy[$property.Name] = '' }
            else { $copy[$property.Name] = ConvertTo-CsvSafeText -Text ([string]$property.Value) -MaxLength 32000 }
        }
        [pscustomobject]$copy
    }
    # -UseCulture: Excel-də iki kliklə düzgün sütunlara bölünsün (AZ/RU/TR ayarlarında ; olur)
    $safeItems | Export-Csv -LiteralPath $Path -NoTypeInformation -UseCulture -Encoding $script:CsvEncoding -Confirm:$false
    return $true
}

function Write-Utf8File {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Content
    )
    [System.IO.File]::WriteAllText($Path, $Content, $script:Utf8Bom)
}

# ============================================================================
#  1) İstifadəçi hesabları
# ============================================================================

function Test-LocalUserName {
    param(
        [AllowEmptyString()]
        [string]$Name
    )
    # Windows daha çox simvola icazə verir, amma skriptlər, yollar və əl ilə yazma üçün
    # yalnız təhlükəsiz simvollar qəbul olunur.
    if ($Name -notmatch '^[A-Za-z0-9._-]{1,20}$') {
        return 'ad 1-20 simvol olmalı və yalnız latın hərfi, rəqəm, nöqtə, alt xətt, defisdən ibarət olmalıdır'
    }
    if ($Name.StartsWith('-') -or $Name.StartsWith('.')) { return 'ad defis və ya nöqtə ilə başlaya bilməz' }
    if ($Name.EndsWith('.')) { return 'ad nöqtə ilə bitə bilməz' }
    if ($Name -eq $env:COMPUTERNAME) { return 'ad kompüterin adı ilə eyni ola bilməz' }
    return $null
}

function ConvertTo-ExpiryDate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )
    # Tarix formatı dil ayarlarından asılı olmasın deyə yalnız dəqiq formatlar qəbul olunur
    $formats = [string[]]@('yyyy-MM-dd', 'dd.MM.yyyy')
    $parsed = [datetime]::MinValue
    $ok = [datetime]::TryParseExact($Text, $formats, [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::None, [ref]$parsed)
    if (-not $ok) { return $null }
    return $parsed.Date
}

function Resolve-LocalGroup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Groups
    )
    # Dəqiq müqayisə (-eq) istifadə olunur: Get-LocalGroup -Name "*" kimi şablonlar bütün
    # qrupları, o cümlədən Administrators-u qaytarardı.
    $sid = $null
    if ($Name -match '^S-1-5-[0-9-]+$') { $sid = $Name }
    elseif ($script:WellKnownGroups.ContainsKey($Name)) { $sid = $script:WellKnownGroups[$Name] }

    if ($sid) {
        return ($Groups | Where-Object { $_.SID.Value -eq $sid } | Select-Object -First 1)
    }
    return ($Groups | Where-Object { $_.Name -eq $Name } | Select-Object -First 1)
}

function Get-SecureRandomInt {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.RandomNumberGenerator]$Rng,

        [Parameter(Mandatory = $true)]
        [int]$MaxExclusive
    )
    # Rədd etmə üsulu (rejection sampling): modul əyriliyi olmadan bərabər paylanma
    $buffer = New-Object -TypeName byte[] -ArgumentList 4
    $range = [long]4294967296
    $limit = $range - ($range % $MaxExclusive)
    do {
        $Rng.GetBytes($buffer)
        $value = [long][System.BitConverter]::ToUInt32($buffer, 0)
    } while ($value -ge $limit)
    return [int]($value % $MaxExclusive)
}

function Get-RandomPassword {
    param(
        [ValidateRange(14, 128)]
        [int]$Length = 16,

        [string[]]$Forbidden = @()
    )
    # Qarışdırıla bilən simvollar (0/O, 1/l/I) və CSV/Excel üçün problemli simvollar
    # (= + - @ , ; dırnaq) çıxarılıb. Parol heç bir cmdlet-dən keçmir (jurnala düşməsin).
    $upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $lower = 'abcdefghijkmnopqrstuvwxyz'
    $digits = '23456789'
    $symbols = '!#%*?_'
    $all = $upper + $lower + $digits + $symbols

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        for ($attempt = 0; $attempt -lt 100; $attempt++) {
            $chars = New-Object -TypeName 'System.Collections.Generic.List[char]'
            # Hər simvol növündən ən azı biri (mürəkkəblik siyasəti üçün)
            foreach ($set in @($upper, $lower, $digits, $symbols)) {
                $chars.Add($set[(Get-SecureRandomInt -Rng $rng -MaxExclusive $set.Length)])
            }
            while ($chars.Count -lt $Length) {
                $chars.Add($all[(Get-SecureRandomInt -Rng $rng -MaxExclusive $all.Length)])
            }
            # Fisher-Yates qarışdırması
            for ($i = $chars.Count - 1; $i -gt 0; $i--) {
                $j = Get-SecureRandomInt -Rng $rng -MaxExclusive ($i + 1)
                $tmp = $chars[$i]
                $chars[$i] = $chars[$j]
                $chars[$j] = $tmp
            }
            $candidate = -join $chars

            # Windows mürəkkəblik siyasəti parolda istifadəçi adının və ya tam addakı
            # 3+ hərfli hissələrin olmasına icazə vermir.
            $rejected = $false
            foreach ($word in $Forbidden) {
                if ($word.Length -ge 3 -and $candidate.IndexOf($word, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    $rejected = $true
                    break
                }
            }
            if (-not $rejected) { return $candidate }
        }
    }
    finally {
        $rng.Dispose()
    }
    throw 'Tələblərə uyğun parol yaradıla bilmədi.'
}

function ConvertTo-SecureStringFromPlain {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )
    $secure = New-Object -TypeName System.Security.SecureString
    foreach ($character in $Text.ToCharArray()) { $secure.AppendChar($character) }
    $secure.MakeReadOnly()
    return $secure
}

function Enable-PasswordChangeAtLogon {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserName
    )
    # "İstifadəçi növbəti girişdə parolu dəyişməlidir" bayrağı (New-LocalUser-da belə parametr yoxdur)
    $adsiPath = 'WinNT://{0}/{1},user' -f $env:COMPUTERNAME, $UserName
    $adsiUser = [ADSI]$adsiPath
    $adsiUser.Put('PasswordExpired', 1)
    $adsiUser.SetInfo()

    # Nəzarət oxunuşu (yalnız xəbərdarlıq verir - hesab artıq düzgün yaradılıb)
    try {
        $check = [ADSI]$adsiPath
        if ([int]$check.InvokeGet('PasswordExpired') -ne 1) {
            Write-RunLog WARN ('"{0}": "növbəti girişdə parolu dəyiş" bayrağı təsdiqlənmədi - lusrmgr.msc-də yoxlayın.' -f $UserName)
        }
    }
    catch {
        Write-RunLog WARN ('"{0}": parol bayrağı yoxlanıla bilmədi: {1}' -f $UserName, $_.Exception.Message)
    }
}

function Assert-LocalAccountSupport {
    if ($PSVersionTable.PSEdition -eq 'Core') {
        throw 'İstifadəçi əməliyyatları yalnız Windows PowerShell 5.1-də dəstəklənir. Skripti powershell.exe ilə işə salın (pwsh.exe ilə yox).'
    }
    if (-not (Get-Command -Name 'New-LocalUser' -ErrorAction SilentlyContinue)) {
        throw 'Microsoft.PowerShell.LocalAccounts modulu tapılmadı (Windows 10 / Server 2016 və ya daha yeni lazımdır).'
    }
    $domainRole = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
    if ($domainRole -ge 4) {
        throw 'Bu kompüter domen kontrolleridir - burada yerli hesab yoxdur. Domen istifadəçiləri üçün ActiveDirectory modulundan (New-ADUser) istifadə edin.'
    }
}

function Write-CredentialRow {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'TemporaryPassword', Justification = 'Müvəqqəti parol yalnız Administrators-un oxuya bildiyi fayla yazılır.')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        $Item,

        [Parameter(Mandatory = $true)]
        [string]$TemporaryPassword,

        [Parameter(Mandatory = $true)]
        [string]$Status
    )
    # Parol heç bir cmdlet-ə ötürülmür: Export-Csv kimi cmdlet-lərin parametrləri "Module Logging"
    # aktiv olanda PowerShell jurnalına (hadisə 4103) olduğu kimi yazılır. Sətir .NET ilə yazılır.
    $lastDay = '-'
    if ($Item.Expires) { $lastDay = $Item.Expires.AddDays(-1).ToString('yyyy-MM-dd') }
    $values = @(
        (ConvertTo-CsvSafeText -Text $Item.UserName),
        (ConvertTo-CsvSafeText -Text $Item.FullName),
        $TemporaryPassword,
        (ConvertTo-CsvSafeText -Text $Item.GroupNames),
        $lastDay,
        $Status,
        [datetime]::Now.ToString('yyyy-MM-dd HH:mm:ss')
    )
    $line = (ConvertTo-CsvLine -Values $values -Delimiter $script:CredentialDelimiter) + [Environment]::NewLine
    [System.IO.File]::AppendAllText($Path, $line, $script:Utf8Bom)
}

function Invoke-UserProvisioning {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [int]$PasswordLength = 16,

        [switch]$AllowPrivilegedGroups,

        [switch]$Force,

        [string]$RunDirectory
    )

    Assert-LocalAccountSupport

    $rows = @(Import-CsvTable -Path $Path -KnownColumns $script:UserColumns -RequiredColumns @('UserName'))
    Write-RunLog INFO ('CSV oxundu: {0} sətir.' -f $rows.Count)

    $existingUsers = @(Get-LocalUser)
    $existingGroups = @(Get-LocalGroup)
    $usersGroup = Resolve-LocalGroup -Name $script:UsersGroupSid -Groups $existingGroups
    if (-not $usersGroup) { throw 'Users qrupu (S-1-5-32-545) tapılmadı.' }

    # ---- Mərhələ 1: bütün sətirləri yoxla (heç nə dəyişdirilmir) ----
    $validationErrors = [System.Collections.Generic.List[string]]::new()
    $plan = [System.Collections.Generic.List[object]]::new()
    $seen = @{}

    foreach ($row in $rows) {
        $line = $row.SourceLine
        $userName = Get-Field -Row $row -Name 'UserName'
        $fullName = Get-Field -Row $row -Name 'FullName'
        $description = Get-Field -Row $row -Name 'Description'
        $groupsText = Get-Field -Row $row -Name 'Groups'
        $expiresText = Get-Field -Row $row -Name 'AccountExpires'
        $prefix = 'Sətir {0} ({1}): ' -f $line, $userName
        $errorsBefore = $validationErrors.Count

        $nameProblem = Test-LocalUserName -Name $userName
        if ($nameProblem) {
            $validationErrors.Add($prefix + $nameProblem)
        }
        elseif ($seen.ContainsKey($userName)) {
            $validationErrors.Add($prefix + ('CSV-də təkrarlanır (sətir {0})' -f $seen[$userName]))
        }
        else {
            $seen[$userName] = $line
        }

        if (@($existingGroups | Where-Object { $_.Name -eq $userName }).Count -gt 0) {
            $validationErrors.Add($prefix + 'bu adda yerli QRUP var; istifadəçi adı qrup adı ilə eyni ola bilməz')
        }
        if ($fullName.Length -gt 256) {
            $validationErrors.Add($prefix + 'FullName 256 simvoldan uzun ola bilməz')
        }
        if ($description.Length -gt 48) {
            $validationErrors.Add($prefix + ('Description ən çox 48 simvol ola bilər (indi {0})' -f $description.Length))
        }

        $expires = $null
        if ($expiresText) {
            $lastDay = ConvertTo-ExpiryDate -Text $expiresText
            if ($null -eq $lastDay) {
                $validationErrors.Add($prefix + ('AccountExpires "{0}" tanınmadı; format: yyyy-MM-dd və ya dd.MM.yyyy' -f $expiresText))
            }
            elseif ($lastDay -lt (Get-Date).Date) {
                $validationErrors.Add($prefix + ('AccountExpires keçmiş tarixdir: {0}' -f $lastDay.ToString('yyyy-MM-dd')))
            }
            else {
                # Göstərilən gün daxil olmaqla aktivdir: hesab növbəti günün 00:00-da bitir
                $expires = $lastDay.AddDays(1)
            }
        }

        $groups = [System.Collections.Generic.List[object]]::new()
        $groups.Add($usersGroup)
        foreach ($groupName in @(Split-ListValue -Value $groupsText)) {
            $group = Resolve-LocalGroup -Name $groupName -Groups $existingGroups
            if (-not $group) {
                $validationErrors.Add($prefix + ('"{0}" qrupu tapılmadı' -f $groupName))
                continue
            }
            if (($script:PrivilegedGroupSids -contains $group.SID.Value) -and -not $AllowPrivilegedGroups) {
                $validationErrors.Add($prefix + ('"{0}" imtiyazlı qrupdur; əlavə etmək üçün -AllowPrivilegedGroups göstərin' -f $group.Name))
                continue
            }
            if (@($groups | Where-Object { $_.SID.Value -eq $group.SID.Value }).Count -eq 0) {
                $groups.Add($group)
            }
        }

        if ($validationErrors.Count -gt $errorsBefore) { continue }

        $plan.Add([pscustomobject]@{
                Line        = $line
                UserName    = $userName
                FullName    = $fullName
                Description = $description
                Groups      = $groups.ToArray()
                GroupNames  = (@($groups | ForEach-Object { $_.Name }) -join ', ')
                Expires     = $expires
                Exists      = (@($existingUsers | Where-Object { $_.Name -eq $userName }).Count -gt 0)
            })
    }

    if ($validationErrors.Count -gt 0) {
        foreach ($message in $validationErrors) { Write-RunLog ERROR $message }
        throw ('CSV-də {0} xəta tapıldı. Heç bir dəyişiklik edilmədi - xətaları düzəldib yenidən işə salın.' -f $validationErrors.Count)
    }

    $table = $plan | Format-Table -AutoSize -Property @(
        @{ Label = 'Sətir'; Expression = { $_.Line } },
        @{ Label = 'İstifadəçi'; Expression = { $_.UserName } },
        @{ Label = 'Tam ad'; Expression = { $_.FullName } },
        @{ Label = 'Qruplar'; Expression = { $_.GroupNames } },
        @{ Label = 'Son aktiv gün'; Expression = { if ($_.Expires) { $_.Expires.AddDays(-1).ToString('yyyy-MM-dd') } else { '-' } } },
        @{ Label = 'Plan'; Expression = { if ($_.Exists) { 'ÖTÜRÜLÜR (artıq var)' } else { 'YARADILACAQ' } } }
    ) | Out-String -Width 250
    Write-RunLog INFO ('Plan:' + [Environment]::NewLine + $table.TrimEnd())

    $toCreate = @($plan | Where-Object { -not $_.Exists })
    $skipped = $plan.Count - $toCreate.Count
    if ($skipped -gt 0) {
        Write-RunLog WARN ('{0} hesab artıq mövcuddur - onlara toxunulmayacaq.' -f $skipped)
    }
    if ($toCreate.Count -eq 0) {
        Write-RunLog OK 'Yaradılacaq yeni hesab yoxdur.'
        return [pscustomobject]@{ Created = 0; Skipped = $skipped; Failed = 0; Cancelled = $false }
    }

    if (-not $WhatIfPreference -and -not $Force) {
        $question = '{0} yeni yerli istifadəçi hesabı yaradılacaq. Davam edilsin?' -f $toCreate.Count
        if (-not (Request-Confirmation -Question $question)) {
            Write-RunLog WARN 'Ləğv edildi. Heç bir dəyişiklik edilmədi.'
            return [pscustomobject]@{ Created = 0; Skipped = $skipped; Failed = 0; Cancelled = $true }
        }
    }

    # ---- Mərhələ 2: hesabları yarat ----
    $credentialFile = $null
    $credentialRows = 0
    if (-not $WhatIfPreference) {
        # Parol faylı yalnız yeni yaradıla bilər (CreateNew) - başqasının qoyduğu fayla yazılmır
        $credentialFile = Join-Path -Path $RunDirectory -ChildPath 'credentials.csv'
        $header = ConvertTo-CsvLine -Values @('UserName', 'FullName', 'TemporaryPassword', 'Groups', 'LastActiveDay', 'Status', 'CreatedAt') -Delimiter $script:CredentialDelimiter
        Initialize-ExclusiveFile -Path $credentialFile -Content ($header + [Environment]::NewLine)
    }
    $created = 0
    $failed = 0

    foreach ($item in $toCreate) {
        if (-not $PSCmdlet.ShouldProcess($item.UserName, 'Yerli istifadəçi hesabı yarat')) { continue }

        $newUser = $null
        $completed = $false
        $creationStarted = $false
        $plainPassword = $null
        try {
            $forbidden = @($item.UserName) + @($item.FullName -split '[\s,.\-_#]+' | Where-Object { $_.Length -ge 3 })
            $plainPassword = Get-RandomPassword -Length $PasswordLength -Forbidden $forbidden

            $newUserParams = @{
                Name        = $item.UserName
                Password    = (ConvertTo-SecureStringFromPlain -Text $plainPassword)
                Disabled    = $true   # qruplara əlavə edilənə qədər deaktiv qalır
                Confirm     = $false
                ErrorAction = 'Stop'
            }
            if ($item.FullName) { $newUserParams['FullName'] = $item.FullName }
            if ($item.Description) { $newUserParams['Description'] = $item.Description }
            if ($item.Expires) { $newUserParams['AccountExpires'] = $item.Expires }

            $creationStarted = $true
            $newUser = New-LocalUser @newUserParams

            foreach ($group in $item.Groups) {
                try {
                    Add-LocalGroupMember -SID $group.SID -Member $newUser -Confirm:$false -ErrorAction Stop
                }
                catch {
                    if ($_.FullyQualifiedErrorId -notlike 'MemberExists*') { throw }
                }
            }

            Enable-LocalUser -SID $newUser.SID -Confirm:$false -ErrorAction Stop
            # Bu bayraq aktivləşdirmədən sonra qoyulur ki, aktivləşdirmə ona toxuna bilməsin
            Enable-PasswordChangeAtLogon -UserName $item.UserName
            Write-CredentialRow -Path $credentialFile -Item $item -TemporaryPassword $plainPassword -Status 'OK'
            $credentialRows++
            $completed = $true
            $created++
            Write-RunLog OK ('Yaradıldı: {0} (qruplar: {1})' -f $item.UserName, $item.GroupNames)
        }
        catch {
            $failed++
            Write-RunLog ERROR ('"{0}" yaradıla bilmədi: {1}' -f $item.UserName, $_.Exception.Message)
        }
        finally {
            # Geri qaytarma finally-dədir: Ctrl+C-də catch işləmir, finally isə işləyir.
            if ($newUser -and -not $completed) {
                $rolledBack = $false
                $rollbackError = ''
                # Əvvəlcə ADSI (.NET çağırışı) - dayandırılan konveyerdə cmdlet işləməyə bilər
                try {
                    $computer = [ADSI]('WinNT://{0},computer' -f $env:COMPUTERNAME)
                    $computer.Delete('user', $item.UserName)
                    $rolledBack = $true
                }
                catch {
                    $rollbackError = $_.Exception.Message
                }
                if (-not $rolledBack) {
                    try {
                        Remove-LocalUser -SID $newUser.SID -Confirm:$false -ErrorAction Stop
                        $rolledBack = $true
                    }
                    catch {
                        $rollbackError = $_.Exception.Message
                    }
                }
                if ($rolledBack) {
                    Write-RunLog WARN ('"{0}" yarımçıq qaldığı üçün geri qaytarıldı (silindi).' -f $item.UserName)
                }
                else {
                    # Hesab qalıbsa, admin onun parolunu bilməlidir
                    try {
                        Write-CredentialRow -Path $credentialFile -Item $item -TemporaryPassword $plainPassword -Status 'YARIMÇIQ - əl ilə yoxlayın'
                        $credentialRows++
                    }
                    catch {
                        Write-RunLog ERROR ('"{0}" üçün parol fayla yazıla bilmədi: {1}' -f $item.UserName, $_.Exception.Message)
                    }
                    Write-RunLog ERROR ('"{0}" geri qaytarıla bilmədi - hesabı əl ilə yoxlayın: {1}' -f $item.UserName, $rollbackError)
                }
            }
            elseif ($creationStarted -and -not $completed) {
                # New-LocalUser işləyərkən kəsilibsə (məs. Ctrl+C), hesab yaranmış, amma bizə qaytarılmamış ola
                # bilər. Başqasının hesabını silməmək üçün avtomatik silinmir - yalnız xəbərdarlıq edilir.
                if (@(Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $item.UserName }).Count -gt 0) {
                    Write-RunLog WARN ('"{0}" hesabı mövcuddur, amma yaradılma prosesi yarımçıq kəsilib: hesab deaktiv və parolu naməlum ola bilər. Yoxlayın, lazım deyilsə silin.' -f $item.UserName)
                }
            }
            $plainPassword = $null
        }
    }

    Write-RunLog INFO ('Nəticə: yaradıldı {0}, ötürüldü {1}, xəta {2}.' -f $created, $skipped, $failed)
    if ($credentialRows -gt 0) {
        Write-RunLog WARN ('Müvəqqəti parollar: {0}' -f $credentialFile)
        Write-RunLog WARN 'Bu faylı yalnız Administrators oxuya bilər. Parolları istifadəçilərə təhlükəsiz yolla çatdırın və sonra faylı silin. İlk girişdə parolun dəyişdirilməsi tələb olunacaq.'
    }
    return [pscustomobject]@{ Created = $created; Skipped = $skipped; Failed = $failed; Cancelled = $false }
}

# ============================================================================
#  2) Firewall qaydaları
# ============================================================================

function Assert-FirewallReady {
    $service = Get-Service -Name 'mpssvc' -ErrorAction SilentlyContinue
    if (-not $service -or [string]$service.Status -ne 'Running') {
        throw 'Windows Defender Firewall xidməti (mpssvc) işləmir. Əvvəlcə xidməti işə salın.'
    }
    foreach ($fwProfile in @(Get-NetFirewallProfile -PolicyStore ActiveStore)) {
        if ([string]$fwProfile.Enabled -eq 'False') {
            Write-RunLog WARN ('"{0}" profilində firewall SÖNDÜRÜLÜB - bu profildə qaydalar təsir etməyəcək.' -f $fwProfile.Name)
        }
        if ([string]$fwProfile.AllowLocalFirewallRules -eq 'False') {
            Write-RunLog WARN ('"{0}" profilində Qrup Siyasəti (GPO) yerli qaydaları qadağan edir - əlavə edilən qaydalar tətbiq olunmayacaq.' -f $fwProfile.Name)
        }
    }
}

function Test-PortSpec {
    param(
        [AllowEmptyString()]
        [string]$Value
    )
    if ($Value -match '^\d{1,5}$') {
        $port = [int]$Value
        return ($port -ge 1 -and $port -le 65535)
    }
    if ($Value -match '^(\d{1,5})-(\d{1,5})$') {
        $from = [int]$Matches[1]
        $to = [int]$Matches[2]
        return ($from -ge 1 -and $to -le 65535 -and $from -le $to)
    }
    return $false
}

function Test-PortInList {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port,

        [AllowEmptyCollection()]
        [string[]]$List = @()
    )
    foreach ($item in $List) {
        if ($item -match '^(\d+)-(\d+)$') {
            if ($Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { return $true }
        }
        elseif ($item -match '^\d+$' -and [int]$item -eq $Port) {
            return $true
        }
    }
    return $false
}

function Test-IpAddressText {
    param(
        [AllowEmptyString()]
        [string]$Text
    )
    # IPv4 ciddi yoxlanılır: [IPAddress]::TryParse "10.1" kimi natamam və ya "010" kimi
    # (səkkizlik say kimi oxunan) yazılışları da qəbul edir.
    $octet = '(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
    if ($Text -match ('^{0}(\.{0}){{3}}$' -f $octet)) { return $true }
    if ($Text.Contains(':') -and -not $Text.Contains('%')) {
        $ip = $null
        return [System.Net.IPAddress]::TryParse($Text, [ref]$ip)
    }
    return $false
}

function Compare-IpAddress {
    param(
        [Parameter(Mandatory = $true)]
        [string]$First,

        [Parameter(Mandatory = $true)]
        [string]$Second
    )
    # Eyni ailədən (IPv4/IPv6) iki ünvanı bayt-bayt müqayisə edir: -1, 0 və ya 1
    $a = ([System.Net.IPAddress]::Parse($First)).GetAddressBytes()
    $b = ([System.Net.IPAddress]::Parse($Second)).GetAddressBytes()
    for ($k = 0; $k -lt $a.Length; $k++) {
        if ($a[$k] -lt $b[$k]) { return -1 }
        if ($a[$k] -gt $b[$k]) { return 1 }
    }
    return 0
}

function Test-SubnetMask {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Mask
    )
    # Düzgün maska: əvvəlcə ardıcıl 1-lər, sonra yalnız 0-lar (məs. 255.255.255.0)
    $bits = -join (([System.Net.IPAddress]::Parse($Mask)).GetAddressBytes() | ForEach-Object { [Convert]::ToString($_, 2).PadLeft(8, '0') })
    return ($bits -match '^1*0*$')
}

function Resolve-RemoteAddressToken {
    param(
        [AllowEmptyString()]
        [string]$Token
    )
    # Qaytarır: normallaşdırılmış dəyər və ya yanlışdırsa $null
    $keyword = $script:AddressKeywords | Where-Object { $_ -eq $Token } | Select-Object -First 1
    if ($keyword) { return $keyword }

    if ($Token -match '^([^/]+)/(\d{1,3})$') {
        # CIDR: 10.0.0.0/8, 2001:db8::/32
        $address = $Matches[1]
        $prefixLength = [int]$Matches[2]
        $maxPrefix = 32
        if ($address.Contains(':')) { $maxPrefix = 128 }
        if ((Test-IpAddressText -Text $address) -and $prefixLength -le $maxPrefix) { return $Token }
        return $null
    }
    if ($Token -match '^([^/]+)/([0-9.]+)$') {
        # Maska ilə: 192.168.1.0/255.255.255.0
        $address = $Matches[1]
        $mask = $Matches[2]
        if ((Test-IpAddressText -Text $address) -and -not $address.Contains(':') -and
            (Test-IpAddressText -Text $mask) -and (Test-SubnetMask -Mask $mask)) { return $Token }
        return $null
    }
    if ($Token -match '^([^-]+)-([^-]+)$') {
        # Aralıq: 10.0.0.1-10.0.0.50 (başlanğıc sondan böyük ola bilməz)
        $first = $Matches[1]
        $last = $Matches[2]
        if ((Test-IpAddressText -Text $first) -and (Test-IpAddressText -Text $last) -and
            ($first.Contains(':') -eq $last.Contains(':')) -and (Compare-IpAddress -First $first -Second $last) -le 0) {
            return $Token
        }
        return $null
    }
    if (Test-IpAddressText -Text $Token) { return $Token }
    return $null
}

function ConvertTo-PortList {
    param(
        [AllowEmptyCollection()]
        [string[]]$Values = @(),

        [Parameter(Mandatory = $true)]
        [string]$Label,

        [Parameter(Mandatory = $true)]
        [string]$Prefix,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$Errors
    )
    $items = @($Values)
    if ($items.Count -eq 0) { return }
    if ($items.Count -eq 1 -and $items[0] -eq 'Any') { return }
    foreach ($item in $items) {
        if (-not (Test-PortSpec -Value $item)) {
            $Errors.Add($Prefix + ('{0} "{1}" yanlışdır (1-65535, məs. 443 və ya 8000-8080)' -f $Label, $item))
        }
    }
    $items
}

function Test-AnyAddress {
    param(
        [AllowEmptyCollection()]
        [string[]]$Addresses = @()
    )
    # Ünvan göstərilməyibsə və ya yazılış bütün ünvanları əhatə edirsə - "hər yer"
    $list = @($Addresses)
    if ($list.Count -eq 0) { return $true }
    foreach ($address in $list) {
        if ($script:MatchAllAddresses -contains $address) { return $true }
        if ($address -match '/0+$') { return $true }   # məs. 0.0.0.0/00 - prefiks 0 bütün ünvanlardır
    }
    return $false
}

function Get-FirewallRuleRisk {
    param(
        [Parameter(Mandatory = $true)]
        $Rule
    )
    # Qaytarır: qayda -AllowRiskyRules tələb edirsə səbəb, əks halda $null.
    # Skript adminin hansı ünvandan qoşulduğunu bilmir, ona görə ünvan göstərilsə belə
    # idarəetmə portlarını bloklayan qayda təhlükəli sayılır.
    $programName = ''
    if ($Rule.Program) {
        $programName = @([Environment]::ExpandEnvironmentVariables($Rule.Program) -split '[\\/]')[-1]
    }
    $anyRemote = Test-AnyAddress -Addresses $Rule.RemoteAddress
    $remoteText = 'göstərilən ünvanlardan'
    if ($anyRemote) { $remoteText = 'hər yerdən' }

    if ($Rule.Action -eq 'Block' -and $Rule.Direction -eq 'Inbound' -and $Rule.Protocol -in @('TCP', 'Any')) {
        if ($programName) {
            if ($script:ManagementPrograms -contains $programName) {
                return ('{0} proqramını bloklayır - RDP/WinRM/SSH bu proqramlarla işləyir' -f $programName)
            }
        }
        elseif (@($Rule.LocalPort).Count -eq 0) {
            return ('{0} gələn bütün TCP bağlantılarını bloklayır (RDP/WinRM/SSH daxil)' -f $remoteText)
        }
        else {
            foreach ($port in $script:ManagementPorts) {
                if (Test-PortInList -Port $port -List $Rule.LocalPort) {
                    return ('uzaqdan idarəetmə portunu ({0}) {1} gələn bağlantılar üçün bloklayır' -f $port, $remoteText)
                }
            }
        }
    }
    if ($Rule.Action -eq 'Block' -and $Rule.Direction -eq 'Outbound' -and -not $programName -and
        $Rule.Protocol -in @('TCP', 'UDP', 'Any') -and $anyRemote -and @($Rule.RemotePort).Count -eq 0) {
        return 'bütün çıxan trafiki bloklayır'
    }
    if ($Rule.Action -eq 'Allow' -and $Rule.Direction -eq 'Inbound' -and -not $programName -and
        $Rule.Protocol -in @('TCP', 'UDP', 'Any') -and @($Rule.LocalPort).Count -eq 0 -and $anyRemote) {
        return 'hər yerdən bütün portlara icazə verir'
    }
    return $null
}

function Get-FirewallRuleWarning {
    param(
        [Parameter(Mandatory = $true)]
        $Rule
    )
    # Bloklamayan, amma diqqət tələb edən hallar
    $warnings = [System.Collections.Generic.List[string]]::new()
    $anyRemote = Test-AnyAddress -Addresses $Rule.RemoteAddress
    if ($Rule.Action -eq 'Allow' -and $Rule.Direction -eq 'Inbound') {
        if ($anyRemote -and $Rule.Profile -match 'Any|Public') {
            $warnings.Add('ictimai (Public) şəbəkədə hər yerdən gələn bağlantıya icazə verir - bunun lazım olduğuna əmin olun.')
        }
        if (-not $anyRemote -and -not $Rule.Program -and $Rule.Protocol -in @('TCP', 'UDP', 'Any') -and @($Rule.LocalPort).Count -eq 0) {
            $warnings.Add('göstərilən ünvanlara bütün portları açır - yalnız etibarlı ünvanlar üçün istifadə edin.')
        }
    }
    return $warnings.ToArray()
}

function ConvertTo-FirewallRulePlan {
    param(
        [Parameter(Mandatory = $true)]
        $Row,

        [Parameter(Mandatory = $true)]
        [int]$Line,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$Errors
    )
    $directionMap = @{ 'in' = 'Inbound'; 'inbound' = 'Inbound'; 'out' = 'Outbound'; 'outbound' = 'Outbound' }
    $actionMap = @{ 'allow' = 'Allow'; 'block' = 'Block' }
    $protocolMap = @{ 'tcp' = 'TCP'; 'udp' = 'UDP'; 'icmpv4' = 'ICMPv4'; 'icmpv6' = 'ICMPv6'; 'any' = 'Any' }
    $profileMap = @{ 'domain' = 'Domain'; 'private' = 'Private'; 'public' = 'Public'; 'any' = 'Any' }

    $name = Get-Field -Row $Row -Name 'Name'
    $displayName = Get-Field -Row $Row -Name 'DisplayName'
    $direction = Get-Field -Row $Row -Name 'Direction'
    $ruleAction = Get-Field -Row $Row -Name 'Action'
    $protocol = Get-Field -Row $Row -Name 'Protocol'
    $program = (Get-Field -Row $Row -Name 'Program').Trim('"')
    $description = Get-Field -Row $Row -Name 'Description'
    $prefix = 'Sətir {0} ({1}): ' -f $Line, $name
    $errorsBefore = $Errors.Count

    if ($name -notmatch '^[A-Za-z0-9._-]{1,128}$') {
        $Errors.Add($prefix + 'Name 1-128 simvol olmalı və yalnız latın hərfi, rəqəm, nöqtə, alt xətt, defisdən ibarət olmalıdır')
    }
    if (-not $displayName) { $displayName = $name }
    if ($displayName.Length -gt 256) { $Errors.Add($prefix + 'DisplayName 256 simvoldan uzun ola bilməz') }

    if ($directionMap.ContainsKey($direction)) { $direction = $directionMap[$direction] }
    else { $Errors.Add($prefix + ('Direction "{0}" yanlışdır (Inbound və ya Outbound)' -f $direction)) }

    if ($actionMap.ContainsKey($ruleAction)) { $ruleAction = $actionMap[$ruleAction] }
    else { $Errors.Add($prefix + ('Action "{0}" yanlışdır (Allow və ya Block)' -f $ruleAction)) }

    if ($protocolMap.ContainsKey($protocol)) { $protocol = $protocolMap[$protocol] }
    else { $Errors.Add($prefix + ('Protocol "{0}" yanlışdır (TCP, UDP, ICMPv4, ICMPv6 və ya Any)' -f $protocol)) }

    $localPort = @(ConvertTo-PortList -Values @(Split-ListValue -Value (Get-Field -Row $Row -Name 'LocalPort')) -Label 'LocalPort' -Prefix $prefix -Errors $Errors)
    $remotePort = @(ConvertTo-PortList -Values @(Split-ListValue -Value (Get-Field -Row $Row -Name 'RemotePort')) -Label 'RemotePort' -Prefix $prefix -Errors $Errors)
    if (($localPort.Count -gt 0 -or $remotePort.Count -gt 0) -and $protocol -notin @('TCP', 'UDP')) {
        $Errors.Add($prefix + 'port yalnız TCP və ya UDP protokolu üçün göstərilə bilər')
    }

    $remoteAddress = [System.Collections.Generic.List[string]]::new()
    $addressTokens = @(Split-ListValue -Value (Get-Field -Row $Row -Name 'RemoteAddress'))
    if (-not ($addressTokens.Count -eq 1 -and $addressTokens[0] -eq 'Any')) {
        foreach ($token in $addressTokens) {
            if ($token -eq 'Any') {
                $Errors.Add($prefix + 'RemoteAddress-də "Any" başqa ünvanlarla birlikdə yazıla bilməz')
                continue
            }
            $normalizedAddress = Resolve-RemoteAddressToken -Token $token
            if ($null -eq $normalizedAddress) {
                $Errors.Add($prefix + ('RemoteAddress "{0}" tanınmadı (IP, CIDR, düzgün sıralı aralıq, düzgün maska və ya LocalSubnet kimi açar söz)' -f $token))
            }
            elseif (-not $remoteAddress.Contains($normalizedAddress)) {
                $remoteAddress.Add($normalizedAddress)
            }
        }
    }

    $profileValue = 'Any'
    $profiles = @(Split-ListValue -Value (Get-Field -Row $Row -Name 'Profile'))
    if ($profiles.Count -eq 0) {
        # İcazə qaydaları standart olaraq ictimai (Public) şəbəkədə açılmır
        if ($ruleAction -eq 'Allow') { $profileValue = 'Domain,Private' }
    }
    else {
        $normalized = [System.Collections.Generic.List[string]]::new()
        foreach ($fwProfile in $profiles) {
            if ($profileMap.ContainsKey($fwProfile)) {
                if (-not $normalized.Contains($profileMap[$fwProfile])) { $normalized.Add($profileMap[$fwProfile]) }
            }
            else {
                $Errors.Add($prefix + ('Profile "{0}" yanlışdır (Domain, Private, Public və ya Any)' -f $fwProfile))
            }
        }
        if (-not $normalized.Contains('Any') -and $normalized.Count -gt 0) { $profileValue = $normalized -join ',' }
    }

    if ($program) {
        if ($program -eq 'System') {
            # Nüvə rejimli xidmətlər üçün xüsusi dəyər (SMB, HTTP.sys/WinRM və s.)
            $program = 'System'
        }
        else {
            $expanded = [Environment]::ExpandEnvironmentVariables($program)
            if ($expanded -notmatch '^[A-Za-z]:\\') {
                $Errors.Add($prefix + 'Program tam yol olmalıdır (məs. C:\App\app.exe və ya %ProgramFiles%\App\app.exe) və ya System')
            }
            elseif (-not (Test-Path -LiteralPath $expanded -PathType Leaf)) {
                Write-RunLog WARN ($prefix + ('Program faylı hazırda mövcud deyil: {0}' -f $expanded))
            }
        }
    }

    if ($Errors.Count -gt $errorsBefore) { return $null }

    $rule = [pscustomobject]@{
        Line          = $Line
        Name          = $name
        DisplayName   = $displayName
        Direction     = $direction
        Action        = $ruleAction
        Protocol      = $protocol
        LocalPort     = $localPort
        RemotePort    = $remotePort
        RemoteAddress = $remoteAddress.ToArray()
        Profile       = $profileValue
        Program       = $program
        Description   = $description
        Risk          = $null
        Exists        = $false
    }
    $rule.Risk = Get-FirewallRuleRisk -Rule $rule
    return $rule
}

function Backup-FirewallPolicy {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Directory
    )
    $file = Join-Path -Path $Directory -ChildPath ('firewall-backup_{0}.wfw' -f $script:RunStamp)
    $result = Invoke-NativeTool -Name 'netsh.exe' -ArgumentList @('advfirewall', 'export', $file)
    if ($result.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw ('Firewall ehtiyat nüsxəsi alınmadı, dəyişiklik edilmir: {0}' -f $result.Output)
    }
    Write-RunLog OK ('Firewall siyasətinin tam ehtiyat nüsxəsi: {0}' -f $file)
    return $file
}

function Invoke-FirewallConfiguration {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$RuleGroup,

        [switch]$AllowRiskyRules,

        [switch]$Force,

        [string]$RunDirectory
    )

    Assert-FirewallReady

    $rows = @(Import-CsvTable -Path $Path -KnownColumns $script:FirewallColumns -RequiredColumns @('Name', 'Direction', 'Action', 'Protocol'))
    Write-RunLog INFO ('CSV oxundu: {0} sətir.' -f $rows.Count)

    # ---- Mərhələ 1: bütün qaydaları yoxla (heç nə dəyişdirilmir) ----
    $validationErrors = [System.Collections.Generic.List[string]]::new()
    $plan = [System.Collections.Generic.List[object]]::new()
    $seen = @{}

    foreach ($row in $rows) {
        $line = $row.SourceLine
        $rule = ConvertTo-FirewallRulePlan -Row $row -Line $line -Errors $validationErrors
        if ($null -eq $rule) { continue }
        $prefix = 'Sətir {0} ({1}): ' -f $line, $rule.Name

        if ($seen.ContainsKey($rule.Name)) {
            $validationErrors.Add($prefix + ('Name CSV-də təkrarlanır (sətir {0})' -f $seen[$rule.Name]))
            continue
        }
        $seen[$rule.Name] = $line

        if ($rule.Risk) {
            if (-not $AllowRiskyRules) {
                $validationErrors.Add($prefix + ('TƏHLÜKƏLİ qayda: {0}. Bunu bilərəkdən istəyirsinizsə və öz ünvanınızın təsirlənmədiyinə əminsinizsə, -AllowRiskyRules göstərin.' -f $rule.Risk))
                continue
            }
            Write-RunLog WARN ($prefix + ('TƏHLÜKƏLİ qayda (-AllowRiskyRules ilə icazə verildi): {0}' -f $rule.Risk))
        }
        foreach ($warning in @(Get-FirewallRuleWarning -Rule $rule)) {
            Write-RunLog WARN ($prefix + $warning)
        }

        $existing = @(Get-NetFirewallRule -Name $rule.Name -PolicyStore PersistentStore -ErrorAction SilentlyContinue)
        if ($existing.Count -gt 0) {
            $rule.Exists = $true
            if ([string]$existing[0].Group -ne $RuleGroup) {
                Write-RunLog WARN ($prefix + ('bu ID ilə qayda artıq var və başqa qrupa aiddir ("{0}") - ona toxunulmayacaq.' -f $existing[0].Group))
            }
        }
        $plan.Add($rule)
    }

    if ($validationErrors.Count -gt 0) {
        foreach ($message in $validationErrors) { Write-RunLog ERROR $message }
        throw ('CSV-də {0} xəta tapıldı. Heç bir dəyişiklik edilmədi - xətaları düzəldib yenidən işə salın.' -f $validationErrors.Count)
    }

    $table = $plan | Format-Table -AutoSize -Property @(
        @{ Label = 'Sətir'; Expression = { $_.Line } },
        @{ Label = 'Name'; Expression = { $_.Name } },
        @{ Label = 'İstiqamət'; Expression = { $_.Direction } },
        @{ Label = 'Əməl'; Expression = { $_.Action } },
        @{ Label = 'Protokol'; Expression = { $_.Protocol } },
        @{ Label = 'Lokal port'; Expression = { Format-ListValue -Value $_.LocalPort } },
        @{ Label = 'Uzaq port'; Expression = { Format-ListValue -Value $_.RemotePort } },
        @{ Label = 'Uzaq ünvan'; Expression = { Format-ListValue -Value $_.RemoteAddress } },
        @{ Label = 'Profil'; Expression = { $_.Profile } },
        @{ Label = 'Plan'; Expression = { if ($_.Exists) { 'ÖTÜRÜLÜR (artıq var)' } else { 'YARADILACAQ' } } }
    ) | Out-String -Width 250
    Write-RunLog INFO ('Plan (qrup: {0}):{1}{2}' -f $RuleGroup, [Environment]::NewLine, $table.TrimEnd())

    $toCreate = @($plan | Where-Object { -not $_.Exists })
    $skipped = $plan.Count - $toCreate.Count
    if ($skipped -gt 0) {
        Write-RunLog WARN ('{0} qayda artıq mövcuddur - onlara toxunulmayacaq (CSV-də dəyişiklik etmisinizsə, əvvəlcə köhnə qaydanı silin).' -f $skipped)
    }
    if ($toCreate.Count -eq 0) {
        Write-RunLog OK 'Əlavə ediləcək yeni qayda yoxdur.'
        return [pscustomobject]@{ Created = 0; Skipped = $skipped; Failed = 0; RolledBack = 0; Cancelled = $false }
    }

    if (-not $WhatIfPreference -and -not $Force) {
        $question = '{0} firewall qaydası əlavə ediləcək. Davam edilsin?' -f $toCreate.Count
        if (-not (Request-Confirmation -Question $question)) {
            Write-RunLog WARN 'Ləğv edildi. Heç bir dəyişiklik edilmədi.'
            return [pscustomobject]@{ Created = 0; Skipped = $skipped; Failed = 0; RolledBack = 0; Cancelled = $true }
        }
    }

    # ---- Mərhələ 2: ehtiyat nüsxə və qaydaların əlavə edilməsi ----
    $backupFile = $null
    if (-not $WhatIfPreference) {
        $backupFile = Backup-FirewallPolicy -Directory $RunDirectory
    }

    $createdNames = [System.Collections.Generic.List[string]]::new()
    $failed = 0
    $rolledBack = 0
    $finished = $false
    try {
        foreach ($rule in $toCreate) {
            $target = '{0} ({1}, {2}, {3})' -f $rule.Name, $rule.Direction, $rule.Action, $rule.Protocol
            if (-not $PSCmdlet.ShouldProcess($target, 'Firewall qaydası əlavə et')) { continue }
            try {
                $ruleParams = @{
                    Name        = $rule.Name
                    DisplayName = $rule.DisplayName
                    Direction   = $rule.Direction
                    Action      = $rule.Action
                    Protocol    = $rule.Protocol
                    Profile     = $rule.Profile
                    Group       = $RuleGroup
                    Enabled     = 'True'
                    PolicyStore = 'PersistentStore'
                    Confirm     = $false
                    ErrorAction = 'Stop'
                }
                if ($rule.Description) { $ruleParams['Description'] = $rule.Description }
                if (@($rule.LocalPort).Count -gt 0) { $ruleParams['LocalPort'] = [string[]]$rule.LocalPort }
                if (@($rule.RemotePort).Count -gt 0) { $ruleParams['RemotePort'] = [string[]]$rule.RemotePort }
                if (@($rule.RemoteAddress).Count -gt 0) { $ruleParams['RemoteAddress'] = [string[]]$rule.RemoteAddress }
                if ($rule.Program) { $ruleParams['Program'] = $rule.Program }

                $null = New-NetFirewallRule @ruleParams

                # Yoxlama: qayda həqiqətən yaradılıbmı?
                if (@(Get-NetFirewallRule -Name $rule.Name -PolicyStore PersistentStore -ErrorAction SilentlyContinue).Count -eq 0) {
                    throw 'qayda yaradıldıqdan sonra tapılmadı'
                }
                $createdNames.Add($rule.Name)
                Write-RunLog OK ('Əlavə edildi: {0}' -f $target)
            }
            catch {
                $failed++
                Write-RunLog ERROR ('"{0}" əlavə edilə bilmədi: {1}' -f $rule.Name, $_.Exception.Message)
                break
            }
        }
        $finished = ($failed -eq 0)
    }
    finally {
        # Hamısı və ya heç biri: xəta olsa və ya iş Ctrl+C ilə kəsilsə, yarımçıq qayda dəsti qalmasın.
        # (Ctrl+C-də catch işləmir, finally isə işləyir.)
        if (-not $finished) {
            if ($createdNames.Count -gt 0) {
                Write-RunLog WARN ('Qalan qaydalar əlavə edilmir; bu işə salınmada əlavə olunan {0} qayda geri silinir.' -f $createdNames.Count)
                foreach ($createdName in $createdNames) {
                    try {
                        Remove-NetFirewallRule -Name $createdName -PolicyStore PersistentStore -Confirm:$false -ErrorAction Stop
                        $rolledBack++
                        Write-RunLog WARN ('Geri silindi: {0}' -f $createdName)
                    }
                    catch {
                        Write-RunLog ERROR ('"{0}" geri silinə bilmədi - əl ilə silin: {1}' -f $createdName, $_.Exception.Message)
                    }
                }
            }
            else {
                Write-RunLog WARN 'Qalan qaydalar əlavə edilmir.'
            }
        }
    }

    $created = $createdNames.Count - $rolledBack
    Write-RunLog INFO ('Nəticə: əlavə edildi {0}, ötürüldü {1}, xəta {2}, geri silindi {3}.' -f $created, $skipped, $failed, $rolledBack)
    if ($backupFile) {
        Write-RunLog INFO ('Yalnız bu skriptin qaydalarını silmək üçün: .\WinAdminToolkit.ps1 -Action RemoveFirewallRules -RuleGroup {0}' -f $RuleGroup)
        Write-RunLog INFO ('Tam bərpa (DİQQƏT: bütün yerli qaydaları əvəz edir): netsh advfirewall import "{0}"' -f $backupFile)
    }
    return [pscustomobject]@{ Created = $created; Skipped = $skipped; Failed = $failed; RolledBack = $rolledBack; Cancelled = $false }
}

function Invoke-FirewallRollback {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RuleGroup,

        [switch]$Force,

        [string]$RunDirectory
    )

    Assert-FirewallReady

    # Əlavə dəqiq süzgəc: yalnız qrupu TAM OLARAQ $RuleGroup olan qaydalar
    $rules = @(Get-NetFirewallRule -Group $RuleGroup -PolicyStore PersistentStore -ErrorAction SilentlyContinue |
            Where-Object { [string]$_.Group -eq $RuleGroup })
    if ($rules.Count -eq 0) {
        Write-RunLog OK ('"{0}" qrupunda qayda tapılmadı. Silinəcək heç nə yoxdur.' -f $RuleGroup)
        return [pscustomobject]@{ Removed = 0; Failed = 0; Cancelled = $false }
    }

    $table = $rules | Format-Table -AutoSize -Property Name, DisplayName, Direction, Action, Enabled | Out-String -Width 250
    Write-RunLog INFO ('Silinəcək qaydalar (qrup: {0}):{1}{2}' -f $RuleGroup, [Environment]::NewLine, $table.TrimEnd())

    if (-not $WhatIfPreference -and -not $Force) {
        $question = '"{0}" qrupundakı {1} qayda silinəcək. Davam edilsin?' -f $RuleGroup, $rules.Count
        if (-not (Request-Confirmation -Question $question)) {
            Write-RunLog WARN 'Ləğv edildi. Heç bir dəyişiklik edilmədi.'
            return [pscustomobject]@{ Removed = 0; Failed = 0; Cancelled = $true }
        }
    }

    if (-not $WhatIfPreference) {
        $null = Backup-FirewallPolicy -Directory $RunDirectory
    }

    $removed = 0
    $failed = 0
    foreach ($rule in $rules) {
        if (-not $PSCmdlet.ShouldProcess($rule.Name, 'Firewall qaydasını sil')) { continue }
        try {
            Remove-NetFirewallRule -Name $rule.Name -PolicyStore PersistentStore -Confirm:$false -ErrorAction Stop
            $removed++
            Write-RunLog OK ('Silindi: {0}' -f $rule.Name)
        }
        catch {
            $failed++
            Write-RunLog ERROR ('"{0}" silinə bilmədi: {1}' -f $rule.Name, $_.Exception.Message)
        }
    }
    Write-RunLog INFO ('Nəticə: silindi {0}, xəta {1}.' -f $removed, $failed)
    return [pscustomobject]@{ Removed = $removed; Failed = $failed; Cancelled = $false }
}

# ============================================================================
#  3) Log-ların toplanması
# ============================================================================

function ConvertTo-EventRow {
    param(
        [Parameter(Mandatory = $true)]
        $Record,

        [Parameter(Mandatory = $true)]
        [string]$LogName
    )
    $level = switch ([int]$Record.Level) {
        1 { 'Critical' }
        2 { 'Error' }
        3 { 'Warning' }
        4 { 'Information' }
        5 { 'Verbose' }
        default { 'Info/Audit' }
    }
    if ($LogName -eq 'Security' -and $null -ne $Record.Keywords) {
        if (([long]$Record.Keywords -band 0x10000000000000) -ne 0) { $level = 'Audit Failure' }
        elseif (([long]$Record.Keywords -band 0x20000000000000) -ne 0) { $level = 'Audit Success' }
    }
    $message = ''
    try { $message = [string]$Record.Message } catch { $message = '(mesaj oxuna bilmədi)' }
    $time = ''
    if ($Record.TimeCreated) { $time = $Record.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') }

    return [pscustomobject]@{
        Time     = $time
        Log      = $LogName
        EventId  = $Record.Id
        Level    = $level
        Provider = (ConvertTo-CsvSafeText -Text ([string]$Record.ProviderName) -MaxLength 200)
        Message  = (ConvertTo-CsvSafeText -Text $message)
    }
}

function Invoke-Collector {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock
    )
    # Bir mənbə alınmasa da qalanları toplanmağa davam edir.
    # Blok sonda $false qaytarırsa, yazılacaq məlumat olmayıb (fayl yaradılmayıb).
    try {
        $outcome = @(& $ScriptBlock)
        if ($outcome.Count -gt 0 -and $outcome[-1] -is [bool] -and -not $outcome[-1]) {
            Write-RunLog INFO ('  = {0}: məlumat yoxdur, fayl yaradılmadı' -f $Name)
        }
        else {
            Write-RunLog OK ('  + {0}' -f $Name)
        }
        return $true
    }
    catch {
        Write-RunLog WARN ('  - {0} toplanmadı: {1}' -f $Name, $_.Exception.Message)
        return $false
    }
}

function Invoke-LogCollection {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleTypes', '', Justification = 'ZipFile tipi istifadədən dərhal əvvəl Add-Type ilə yüklənir.')]
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$LogName,

        [Parameter(Mandatory = $true)]
        [int]$Days,

        [Parameter(Mandatory = $true)]
        [int]$MaxEvents,

        [string]$RunDirectory
    )
    $startTime = (Get-Date).AddDays(-$Days)

    $validLogs = [System.Collections.Generic.List[string]]::new()
    foreach ($log in $LogName) {
        try {
            $info = Get-WinEvent -ListLog $log -ErrorAction Stop
            if ($validLogs.Contains($info.LogName)) {
                Write-RunLog INFO ('"{0}" iki dəfə göstərilib - bir dəfə toplanır.' -f $info.LogName)
                continue
            }
            $validLogs.Add($info.LogName)
            Write-RunLog INFO ('Jurnal tapıldı: {0} (maks. ölçü {1:N0} MB)' -f $info.LogName, ($info.MaximumSizeInBytes / 1MB))
        }
        catch {
            Write-RunLog WARN ('"{0}" jurnalı tapılmadı və ya oxuna bilmir - ötürülür.' -f $log)
        }
    }
    if ($validLogs.Count -eq 0) { throw 'Toplanacaq jurnal tapılmadı.' }

    $target = $RunDirectory
    if (-not $target) { $target = 'yeni qorunan qovluq' }
    if (-not $PSCmdlet.ShouldProcess($target, ('Son {0} günün log-larını topla: {1}' -f $Days, ($validLogs -join ', ')))) {
        return [pscustomobject]@{ Failed = 0; Cancelled = $false }
    }

    $dataDir = Join-Path -Path $RunDirectory -ChildPath 'data'
    $null = [System.IO.Directory]::CreateDirectory($dataDir)   # qorunan qovluğun icazələrini irsən alır
    $failures = 0
    $query = '*[System[TimeCreated[timediff(@SystemTime)<={0}]]]' -f ([long]$Days * 86400000)

    foreach ($log in $validLogs) {
        $safeName = $log -replace '[\\/:*?"<>| ]', '_'
        Write-RunLog INFO ('Toplanır: {0}' -f $log)

        # 1) Tam EVTX ixracı (Event Viewer-də açmaq üçün)
        $evtxFile = Join-Path -Path $dataDir -ChildPath ($safeName + '.evtx')
        $export = Invoke-NativeTool -Name 'wevtutil.exe' -ArgumentList @('epl', $log, $evtxFile, ('/q:' + $query))
        if ($export.ExitCode -eq 0) {
            Write-RunLog OK ('  + {0}.evtx' -f $safeName)
        }
        else {
            $failures++
            Write-RunLog WARN ('  - {0}.evtx alınmadı: {1}' -f $safeName, $export.Output)
        }

        # 2) Oxunaqlı CSV xülasəsi (Security üçün əsas hadisələr, digərləri üçün xəta/xəbərdarlıqlar)
        $summaryName = $safeName + '_summary.csv'
        try {
            $filter = @{ LogName = $log; StartTime = $startTime }
            if ($log -eq 'Security') { $filter['Id'] = $script:SecurityEventIds }
            else { $filter['Level'] = @(1, 2, 3) }

            $events = @()
            try {
                $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop)
            }
            catch {
                # Uyğun hadisə olmaması xəta deyil
                if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
            }
            $summaryRows = @(foreach ($record in $events) { ConvertTo-EventRow -Record $record -LogName $log })
            if (Save-Csv -Data $summaryRows -Path (Join-Path -Path $dataDir -ChildPath $summaryName)) {
                Write-RunLog OK ('  + {0} ({1} hadisə)' -f $summaryName, $summaryRows.Count)
            }
            else {
                Write-RunLog INFO ('  = {0}: bu dövrdə uyğun hadisə yoxdur, fayl yaradılmadı' -f $summaryName)
            }
            if ($events.Count -ge $MaxEvents) {
                Write-RunLog WARN ('    {0} hadisə limitinə çatıldı - ən yeniləri saxlanıldı (tam məlumat .evtx faylındadır).' -f $MaxEvents)
            }
        }
        catch {
            $failures++
            Write-RunLog WARN ('  - {0} alınmadı: {1}' -f $summaryName, $_.Exception.Message)
        }
    }

    Write-RunLog INFO 'Diaqnostika məlumatları toplanır...'
    $diagnostics = @(
        (Invoke-Collector -Name 'system-info.txt' -ScriptBlock {
                $os = Get-CimInstance -ClassName Win32_OperatingSystem
                $cs = Get-CimInstance -ClassName Win32_ComputerSystem
                $info = [ordered]@{
                    'Kompüter'            = $env:COMPUTERNAME
                    'Əməliyyat sistemi'   = $os.Caption
                    'Versiya / Build'     = ('{0} / {1}' -f $os.Version, $os.BuildNumber)
                    'Quraşdırılma tarixi' = $os.InstallDate
                    'Son yüklənmə'        = $os.LastBootUpTime
                    'İstehsalçı / Model'  = ('{0} / {1}' -f $cs.Manufacturer, $cs.Model)
                    'Domen / İşçi qrup'   = $cs.Domain
                    'RAM (GB)'            = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
                    'PowerShell'          = $PSVersionTable.PSVersion.ToString()
                    'Toplanma vaxtı'      = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                    'Toplayan'            = ('{0}\{1}' -f [Environment]::UserDomainName, [Environment]::UserName)
                    'Dövr'                = ('son {0} gün' -f $Days)
                }
                $text = ($info.GetEnumerator() | ForEach-Object { '{0,-22}: {1}' -f $_.Key, $_.Value }) -join [Environment]::NewLine
                Write-Utf8File -Path (Join-Path -Path $dataDir -ChildPath 'system-info.txt') -Content $text
            }),
        (Invoke-Collector -Name 'hotfixes.csv' -ScriptBlock {
                $items = @(Get-HotFix | Select-Object -Property HotFixID, Description, InstalledOn, InstalledBy)
                Save-Csv -Data $items -Path (Join-Path -Path $dataDir -ChildPath 'hotfixes.csv')
            }),
        (Invoke-Collector -Name 'services-not-running.csv' -ScriptBlock {
                $items = @(Get-CimInstance -ClassName Win32_Service -Filter "StartMode='Auto' AND State<>'Running'" |
                        Select-Object -Property Name, DisplayName, State, StartMode, StartName, PathName)
                Save-Csv -Data $items -Path (Join-Path -Path $dataDir -ChildPath 'services-not-running.csv')
            }),
        (Invoke-Collector -Name 'listening-ports.csv' -ScriptBlock {
                $processNames = @{}
                foreach ($process in @(Get-Process)) { $processNames[[int]$process.Id] = $process.ProcessName }
                $items = @(Get-NetTCPConnection -State Listen | Sort-Object -Property LocalPort | ForEach-Object {
                        [pscustomobject]@{
                            LocalAddress = $_.LocalAddress
                            LocalPort    = $_.LocalPort
                            ProcessId    = $_.OwningProcess
                            Process      = $processNames[[int]$_.OwningProcess]
                        }
                    })
                Save-Csv -Data $items -Path (Join-Path -Path $dataDir -ChildPath 'listening-ports.csv')
            }),
        (Invoke-Collector -Name 'ipconfig.txt' -ScriptBlock {
                $ipconfig = Invoke-NativeTool -Name 'ipconfig.exe' -ArgumentList @('/all')
                Write-Utf8File -Path (Join-Path -Path $dataDir -ChildPath 'ipconfig.txt') -Content $ipconfig.Output
            }),
        (Invoke-Collector -Name 'firewall-profiles.csv' -ScriptBlock {
                $items = @(Get-NetFirewallProfile -PolicyStore ActiveStore |
                        Select-Object -Property Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowLocalFirewallRules, LogAllowed, LogBlocked, LogFileName)
                Save-Csv -Data $items -Path (Join-Path -Path $dataDir -ChildPath 'firewall-profiles.csv')
            }),
        (Invoke-Collector -Name 'local-users.csv' -ScriptBlock {
                $items = @(Get-LocalUser |
                        Select-Object -Property Name, Enabled, Description, LastLogon, PasswordLastSet, PasswordExpires, PasswordRequired, AccountExpires, SID)
                Save-Csv -Data $items -Path (Join-Path -Path $dataDir -ChildPath 'local-users.csv')
            }),
        (Invoke-Collector -Name 'local-administrators.csv' -ScriptBlock {
                try {
                    $items = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop |
                            Select-Object -Property Name, ObjectClass, PrincipalSource, SID)
                }
                catch {
                    # Get-LocalGroupMember qrupda silinmiş (yetim) SID olduqda xəta verir - ADSI ilə alternativ
                    $adminGroupName = (Get-LocalGroup -SID 'S-1-5-32-544').Name
                    $adsiGroup = [ADSI]('WinNT://{0}/{1},group' -f $env:COMPUTERNAME, $adminGroupName)
                    $items = @($adsiGroup.Invoke('Members') | ForEach-Object {
                            $member = [ADSI]$_
                            [pscustomobject]@{
                                Name            = ([string]$member.Path -replace '^WinNT://', '')
                                ObjectClass     = [string]$member.SchemaClassName
                                PrincipalSource = 'ADSI'
                                SID             = ''
                            }
                        })
                }
                Save-Csv -Data $items -Path (Join-Path -Path $dataDir -ChildPath 'local-administrators.csv')
            })
    )
    $failures += @($diagnostics | Where-Object { -not $_ }).Count

    # Arxiv və bütövlük (integrity) üçün SHA256
    $zipFile = Join-Path -Path $RunDirectory -ChildPath ('{0}_logs_{1}.zip' -f $env:COMPUTERNAME, $script:RunStamp)
    if ($PSVersionTable.PSEdition -eq 'Core') {
        Add-Type -AssemblyName System.IO.Compression.ZipFile
    }
    else {
        Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    }
    [System.IO.Compression.ZipFile]::CreateFromDirectory($dataDir, $zipFile, [System.IO.Compression.CompressionLevel]::Optimal, $false)
    $hash = (Get-FileHash -LiteralPath $zipFile -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Utf8File -Path ($zipFile + '.sha256') -Content ('{0} *{1}' -f $hash, (Split-Path -Path $zipFile -Leaf))

    Write-RunLog OK ('Arxiv: {0}' -f $zipFile)
    Write-RunLog INFO ('SHA256: {0}' -f $hash)
    Write-RunLog WARN 'Arxivdə həssas məlumat var (istifadəçi adları, IP ünvanları, təhlükəsizlik hadisələri). Yalnız etibarlı yolla paylaşın.'
    if ($failures -gt 0) {
        Write-RunLog WARN ('{0} mənbə toplanmadı - yuxarıdakı xəbərdarlıqlara baxın.' -f $failures)
    }
    return [pscustomobject]@{ Failed = $failures; Cancelled = $false }
}

# ============================================================================
#  Əsas axın
# ============================================================================
$exitCode = 0
$result = $null
$runDirectory = $null

try {
    if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
        throw 'Bu skript yalnız Windows-da işləyir.'
    }
    if (-not (Test-IsAdministrator)) {
        throw 'Skripti "Run as administrator" (Administrator kimi işə sal) ilə açılmış PowerShell pəncərəsində işə salın.'
    }

    # Nisbi yolları PowerShell-in cari qovluğuna görə tam yola çevir (.NET başqa qovluğu görə bilər)
    $WorkDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($WorkDirectory)
    if ($WorkDirectory.Length -gt 3) { $WorkDirectory = $WorkDirectory.TrimEnd('\') }
    if ($WorkDirectory -notmatch '^[A-Za-z]:\\') {
        throw ('WorkDirectory yerli diskdə tam yol olmalıdır (məs. C:\AdminToolkit): {0}' -f $WorkDirectory)
    }
    if ($Action -in @('CreateUsers', 'ConfigureFirewall')) {
        if ([string]::IsNullOrWhiteSpace($CsvPath)) {
            throw ('-Action {0} üçün -CsvPath göstərilməlidir.' -f $Action)
        }
        if (-not (Test-Path -LiteralPath $CsvPath -PathType Leaf)) {
            throw ('CSV faylı tapılmadı: {0}' -f $CsvPath)
        }
        $CsvPath = (Resolve-Path -LiteralPath $CsvPath).ProviderPath
    }

    # Simulyasiyada diskə heç nə yazılmır
    if (-not $WhatIfPreference) {
        $runDirectory = Initialize-RunDirectory -BaseDirectory $WorkDirectory -Action $Action
        $logPath = Join-Path -Path $runDirectory -ChildPath 'run.log'
        Initialize-ExclusiveFile -Path $logPath
        $script:LogFile = $logPath
    }

    $header = 'WinAdminToolkit | Əməliyyat: {0} | Kompüter: {1} | İcra edən: {2}\{3} | PowerShell {4}' -f $Action, $env:COMPUTERNAME, [Environment]::UserDomainName, [Environment]::UserName, $PSVersionTable.PSVersion
    Write-RunLog INFO $header
    $boundText = ($PSBoundParameters.GetEnumerator() | ForEach-Object { '-{0} {1}' -f $_.Key, (@($_.Value) -join ',') }) -join ' '
    Write-RunLog INFO ('Parametrlər: {0}' -f $boundText)
    if ($WhatIfPreference) {
        Write-RunLog WARN 'SİMULYASİYA (-WhatIf): heç bir dəyişiklik edilməyəcək, diskə heç nə yazılmayacaq.'
        if (Assert-WorkDirectorySafe -BaseDirectory $WorkDirectory -TrustedSids (Get-TrustedSidList)) {
            Write-RunLog OK ('WorkDirectory yoxlandı: {0}' -f $WorkDirectory)
        }
        else {
            Write-RunLog INFO ('WorkDirectory hələ yoxdur, real işə salınmada qorunan şəkildə yaradılacaq: {0}' -f $WorkDirectory)
        }
    }

    # Skripti və ya CSV-ni başqa istifadəçilər dəyişə bilirmi?
    if ($PSCommandPath) { Test-InputFileTrust -Path $PSCommandPath -Label 'Skript faylı' }
    if ($Action -in @('CreateUsers', 'ConfigureFirewall')) { Test-InputFileTrust -Path $CsvPath -Label 'CSV faylı' }

    switch ($Action) {
        'CreateUsers' {
            $actionParams = @{
                Path                  = $CsvPath
                PasswordLength        = $PasswordLength
                AllowPrivilegedGroups = $AllowPrivilegedGroups
                Force                 = $Force
                RunDirectory          = $runDirectory
            }
            $result = Invoke-UserProvisioning @actionParams
        }
        'ConfigureFirewall' {
            $actionParams = @{
                Path            = $CsvPath
                RuleGroup       = $RuleGroup
                AllowRiskyRules = $AllowRiskyRules
                Force           = $Force
                RunDirectory    = $runDirectory
            }
            $result = Invoke-FirewallConfiguration @actionParams
        }
        'RemoveFirewallRules' {
            $result = Invoke-FirewallRollback -RuleGroup $RuleGroup -Force:$Force -RunDirectory $runDirectory
        }
        'CollectLogs' {
            $result = Invoke-LogCollection -LogName $LogName -Days $Days -MaxEvents $MaxEvents -RunDirectory $runDirectory
        }
    }

    if ($null -ne $result) {
        if ($result.Cancelled) { $exitCode = 3 }
        elseif ($result.Failed -gt 0) { $exitCode = 1 }
    }
}
catch {
    Write-RunLog ERROR $_.Exception.Message
    Write-RunLog ERROR 'Əməliyyat dayandırıldı. Təfərrüatlar yuxarıda və log faylındadır.'
    $exitCode = 2
}

if ($runDirectory) { Write-RunLog INFO ('Log və nəticələr: {0}' -f $runDirectory) }
if ($WhatIfPreference) { Write-RunLog WARN 'Simulyasiya bitdi - heç nə dəyişdirilmədi.' }
exit $exitCode
