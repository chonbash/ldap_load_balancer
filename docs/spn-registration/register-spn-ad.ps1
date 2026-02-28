<#
.SYNOPSIS
    Registers SPN(s) for LDAP load balancer on an Active Directory account so that
    GSSAPI/Kerberos authentication works when clients connect via the balancer.

.DESCRIPTION
    Registers ldap/<BalancerHost> (and optionally ldap/<FQDN>) on the specified
    account (default: PDC emulator computer account). The backend DC that serves
    LDAP behind the balancer must have this SPN so it can accept Kerberos tickets
    issued for the balancer's name.

.PARAMETER BalancerHost
    Hostname or FQDN that clients use to connect to the LDAP load balancer
    (e.g. ldap-balancer or ldap-balancer.example.com).

.PARAMETER AccountName
    sAMAccountName of the AD account to register the SPN on (e.g. DC01$ for a
    computer account). If not specified, the PDC emulator computer account is used.

.PARAMETER Domain
    NetBIOS or FQDN of the domain (optional). If not specified, current domain is used.

.EXAMPLE
    .\register-spn-ad.ps1 -BalancerHost ldap-balancer.example.com
.EXAMPLE
    .\register-spn-ad.ps1 -BalancerHost ldap-balancer -AccountName DC01$
.EXAMPLE
    .\register-spn-ad.ps1 -BalancerHost lb.contoso.com -AccountName svc_ldap$
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Hostname or FQDN of the LDAP load balancer (as used by clients)")]
    [string]$BalancerHost,

    [Parameter(Mandatory = $false, HelpMessage = "AD account (sAMAccountName) to register SPN on, e.g. DC01$")]
    [string]$AccountName,

    [Parameter(Mandatory = $false, HelpMessage = "Domain name (optional)")]
    [string]$Domain
)

$ErrorActionPreference = "Stop"

function Write-Result {
    param([string]$Message, [string]$Type = "Info")
    $color = switch ($Type) { "Success" { "Green" } "Error" { "Red" } "Warning" { "Yellow" } default { "White" } }
    Write-Host $Message -ForegroundColor $color
}

# Resolve account to register SPN on
if (-not $AccountName) {
    try {
        $dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $pdc = $dom.PdcRoleOwner.Name
        $AccountName = "$pdc`$"
        Write-Verbose "Using PDC emulator computer account: $AccountName"
    } catch {
        Write-Result "Could not discover PDC. Specify -AccountName (e.g. DC01`$) explicitly." "Error"
        exit 1
    }
}

# Normalize account: ensure $ for computer account if missing
if ($AccountName -notmatch '\$$' -and $AccountName -match '^[A-Za-z0-9_-]+$') {
    Write-Verbose "Assuming computer account: appending `$"
    $AccountName = "$AccountName`$"
}

# Build list of SPNs to register
$spnsToAdd = @("ldap/$BalancerHost")
$domainFqdn = $null
if ($Domain) {
    if ($Domain -notmatch '\.') {
        try {
            $dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $domainFqdn = $dom.Name
        } catch { }
    } else {
        $domainFqdn = $Domain
    }
}
# If BalancerHost has no dot and we have domain, add ldap/<host>.<domain>
if ($BalancerHost -notmatch '\.' -and $domainFqdn) {
    $fqdnSpn = "ldap/$BalancerHost.$domainFqdn"
    if ($fqdnSpn -ne $spnsToAdd[0]) {
        $spnsToAdd += $fqdnSpn
    }
}

# Check Setspn is available
$setspn = Get-Command setspn.exe -ErrorAction SilentlyContinue
if (-not $setspn) {
    Write-Result "setspn.exe not found. Run this script on a domain-joined machine with AD tools." "Error"
    exit 1
}

$added = @()
$skipped = @()
$errors = @()

foreach ($spn in $spnsToAdd) {
    # Check if SPN is already on our account (setspn -L lists SPNs for account)
    $listOut = & setspn -L $AccountName 2>&1 | Out-String
    if ($listOut -match [regex]::Escape($spn)) {
        $skipped += $spn
        Write-Verbose "SPN already on account: $spn"
        continue
    }
    # Check if SPN exists on another account
    $query = & setspn -Q $spn 2>&1
    $queryExit = $LASTEXITCODE
    if ($queryExit -eq 0) {
        $queryStr = $query | Out-String
        $errors += "SPN $spn is already registered on another account. Run: setspn -Q $spn"
        continue
    }
    # Add SPN
    $addOut = & setspn -A $spn $AccountName 2>&1
    $addExit = $LASTEXITCODE
    if ($addExit -eq 0) {
        $added += $spn
    } else {
        $errors += "Failed to add $spn : $addOut"
    }
}

# Report
if ($errors.Count -gt 0) {
    foreach ($e in $errors) { Write-Result $e "Error" }
    if ($added.Count -gt 0) {
        Write-Result "Added: $($added -join ', ')" "Success"
    }
    exit 1
}

if ($added.Count -gt 0) {
    Write-Result "Success. SPN(s) registered on $AccountName : $($added -join ', ')" "Success"
}
if ($skipped.Count -gt 0) {
    Write-Result "Already present (skipped): $($skipped -join ', ')" "Info"
}
if ($added.Count -eq 0 -and $skipped.Count -eq 0) {
    Write-Result "No SPNs added and none skipped." "Warning"
}

exit 0
