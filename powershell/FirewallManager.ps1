param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Add", "Remove", "Check")]
    [string]$Action,
    [string]$RemoteIP
)
$ErrorActionPreference = "Stop"
$RulePrefix = "StudentIDS_Demo_"

function Test-PrivateIPv4([string]$Address) {
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$parsed)) {
        throw "Invalid IP address."
    }
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw "Only IPv4 is allowed for this controlled demo."
    }
    $bytes = $parsed.GetAddressBytes()
    $private = ($bytes[0] -eq 10) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or
        ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31)
    if (-not $private -or $Address -eq "127.0.0.1" -or $Address -eq "0.0.0.0") {
        throw "Only a private LAN IPv4 address is allowed."
    }
}

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator to manage firewall rules."
}

switch ($Action) {
    "Add" {
        if (-not $RemoteIP) { throw "-RemoteIP is required for Add." }
        Test-PrivateIPv4 $RemoteIP
        $name = "$RulePrefix$($RemoteIP.Replace('.', '-'))"
        $existing = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Output "EXISTS: $name"
        } else {
            New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Block `
                -RemoteAddress $RemoteIP -Profile Private -Enabled True | Out-Null
            $verified = Get-NetFirewallRule -DisplayName $name
            if (-not $verified -or $verified.Action -ne "Block" -or -not $verified.Enabled) {
                throw "Rule creation could not be verified."
            }
            Write-Output "CREATED_AND_VERIFIED: $name (RemoteIP=$RemoteIP, Direction=Inbound, Action=Block)"
        }
    }
    "Remove" {
        $rules = Get-NetFirewallRule -DisplayName "$RulePrefix*" -ErrorAction SilentlyContinue
        if ($rules) {
            $rules | Remove-NetFirewallRule
            Write-Output "Removed $($rules.Count) project firewall rule(s)."
        } else {
            Write-Output "No project firewall rules found."
        }
    }
    "Check" {
        if (-not $RemoteIP) { throw "-RemoteIP is required for Check." }
        Test-PrivateIPv4 $RemoteIP
        $name = "$RulePrefix$($RemoteIP.Replace('.', '-'))"
        Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue |
            Select-Object DisplayName, Enabled, Direction, Action, Profile | Format-Table -AutoSize
    }
}
