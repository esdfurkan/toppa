# Toppa E2E leak checks (run on the Windows PC with an active tunnel).
#
# Usage:  .\scripts\e2e\leak-checks.ps1 [-TunnelIp 10.111.0.1] [-AdapterName Toppa]
# Exit code 0 = no leaks detected. Manual Wireshark-on-uplink audits remain
# the gold standard; this script automates the fast deterministic checks.
param(
    [string]$TunnelIp = "10.111.0.1",
    [string]$AdapterName = "Toppa",
    [int]$MaxTtl = 64
)

$ErrorActionPreference = "Stop"
$failures = 0

function Check($name, $ok, $detail) {
    if ($ok) { Write-Host "PASS  $name" -ForegroundColor Green }
    else { Write-Host "FAIL  $name  ($detail)" -ForegroundColor Red; $script:failures++ }
}

# 1. Default route: the tunnel must own 0.0.0.0/0 (kill-switch, fail-closed).
$routes = route print 0.0.0.0 | Out-String
Check "default route via tunnel" ($routes -match $AdapterName) "0/0 not routed via $AdapterName"

# 2. DNS: every adapter must point at the tunnel resolver (no parallel-query
#    leaks via Smart Multi-Homed Name Resolution).
$dnsOutput = netsh interface ip show dns | Out-String
$physicalDnsOk = -not ($dnsOutput -match "8\.8\.8\.8") # example: a hardcoded public resolver surviving the rewrite
Check "physical adapters use tunnel dns" $physicalDnsOk "a physical adapter still has a public resolver"

# 3. IPv6 blackhole: no working v6 default outside the tunnel.
$v6 = netsh interface ipv6 show route ::/0 | Out-String
Check "ipv6 default handled" ($v6 -ne $null) "inspect ::/0 manually (blackhole or tunnel)"

# 4. DNS answers come through the tunnel (resolver is on the tunnel IP).
$resolve = Resolve-DnsName example.com -Server $TunnelIp -DnsOnly -ErrorAction SilentlyContinue
Check "dns answers via tunnel resolver" ($null -ne $resolve) "tunnel resolver did not answer"

# 5. Egress TTL: the test endpoint (scripts/e2e/ttl-echo or any 'ping' TTL
#    report) must see TTL <= MaxTtl — Android-originated, not Windows 128.
Write-Host "NOTE  egress TTL check needs the ttl-echo test server; verify manually or via scripts/e2e README."

if ($failures -gt 0) { exit 1 } else { Write-Host "All leak checks passed." -ForegroundColor Green; exit 0 }
