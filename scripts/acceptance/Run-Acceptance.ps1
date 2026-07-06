param(
    [string]$LocalDns = "127.0.0.1",
    [int]$LocalDnsPort = 53,
    [string]$UpstreamDns = "202.106.0.20",
    [string]$LocalHitDomain = "www.bupt.com.cn",
    [string]$LocalHitIp = "114.255.40.66",
    [string]$BlacklistDomain = "www.666.com",
    [string]$MissDomain = "www.baidu.com",
    [int]$RepeatCount = 100,
    [string]$OutDir = "evidence\nslookup"
)

# DNS Relay acceptance helper for Windows PowerShell.
# Run after the DNS Relay Java program has started as Administrator and is listening on UDP 53.

$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$summary = Join-Path $OutDir "powershell_summary.csv"
$runLog = Join-Path $OutDir "powershell_run.log"

@(
    "DNS Relay acceptance run"
    "date=$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')"
    "local_dns=$LocalDns"
    "local_dns_port=$LocalDnsPort"
    "upstream_dns=$UpstreamDns"
    "local_hit_domain=$LocalHitDomain"
    "local_hit_ip=$LocalHitIp"
    "blacklist_domain=$BlacklistDomain"
    "miss_domain=$MissDomain"
    "repeat_count=$RepeatCount"
    ""
) | Set-Content -Encoding UTF8 -Path $runLog

"case,domain,type,server,iteration,exit_code,elapsed_ms,heuristic" | Set-Content -Encoding UTF8 -Path $summary

function Invoke-DnsRelayLookup {
    param(
        [string]$CaseId,
        [string]$Domain,
        [string]$QueryType,
        [string]$Server,
        [string]$Iteration
    )

    $outFile = Join-Path $OutDir ("{0}_{1}_{2}.txt" -f $CaseId, $QueryType, $Iteration)
    $timer = [System.Diagnostics.Stopwatch]::StartNew()

    $portArgs = @()
    if ($Server -eq $LocalDns -and $LocalDnsPort -ne 53) {
        $portArgs += "-port=$LocalDnsPort"
    }

    if ($QueryType -eq "DEFAULT") {
        $output = & nslookup @portArgs $Domain $Server 2>&1
    }
    else {
        $output = & nslookup @portArgs "-type=$QueryType" $Domain $Server 2>&1
    }

    $exitCode = $LASTEXITCODE
    $timer.Stop()
    $text = ($output | Out-String)
    $text | Set-Content -Encoding UTF8 -Path $outFile

    $heuristic = "manual_check"
    if ($CaseId -eq "TC02_local_hit") {
        if ($text -match [regex]::Escape($LocalHitIp)) { $heuristic = "contains_expected_ip" } else { $heuristic = "missing_expected_ip" }
    }
    elseif ($CaseId -eq "TC03_blacklist") {
        if ($text -match "NXDOMAIN|Non-existent domain|can't find|not find|不存在|不存在的域") { $heuristic = "looks_nxdomain_or_not_found" } else { $heuristic = "manual_check_blacklist" }
    }
    elseif ($CaseId -in @("TC04_miss_relay", "TC04_miss_upstream")) {
        $heuristic = "output_saved_manual_compare"
    }
    elseif ($CaseId -eq "TC06_type_a") {
        if ($text -match [regex]::Escape($LocalHitIp)) { $heuristic = "contains_expected_a_ip" } else { $heuristic = "missing_expected_a_ip" }
    }
    elseif ($CaseId -eq "TC06_type_aaaa") {
        $heuristic = "aaaa_policy_requires_packet_or_output_review"
    }

    $line = '"{0}","{1}","{2}","{3}","{4}",{5},{6},"{7}"' -f $CaseId, $Domain, $QueryType, $Server, $Iteration, $exitCode, $timer.ElapsedMilliseconds, $heuristic
    Add-Content -Encoding UTF8 -Path $summary -Value $line
}

Write-Host "[1/7] TC-02 local hit A lookup"
Invoke-DnsRelayLookup -CaseId "TC02_local_hit" -Domain $LocalHitDomain -QueryType "DEFAULT" -Server $LocalDns -Iteration "001"

Write-Host "[2/7] TC-03 blacklist lookup"
Invoke-DnsRelayLookup -CaseId "TC03_blacklist" -Domain $BlacklistDomain -QueryType "DEFAULT" -Server $LocalDns -Iteration "001"

Write-Host "[3/7] TC-04 relay miss lookup via local DNS"
Invoke-DnsRelayLookup -CaseId "TC04_miss_relay" -Domain $MissDomain -QueryType "DEFAULT" -Server $LocalDns -Iteration "001"

Write-Host "[4/7] TC-04 direct upstream comparison"
Invoke-DnsRelayLookup -CaseId "TC04_miss_upstream" -Domain $MissDomain -QueryType "DEFAULT" -Server $UpstreamDns -Iteration "001"

Write-Host "[5/7] TC-06 A and AAAA lookups"
Invoke-DnsRelayLookup -CaseId "TC06_type_a" -Domain $LocalHitDomain -QueryType "A" -Server $LocalDns -Iteration "001"
Invoke-DnsRelayLookup -CaseId "TC06_type_aaaa" -Domain $LocalHitDomain -QueryType "AAAA" -Server $LocalDns -Iteration "001"

Write-Host "[6/7] TC-05 quick mixed sequence"
@($MissDomain, "www.qq.com", "www.sina.com.cn", $LocalHitDomain, $BlacklistDomain) | ForEach-Object {
    $safeName = ($_ -replace "[^A-Za-z0-9_]", "_")
    Invoke-DnsRelayLookup -CaseId "TC05_mixed_$safeName" -Domain $_ -QueryType "DEFAULT" -Server $LocalDns -Iteration "001"
}

Write-Host "[7/7] TC-07 repeated local-hit lookup: $RepeatCount iterations"
1..$RepeatCount | ForEach-Object {
    Invoke-DnsRelayLookup -CaseId "TC07_100_loop" -Domain $LocalHitDomain -QueryType "DEFAULT" -Server $LocalDns -Iteration ("{0:D3}" -f $_)
}

@(
    ""
    "Output files:"
    "- raw nslookup output: $OutDir"
    "- summary CSV: $summary"
    ""
    "Important: Wireshark evidence, UDP 53 listener evidence, administrator permissions, and screenshots must be collected manually on the acceptance machine."
) | Add-Content -Encoding UTF8 -Path $runLog

Write-Host "Done. Review $summary and the raw files under $OutDir."
