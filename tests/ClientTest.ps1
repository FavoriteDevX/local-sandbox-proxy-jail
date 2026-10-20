<#
.SYNOPSIS
    Integration and Validation Test Suite for the Local Sandbox Proxy Jail.
.DESCRIPTION
    Simulates sandboxed application scripts sending payloads to validated vs jailed endpoints.
#>

\$SandboxUrl = "http://localhost:9090"

Write-Host "=== INITIALIZING SANDBOX BOUNDARY TESTS ===" -ForegroundColor Cyan

# TEST 1: Requesting a Whitelisted Destination (Should Succeed)
\$Target1 = "https://github.com"
Write-Host "`n[*] Test 1: Sending request to ALLOWED host ($Target1)..." -ForegroundColor Yellow

try {
    $Headers1 = @{ "X-Sandbox-Target-Redirect" = $Target1 }
    $Response1 = Invoke-WebRequest -Uri $SandboxUrl -Headers $Headers1 -Method Get -UseBasicParsing
    
    Write-Host "[SUCCESS] Sandbox allowed traffic. Status Code: $($Response1.StatusCode)" -ForegroundColor Green
    Write-Host "Payload Preview: $($Response1.Content.Substring(0, 100))..." -ForegroundColor Gray
} catch {
    Write-Host "[FAIL] Test 1 failed unexpectedly: $_" -ForegroundColor Red
}

# TEST 2: Requesting a Jailed/Blocked Destination (Should Be Blocked by Policy)
$Target2 = "https://bad-untrusted-domain.com"
Write-Host "`n[*] Test 2: Sending request to JAILED host (\$Target2)..." -ForegroundColor Yellow

try {
    \$Headers2 = @{ "X-Sandbox-Target-Redirect" = \(Target2 }\)Response2 = Invoke-WebRequest -Uri SandboxUrl -Headers Headers2 -Method Get -UseBasicParsing
    Write-Host "[FAIL] Security Flaw: Sandbox allowed a blocked domain!" -ForegroundColor Red
} catch {
    # Expecting a 403 Forbidden boundary exception
    if (\$_.Exception.Response.StatusCode -eq "Forbidden") {
        Write-Host "[SUCCESS] Sandbox Jail successfully blocked the forbidden host!" -ForegroundColor Green
        Write-Host "Server Intercept Message: Exception captured as intended." -ForegroundColor Gray
    } else {
        Write-Host "[FAIL] Unexpected error token during boundary validation: \$_" -ForegroundColor Red
    }
}
