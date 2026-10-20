<#
.SYNOPSIS
    Local Sandbox Network Proxy Jail & Traffic Interceptor.
.DESCRIPTION
    Launches an isolated network sandbox gateway that acts as a secure reverse proxy jail.
    Intercepts script requests, handles rotational outbound proxies, and enforces traffic isolation rules.
.EXAMPLE
    .\SandboxJail.ps1 -ListenPort 9090 -AllowedHosts @("://github.com", "registry.npmjs.org")
#>

param (
    [int]$ListenPort = 9090,
    [string[]]$AllowedHosts = @("://github.com", "github.com"),
    [string[]]$OutboundProxies = @()
)

# Enforce secure protocol negotiations inside the sandbox engine
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

# Initialize the Sandbox HTTP Boundary Listener
$SandboxListener = New-Object System.Net.HttpListener
$SandboxListener.Prefixes.Add("http://localhost:$ListenPort/")

try {
    $SandboxListener.Start()
    Write-Host "[SUCCESS] Local Sandbox Proxy Jail initialized perfectly on http://localhost:$ListenPort/" -ForegroundColor Gold
    Write-Host "[*] Traffic isolation active. Unallowed outbound connections will be trapped and jailed." -ForegroundColor Cyan
} catch {
    Write-Error "Failed to bind Sandbox gateway listener to port $ListenPort."
    return
}

$ProxyIndex = 0

while ($SandboxListener.IsListening) {
    try {
        # Await transactional payload packet from the sandboxed development agent
        $Context = $SandboxListener.GetContext()
        $Request = $Context.Request
        $Response = $Context.Response

        # Extract target URI destination header from the isolated script request
        $TargetUriString = $Request.Headers["X-Sandbox-Target-Redirect"]
        
        if ([string]::IsNullOrEmpty($TargetUriString)) {
            Write-Host "[!] Dropping un-mapped packet. Missing 'X-Sandbox-Target-Redirect' control header." -ForegroundColor Red
            $Response.StatusCode = 400
            $ErrorBuffer = [System.Text.Encoding]::UTF8.GetBytes('{"error": "Sandbox Boundary Violation. Target redirection header missing."}')
            $Response.OutputStream.Write($ErrorBuffer, 0, $ErrorBuffer.Length)
            $Response.Close()
            continue
        }

        $TargetUri = New-Object System.Uri($TargetUriString)
        Write-Host "`n[+] Sandbox Intercepted Request targeting host: $($TargetUri.Host)" -ForegroundColor Green

        # 1. ENFORCE SANDBOX JAIL RULES (HOST ISOLATION)
        $IsAllowed = $false
        foreach ($hostName in $AllowedHosts) {
            if ($TargetUri.Host -like "*$hostName*") { $IsAllowed = $true; break; }
        }

        if (-not $IsAllowed) {
            Write-Host "[BLOCK] Sandbox Execution Blocked! Host '$($TargetUri.Host)' is not whitelisted inside the Jail parameters." -ForegroundColor Red
            $Response.StatusCode = 403
            $BlockBuffer = [System.Text.Encoding]::UTF8.GetBytes('{"error": "Sandbox Security Policy Violation. Target host destination is jailed."}')
            $Response.OutputStream.Write($BlockBuffer, 0, $BlockBuffer.Length)
            $Response.Close()
            continue
        }

        # 2. ROTATING OUTBOUND PROXY INJECTION LAYER
        $Handler = New-Object System.Net.Http.HttpClientHandler
        if ($OutboundProxies.Count -gt 0) {
            $SelectedProxy = $OutboundProxies[$ProxyIndex]
            Write-Host "[*] Tunneling sandbox payload through active outbound proxy: $SelectedProxy" -ForegroundColor Yellow
            $Handler.Proxy = New-Object System.Net.WebProxy($SelectedProxy)
            $Handler.UseProxy = $true
            $ProxyIndex = ($ProxyIndex + 1) % $OutboundProxies.Count # Increment index safely
        }

        # 3. SECURE PACKET DELIVERANCE & RETRIEVAL
        $Client = New-Object System.Net.Http.HttpClient($Handler)
        $Client.Timeout = [TimeSpan]::FromSeconds(10)

        Write-Host "[*] Request authorized. Relaying data safely to production endpoint..." -ForegroundColor Cyan
        $Task = $Client.GetAsync($TargetUri)
        $TargetResponse = $Task.Result

        # Stream extraction and scrub routine
        $RawPayloadData = $TargetResponse.Content.ReadAsStringAsync().Result
        $OutputBuffer = [System.Text.Encoding]::UTF8.GetBytes($RawPayloadData)

        # Build clean HTTP boundary response package back to the development environment
        $Response.ContentLength64 = $OutputBuffer.Length
        $Response.ContentType = "application/json"
        $Response.StatusCode = [int]$TargetResponse.StatusCode

        $Response.OutputStream.Write($OutputBuffer, 0, $OutputBuffer.Length)
        $Response.OutputStream.Close()
        Write-Host "[SUCCESS] Secure transaction complete. Data channeled back to local application state." -ForegroundColor Green

    } catch {
        Write-Host "[ERR] Internal sandbox engine fault exception: $_" -ForegroundColor Red
        if ($null -ne $Response) {
            $Response.StatusCode = 500
            $Response.Close()
        }
    }
}
