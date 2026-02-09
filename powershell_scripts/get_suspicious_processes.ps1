# ===========================================================
# Mini EDR - Suspicious Process Monitor (Final Version)
# ===========================================================

# Dictionary to track already reported suspicious processes
# Key = "ProcessName|Path", Value = @{ LastSeen = datetime; AlreadyReported = bool }
$checked = @{}

# Suspicious folders
$suspiciousPaths = @("AppData", "Temp", "Downloads")

# Trusted paths (paths that are considered safe)
$trustedPaths = @("C:\Program Files", "C:\Windows")

# Local IP patterns (not external)
$localIPs = @("127.0.", "192.168.", "10.0.", "172.16.", "169.254.", "localhost", "::1")

# JSON report file (repo-relative; avoids user-specific absolute paths)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")
$reportFile = Join-Path $repoRoot "reports\suspicious_processes.json"

# Function to get network connections for a process
function Get-ProcessConnections {
    param([int]$ProcessId)
    
    try {
        $connections = @()
        $netConns = Get-NetTCPConnection -OwningProcess $ProcessId -ErrorAction SilentlyContinue | 
        Where-Object { $_.State -eq "Established" }
        
        foreach ($conn in $netConns) {
            $connections += @{
                RemoteIP   = $conn.RemoteAddress
                RemotePort = $conn.RemotePort
                LocalPort  = $conn.LocalPort
            }
        }
        
        return $connections
    }
    catch {}
    
    return @()
}

# Function to check if IP is external
function Is-ExternalIP {
    param([string]$IP)
    
    foreach ($local in $localIPs) {
        if ($IP -like "$local*") { return $false }
    }
    return $true
}

# Ensure the reports folder exists
$reportFolder = Split-Path $reportFile
if (-not (Test-Path $reportFolder)) {
    New-Item -ItemType Directory -Path $reportFolder | Out-Null
}

# ===========================================================
# Main monitoring loop
# ===========================================================
while ($true) {

    $processList = @()

    # Get all running processes
    $processes = Get-Process | Where-Object { $_.Path -notlike "C:\Windows*" -and $_.Path -notlike "C:\Program Files*" }

    foreach ($proc in $processes) {

        $proid = $proc.Id
        $path = ""

        # Try to get executable path
        try { $path = $proc.Path } catch { $path = "" }

        $isSuspicious = $false

        if (-not [string]::IsNullOrEmpty($path)) {

            # Skip if path is in trusted paths
            $isTrusted = $false
            foreach ($t in $trustedPaths) {
                if ($path -like "$t*") { $isTrusted = $true; break }
            }

            if (-not $isTrusted) {

                # Suspicious folder check
                if ($suspiciousPaths | Where-Object { $path -match $_ }) {
                    $isSuspicious = $true
                }

                # Signature check
                try {
                    $sig = Get-AuthenticodeSignature $path
                    if ($sig.Status -ne "Valid") { $isSuspicious = $true }
                }
                catch { $sig = $null }
            }
        }

        if ($isSuspicious) {

            # Get network connections first
            $netConnections = Get-ProcessConnections -ProcessId $proid
            $externalConnections = $netConnections | Where-Object { Is-ExternalIP $_.RemoteIP }

            # Use ProcessName + Path as key to prevent multiple alerts for same process
            $key = "$($proc.ProcessName)|$path"

            # Print to console only once per unique process
            if (-not $checked.ContainsKey($key) -or -not $checked[$key].AlreadyReported) {
                $netMsg = if ($externalConnections.Count -gt 0) { " [NETWORK: External connections detected!]" } else { "" }
                Write-Output "$(Get-Date -Format 'HH:mm:ss') - $($proc.ProcessName) is suspicious!$netMsg"
            }

            # Update dictionary
            $checked[$key] = @{
                LastSeen        = Get-Date
                AlreadyReported = $true
            }

            # Add to JSON report
            $processList += [PSCustomObject]@{
                Timestamp           = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                PID                 = $proid
                Name                = $proc.ProcessName
                Path                = $path
                Signature           = if ($sig) { $sig.Status } else { "Unknown" }
                NetworkConnections  = $netConnections
                ExternalConnections = @($externalConnections)
                HasExternalConn     = $externalConnections.Count -gt 0
            }
        }
    }

    # Save JSON report if there are suspicious processes
    if ($processList.Count -gt 0) {
        $processList | ConvertTo-Json -Depth 3 | Out-File -FilePath $reportFile -Encoding UTF8
    }

    # Remove keys for processes that no longer exist
    $toRemove = $checked.Keys | Where-Object { 
        # Split key to extract path
        $namePath = $_.Split("|")
        $name = $namePath[0]
        $path = $namePath[1]

        # Check if any PID with this Name+Path is still running
        -not ($processes | Where-Object { $_.ProcessName -eq $name -and $_.Path -eq $path })
    }
    foreach ($key in $toRemove) {
        $checked.Remove($key)
    }

    # Wait 4 seconds before next scan
    Start-Sleep -Seconds 4
}
