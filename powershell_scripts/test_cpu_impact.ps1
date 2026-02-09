# ===========================================================
# CPU Impact Test - Filter vs No Filter
# ===========================================================

Write-Host "Testing CPU impact of early process filtering..." -ForegroundColor Yellow
Write-Host ""

# Test 1: WITH early filtering (current approach)
Write-Host "Test 1: WITH early filtering (current approach)" -ForegroundColor Green
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

for ($i = 0; $i -lt 10; $i++) {
    $processes = Get-Process | Where-Object { $_.Path -notlike "C:\Windows*" -and $_.Path -notlike "C:\Program Files*" }
    
    $suspiciousCount = 0
    foreach ($proc in $processes) {
        $path = $proc.Path
        if (-not [string]::IsNullOrEmpty($path)) {
            try {
                $sig = Get-AuthenticodeSignature $path
                if ($sig.Status -ne "Valid") {
                    $suspiciousCount++
                }
            }
            catch { }
        }
    }
}

$stopwatch.Stop()
$timeWithFilter = $stopwatch.ElapsedMilliseconds

Write-Host "Time (10 iterations): $timeWithFilter ms" -ForegroundColor Cyan
Write-Host ""

# Test 2: WITHOUT early filtering (all processes)
Write-Host "Test 2: WITHOUT early filtering (checking all processes)" -ForegroundColor Green
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

for ($i = 0; $i -lt 10; $i++) {
    $processes = Get-Process
    
    $suspiciousCount = 0
    foreach ($proc in $processes) {
        $path = $proc.Path
        if (-not [string]::IsNullOrEmpty($path)) {
            try {
                $sig = Get-AuthenticodeSignature $path
                if ($sig.Status -ne "Valid") {
                    $suspiciousCount++
                }
            }
            catch { }
        }
    }
}

$stopwatch.Stop()
$timeWithoutFilter = $stopwatch.ElapsedMilliseconds

Write-Host "Time (10 iterations): $timeWithoutFilter ms" -ForegroundColor Cyan
Write-Host ""

# Calculate improvement
$improvement = $timeWithoutFilter - $timeWithFilter
$percentImprovement = ($improvement / $timeWithoutFilter) * 100

Write-Host "=== RESULTS ===" -ForegroundColor Yellow
Write-Host "With filter:    $timeWithFilter ms"
Write-Host "Without filter: $timeWithoutFilter ms"
Write-Host "Improvement:    $improvement ms ($([math]::Round($percentImprovement, 2))%)" -ForegroundColor Green
Write-Host ""

if ($percentImprovement -gt 20) {
    Write-Host "✓ Filter SIGNIFICANTLY helps CPU!" -ForegroundColor Green
}
elseif ($percentImprovement -gt 5) {
    Write-Host "✓ Filter provides modest CPU improvement" -ForegroundColor Green
}
else {
    Write-Host "- Filter has minimal impact" -ForegroundColor Yellow
}
