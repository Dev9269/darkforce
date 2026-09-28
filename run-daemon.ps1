$env:DATABASE_URL = "postgresql://darkforce@127.0.0.1:5433/darkforce"
$env:DF_COLLECT_INTERVAL = "10"
$env:DF_MAX_SITES = "5000"
$env:DF_CRAWL_CAP = "40"
$env:DF_FAST_CRAWL = "1"
$env:DF_SWEEP_DAYS = "7"

Start-Process -FilePath "C:\Users\jaina\AppData\Local\Programs\Python\Python312\python.exe" `
  -ArgumentList "run.py", "--live", "--daemon", "--interval", "10" `
  -WorkingDirectory "C:\Users\jaina\darkforce" `
  -RedirectStandardOutput "C:\Users\jaina\darkforce\server-out.log" `
  -RedirectStandardError  "C:\Users\jaina\darkforce\server-err.log" `
  -WindowStyle Hidden

Write-Output "daemon launched (pid on 8000). waiting 20s for boot+first pass..."
Start-Sleep -Seconds 20
if (Test-Path "C:\Users\jaina\darkforce\server-out.log") {
  Write-Output "--- server-out.log tail ---"
  Get-Content "C:\Users\jaina\darkforce\server-out.log" -Tail 15
}
if (Test-Path "C:\Users\jaina\darkforce\server-err.log") {
  Write-Output "--- server-err.log tail ---"
  Get-Content "C:\Users\jaina\darkforce\server-err.log" -Tail 15
}