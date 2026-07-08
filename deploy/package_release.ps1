param(
  [string]$Version = (Get-Date -Format "yyyyMMdd-HHmmss")
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$DistDir = Join-Path $ProjectRoot "dist"
$StageDir = Join-Path $DistDir "a2-secops-agent"
$ZipPath = Join-Path $DistDir "a2-secops-agent-release-$Version.zip"

if (Test-Path $StageDir) {
  Remove-Item -LiteralPath $StageDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $StageDir | Out-Null
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

$Include = @(
  "backend",
  "frontend",
  "deploy",
  "tests",
  "README.md",
  "OFFLINE_DEPLOY.md",
  ".env.example"
)

foreach ($item in $Include) {
  $src = Join-Path $ProjectRoot $item
  if (Test-Path $src) {
    $dst = Join-Path $StageDir $item
    if ((Get-Item $src).PSIsContainer) {
      Copy-Item -LiteralPath $src -Destination $dst -Recurse
    } else {
      Copy-Item -LiteralPath $src -Destination $dst
    }
  }
}

$junk = @(
  "__pycache__",
  "*.pyc",
  ".DS_Store",
  "Thumbs.db",
  "dist",
  "data\a2_agent.sqlite3",
  "data\audit_events.jsonl"
)

foreach ($pattern in $junk) {
  Get-ChildItem -LiteralPath $StageDir -Recurse -Force -Filter $pattern -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
}

if (Test-Path $ZipPath) {
  Remove-Item -LiteralPath $ZipPath -Force
}
Compress-Archive -LiteralPath $StageDir -DestinationPath $ZipPath -Force

Write-Host "Release package created:"
Write-Host $ZipPath
