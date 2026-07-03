$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
if (-not $root) { $root = (Get-Location).Path }
Push-Location "$root\frontend"
bun install --frozen-lockfile
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
bun run build
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Pop-Location
$dest = "$root\internal\core\adminweb\dist"
Remove-Item -Recurse -Force $dest -ErrorAction SilentlyContinue
Copy-Item -Recurse "$root\frontend\out" $dest
Push-Location $root
go mod tidy
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
go build -o bin\my-openwaf.exe ./cmd/...
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Pop-Location
