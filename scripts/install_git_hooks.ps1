# Install tracked git hooks from .githooks/ into .git/hooks/
$ErrorActionPreference = "Stop"
$Root = git rev-parse --show-toplevel 2>$null
if (-not $Root) { throw "Not inside a git repository." }
$Src = Join-Path $Root ".githooks"
$Dst = Join-Path $Root ".git\hooks"
if (-not (Test-Path $Src)) { throw "Missing .githooks at $Src" }
Get-ChildItem $Src -File | ForEach-Object {
  $target = Join-Path $Dst $_.Name
  Copy-Item $_.FullName $target -Force
  Write-Host "Installed $($_.Name) -> $target"
}
Write-Host "Done. Hooks: pre-commit + pre-push (encoding checks)."
