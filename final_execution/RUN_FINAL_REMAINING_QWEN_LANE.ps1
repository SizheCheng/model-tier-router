param(
    [string]$ArtifactPath = '',
    [string]$PacketRoot = '',
    [string]$RouterRepository = 'C:\Users\sizhe\Documents\model-tier-router',
    [string]$QwenRepository = 'C:\Users\sizhe\Documents\qwen-redaction-standalone',
    [string]$WorkspaceParent = 'C:\Users\sizhe\mtr-work\qwen-r1',
    [string]$ResultRoot = ''
)

$ErrorActionPreference = 'Stop'
if (-not $PacketRoot) {
    $PacketRoot = $PSScriptRoot
}
if (-not $ArtifactPath) {
    $ArtifactPath = Join-Path $PSScriptRoot 'mtr-dogfood-remaining-lane.pyz'
}
if (-not $ResultRoot) {
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ')
    $name = 'final-remaining-qwen-result-' + $stamp + '-' + $PID
    $ResultRoot = Join-Path (Join-Path $PSScriptRoot 'results') $name
}
$python = (Get-Command python.exe -ErrorAction Stop).Source

& $python -B $ArtifactPath `
    --packet-root $PacketRoot `
    --router-repository $RouterRepository `
    --qwen-repository $QwenRepository `
    --workspace-parent $WorkspaceParent `
    --result-root $ResultRoot `
    --runner-pid $PID

exit $LASTEXITCODE