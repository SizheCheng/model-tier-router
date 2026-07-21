param(
    [string]$ArtifactPath = '',
    [string]$PacketRoot = '',
    [string]$RouterRepository = 'C:\Users\sizhe\Documents\model-tier-router',
    [string]$SourceRepository = '',
    [string]$WorkspaceParent = 'C:\Users\sizhe\mtr-work\product-r1',
    [string]$ResultRoot = ''
)

$ErrorActionPreference = 'Stop'
if (-not $PacketRoot) {
    $PacketRoot = $PSScriptRoot
}
if (-not $SourceRepository) {
    $manifest = Get-Content -Raw -LiteralPath (Join-Path $PacketRoot 'FINAL_EXECUTION_MANIFEST.json') | ConvertFrom-Json
    $SourceRepository = [string]$manifest.lanes[0].source_repository
}
if (-not $ArtifactPath) {
    $ArtifactPath = Join-Path $PSScriptRoot 'mtr-dogfood-product-lane.pyz'
}
if (-not $ResultRoot) {
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ')
    $name = 'product-result-' + $stamp + '-' + $PID
    $ResultRoot = Join-Path (Join-Path $PSScriptRoot 'results') $name
}
$python = (Get-Command python.exe -ErrorAction Stop).Source

& $python -B $ArtifactPath `
    --packet-root $PacketRoot `
    --router-repository $RouterRepository `
    --source-repository $SourceRepository `
    --workspace-parent $WorkspaceParent `
    --result-root $ResultRoot `
    --runner-pid $PID

exit $LASTEXITCODE
