param(
    [string]$ArtifactPath = '',
    [Parameter(Mandatory = $true)]
    [string]$PacketRoot,
    [Parameter(Mandatory = $true)]
    [string]$RouterRepository,
    [Parameter(Mandatory = $true)]
    [string]$QwenRepository,
    [Parameter(Mandatory = $true)]
    [string]$WorkspaceParent,
    [string]$ReceiptPath = ''
)

$ErrorActionPreference = 'Stop'
if (-not $ArtifactPath) {
    $ArtifactPath = Join-Path $PSScriptRoot 'mtr-dogfood-qualification.pyz'
}
if (-not $ReceiptPath) {
    $ReceiptPath = Join-Path $PSScriptRoot 'qualification-receipt.json'
}
$python = (Get-Command python.exe -ErrorAction Stop).Source

& $python -B $ArtifactPath `
    --packet-root $PacketRoot `
    --router-repository $RouterRepository `
    --qwen-repository $QwenRepository `
    --workspace-parent $WorkspaceParent `
    --receipt $ReceiptPath

exit $LASTEXITCODE
