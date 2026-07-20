[CmdletBinding()]
param(
    [string]$ContractPath = "contracts/MODEL_TIER_ROUTER_DOGFOOD_R3_EXTERNAL_RUNTIME.json",
    [string]$CloseoutPath = "reports/pilot-r3-closeout.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$HarnessRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
Set-Location -LiteralPath $HarnessRoot

if (-not [System.IO.Path]::IsPathRooted($ContractPath)) {
    $ContractPath = Join-Path -Path $HarnessRoot -ChildPath $ContractPath
}
if (-not [System.IO.Path]::IsPathRooted($CloseoutPath)) {
    $CloseoutPath = Join-Path -Path $HarnessRoot -ChildPath $CloseoutPath
}
$ContractPath = [System.IO.Path]::GetFullPath($ContractPath)
$CloseoutPath = [System.IO.Path]::GetFullPath($CloseoutPath)

$env:PYTHONPATH = Join-Path -Path $HarnessRoot -ChildPath "src"
$env:PYTHONDONTWRITEBYTECODE = "1"

& python -B -m mtr_dogfood.external_runner --contract $ContractPath --closeout $CloseoutPath --runner-pid $PID
$RunnerExitCode = $LASTEXITCODE
exit $RunnerExitCode
