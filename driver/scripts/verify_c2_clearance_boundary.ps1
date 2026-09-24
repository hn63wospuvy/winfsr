[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$clearancePath = (
    Resolve-Path -LiteralPath (
        Join-Path $PSScriptRoot '..\fsring-core\src\effect\clearance.rs'
    )
).Path
$expectedHash = 'AE8948B66029B7FD5A406FF17EEB7179974D04F91CAE52054F6BA528A7D4C37B'
$actualHash = (Get-FileHash -LiteralPath $clearancePath -Algorithm SHA256).Hash

if ($actualHash -cne $expectedHash) {
    Write-Error (
        'C2 CLEARANCE BOUNDARY: FAIL - SHA-256 mismatch for {0}; expected {1}, actual {2}' -f
            $clearancePath,
            $expectedHash,
            $actualHash
    )
    exit 1
}

Write-Output (
    'C2 CLEARANCE BOUNDARY: PASS ({0}; SHA-256 {1})' -f
        $clearancePath,
        $actualHash
)
