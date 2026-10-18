# NetSecure - build.ps1
# Builds NetSecure (plus its sibling Network and Crypto dependencies) and
# optionally runs the tests.
#   pwsh -ExecutionPolicy Bypass -File scripts/build.ps1 -Linkage shared -Test

param(
    [ValidateSet('shared', 'static')]
    [string]$Linkage = 'shared',
    [switch]$Test
)

$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot                # .../NetSecure
$ToolsRoot = Join-Path $Root "..\..\tools"              # workspace tools
$BuildDir = Join-Path $Root "build-$Linkage"
if ($Linkage -eq 'shared') { $Shared = 'ON' } else { $Shared = 'OFF' }

$cmakeArgs = @(
    "-S", $Root,
    "-B", $BuildDir,
    "-G", "MinGW Makefiles",
    "-DCMAKE_BUILD_TYPE=Release",
    "-DBUILD_SHARED_LIBS=$Shared"
)

$opensslInstall = Join-Path $ToolsRoot "openssl-install"
if (Test-Path $opensslInstall) {
    $cmakeArgs += "-DOPENSSL_ROOT_DIR=$opensslInstall"
} else {
    throw "OpenSSL installation not found: $opensslInstall"
}

& cmake @cmakeArgs
if ($LASTEXITCODE -ne 0) { throw "cmake configure failed (exit $LASTEXITCODE)" }

& cmake --build $BuildDir
if ($LASTEXITCODE -ne 0) { throw "cmake build failed (exit $LASTEXITCODE)" }

if ($Test) {
    Write-Host ""
    Write-Host "Running the NetSecure test suite (ctest)..."
    & ctest --test-dir $BuildDir --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw "ctest failed (exit $LASTEXITCODE)" }
}

Write-Host ""
Write-Host "Build finished: $(Join-Path $BuildDir 'bin\secure_echo_server.exe')"
