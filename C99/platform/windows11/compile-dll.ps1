Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$C99Root = Resolve-Path (Join-Path $ScriptDir "..\..")
$CMakeLists = Join-Path $C99Root "CMakeLists.txt"

if (-not (Test-Path $CMakeLists)) {
    Write-Error "C99/CMakeLists.txt does not exist yet. Create the C99 CMake project before running this build script."
    exit 2
}

$BuildDir = Join-Path $C99Root "out\windows11\build"
$InstallDir = Join-Path $C99Root "out\windows11\install"

cmake -S $C99Root -B $BuildDir `
    -A x64 `
    -DCMAKE_INSTALL_PREFIX="$InstallDir" `
    -DBUILD_SHARED_LIBS=ON `
    -DWEBTRANSPORT_C99_BUILD_APPS=ON `
    -DWEBTRANSPORT_C99_BUILD_TESTS=ON

cmake --build $BuildDir --config Release --parallel
cmake --install $BuildDir --config Release
