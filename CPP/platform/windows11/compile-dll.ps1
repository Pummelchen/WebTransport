Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CppRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$CMakeLists = Join-Path $CppRoot "CMakeLists.txt"

if (-not (Test-Path $CMakeLists)) {
    Write-Error "CPP/CMakeLists.txt does not exist yet. Create the C++ CMake project before running this build script."
    exit 2
}

$BuildDir = Join-Path $CppRoot "out\windows11\build"
$InstallDir = Join-Path $CppRoot "out\windows11\install"

cmake -S $CppRoot -B $BuildDir `
    -A x64 `
    -DCMAKE_INSTALL_PREFIX="$InstallDir" `
    -DBUILD_SHARED_LIBS=ON `
    -DWEBTRANSPORT_BUILD_APPS=ON `
    -DWEBTRANSPORT_BUILD_TESTS=ON

cmake --build $BuildDir --config Release --parallel
cmake --install $BuildDir --config Release
