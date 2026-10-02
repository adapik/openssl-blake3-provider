param([string]$Version, [string]$Prefix)
$ErrorActionPreference = "Stop"
if (Test-Path "$Prefix\bin\openssl.exe") { Write-Host "already built"; exit 0 }
$tmp = New-Item -ItemType Directory -Path "$env:RUNNER_TEMP\ossl-$Version" -Force
Invoke-WebRequest "https://github.com/openssl/openssl/releases/download/openssl-$Version/openssl-$Version.tar.gz" -OutFile "$tmp\o.tgz"
tar -xzf "$tmp\o.tgz" -C $tmp
Push-Location "$tmp\openssl-$Version"
perl Configure VC-WIN64A no-asm no-docs no-tests --prefix=$Prefix --openssldir=$Prefix\ssl
nmake
nmake install_sw
Pop-Location
