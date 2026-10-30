<#
.SYNOPSIS
    Push a radius-admin package from this Windows PC to the RADIUS server and install it.

.DESCRIPTION
    1. Picks the package (default: the newest radius-admin*.tar.gz in your Downloads folder)
       and computes its SHA-256.
    2. Copies it to your home directory on the server over ssh (Windows' built-in OpenSSH;
       a plain ssh session, so neither scp nor the SFTP service is needed on the server).
    3. Connects with ssh, checks the SHA-256 on the server and runs deploy/update.sh from the
       package with sudo. update.sh unpacks the release under /opt/radius-admin-src, shows
       which install.sh phases it will run, asks you to confirm, installs, and keeps the last
       five releases for rollback.

    You are asked for your SSH password (twice, unless you use an SSH key) and your sudo
    password on the server. Nothing is stored except the server name, user name, port and
    key path, in %APPDATA%\radius-admin-push\settings.json.

.PARAMETER Package
    The .tar.gz to install. Default: newest radius-admin*.tar.gz in Downloads.
.PARAMETER Server
    Server name or address. Remembered after the first run (default radius.example.net).
.PARAMETER User
    Your Linux user name on the server. Remembered after the first run.
.PARAMETER Port
    SSH port (default 22). Remembered.
.PARAMETER IdentityFile
    SSH private key to use (optional). Remembered. Only this key is offered to the server.
.PARAMETER SshVerbose
    Show ssh's connection details (ssh -v) to diagnose login or connection problems.
.PARAMETER WithFreeradius
    Also install changed FreeRADIUS files (install.sh freeradius phase). Does not restart
    FreeRADIUS; that still happens from Review and apply in the web UI.
.PARAMETER Force
    Reinstall even if this package is already the current release.
.PARAMETER Yes
    Do not ask for confirmation on the server.
.PARAMETER Rollback
    Re-install the release before the current one (web UI only).
.PARAMETER List
    Show the releases installed on the server.

.EXAMPLE
    .\push-radius-admin.cmd
.EXAMPLE
    .\push-radius-admin.cmd -Package C:\Temp\radius-admin.tar.gz
.EXAMPLE
    .\push-radius-admin.cmd -Rollback
#>
[CmdletBinding(DefaultParameterSetName = 'Push')]
param(
    [Parameter(ParameterSetName = 'Push', Position = 0)] [string] $Package,
    [string] $Server,
    [string] $User,
    [int] $Port = 0,
    [string] $IdentityFile,
    [Parameter(ParameterSetName = 'Push')] [switch] $WithFreeradius,
    [Parameter(ParameterSetName = 'Push')] [switch] $Force,
    [Parameter(ParameterSetName = 'Push')] [switch] $Yes,
    [switch] $SshVerbose,
    [Parameter(ParameterSetName = 'Rollback', Mandatory = $true)] [switch] $Rollback,
    [Parameter(ParameterSetName = 'List', Mandatory = $true)] [switch] $List
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Fail([string] $msg) {
    Write-Host "ERROR: $msg" -ForegroundColor Red
    exit 1
}

# ------------------------------------------------------------------ SHA-256 of a file
# Get-FileHash is not available everywhere (older PowerShell, module auto-loading turned
# off by policy, Constrained Language Mode), so fall back to .NET and then to certutil.
# The .NET class used is the CryptoAPI provider, which also works when Windows'
# "use FIPS compliant algorithms" policy is on.
function Get-Sha256Hex([string] $path) {
    $errs = @()
    if (Get-Command Get-FileHash -ErrorAction SilentlyContinue) {
        try { return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
        catch { $errs += "Get-FileHash: $($_.Exception.Message)" }
    }
    try {
        $sha = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
        $fs = [System.IO.File]::OpenRead($path)
        try { $bytes = $sha.ComputeHash($fs) } finally { $fs.Dispose(); $sha.Dispose() }
        return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
    } catch { $errs += ".NET: $($_.Exception.Message)" }
    $certutil = Join-Path $env:SystemRoot 'System32\certutil.exe'
    if (Test-Path -LiteralPath $certutil) {
        $out = & $certutil -hashfile $path SHA256 2>&1
        foreach ($line in $out) {
            $h = ("$line" -replace '\s', '').ToLowerInvariant()
            if ($h -match '^[0-9a-f]{64}$') { return $h }
        }
        $errs += "certutil: $($out -join ' ')"
    }
    Fail ("Cannot compute the SHA-256 of the package. " + ($errs -join ' | '))
}

# ------------------------------------------------------------------ OpenSSH client
$ssh = Get-Command ssh.exe -ErrorAction SilentlyContinue
if (-not $ssh) {
    Fail ("The Windows OpenSSH client is not installed. Install it from Settings > System > " +
          "Optional features > OpenSSH Client (or ask IT), then open a new window and try again.")
}

# ------------------------------------------------------------------ settings
$settingsDir = Join-Path $env:APPDATA 'radius-admin-push'
$settingsFile = Join-Path $settingsDir 'settings.json'
$saved = $null
if (Test-Path -LiteralPath $settingsFile) {
    try { $saved = Get-Content -LiteralPath $settingsFile -Raw | ConvertFrom-Json } catch { $saved = $null }
}
function Saved([string] $name) {
    if ($saved -and ($saved.PSObject.Properties.Name -contains $name)) { return $saved.$name }
    return $null
}
function Ask([string] $prompt, [string] $default) {
    $a = Read-Host "$prompt [$default]"
    if ([string]::IsNullOrWhiteSpace($a)) { return $default }
    return $a.Trim()
}

if (-not $Server) { $Server = Saved 'Server' }
if (-not $Server) { $Server = Ask 'RADIUS server name or address' 'radius.example.net' }
if (-not $User) { $User = Saved 'User' }
if (-not $User) { $User = Ask "Your Linux user name on $Server" $env:USERNAME.ToLower() }
if ($Port -eq 0) { $p = Saved 'Port'; if ($p) { $Port = [int]$p } else { $Port = 22 } }
if (-not $IdentityFile) { $IdentityFile = Saved 'IdentityFile' }

if ($Server -notmatch '^[A-Za-z0-9.\-:]+$') { Fail "Server '$Server' does not look like a host name or address." }
if ($User -notmatch '^[a-z_][a-z0-9_.\-]*$') { Fail "User '$User' does not look like a Linux user name." }
if ($IdentityFile -and -not (Test-Path -LiteralPath $IdentityFile)) { Fail "SSH key not found: $IdentityFile" }

New-Item -ItemType Directory -Force -Path $settingsDir | Out-Null
[pscustomobject]@{ Server = $Server; User = $User; Port = $Port; IdentityFile = $IdentityFile } |
    ConvertTo-Json | Set-Content -LiteralPath $settingsFile -Encoding UTF8

$target = "$User@$Server"
$sshArgs = @('-p', "$Port", '-o', 'ServerAliveInterval=30')
# FIPS-mode sshd: offer only approved algorithms. Windows OpenSSH prefers Curve25519,
# Ed25519 and ChaCha20, which a FIPS server advertises but cannot compute, so it drops the
# connection during key exchange ("Connection closed ... expecting SSH2_MSG_KEX_ECDH_REPLY").
$sshArgs += @(
    '-o', 'KexAlgorithms=ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256',
    '-o', 'HostKeyAlgorithms=ecdsa-sha2-nistp384,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256',
    '-o', 'Ciphers=aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr',
    '-o', 'MACs=hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256',
    '-o', 'PubkeyAcceptedAlgorithms=ecdsa-sha2-nistp384,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256')
# With a key: offer only that key (an agent holding several keys can otherwise use up the
# server's MaxAuthTries and get the connection closed before the right key is tried).
if ($IdentityFile) { $sshArgs += @('-i', $IdentityFile, '-o', 'IdentitiesOnly=yes') }
if ($SshVerbose) { $sshArgs += '-v' }

function ConvertTo-QuotedArgument([string] $a) {
    # Start-Process joins arguments with spaces; quote the ones that need it.
    if ($a -match '[\s"]') { return '"' + ($a -replace '"', '\"') + '"' }
    return $a
}

$updater = '/opt/radius-admin-src/current/deploy/update.sh'
# ssh is always called directly (never captured into a variable) so its output and the
# sudo password prompt reach this window unbuffered. -t: sudo needs a terminal.

# ------------------------------------------------------------------ list / rollback
if ($List) {
    & $ssh.Source @sshArgs -t $target "sudo bash $updater --list"
    exit $LASTEXITCODE
}
if ($Rollback) {
    Write-Host "Rolling back the web UI on $Server to the previous release..." -ForegroundColor Cyan
    & $ssh.Source @sshArgs -t $target "sudo bash $updater --rollback"
    exit $LASTEXITCODE
}

# ------------------------------------------------------------------ push
if (-not $Package) {
    $downloads = Join-Path $env:USERPROFILE 'Downloads'
    $latest = Get-ChildItem -LiteralPath $downloads -Filter 'radius-admin*.tar.gz' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $latest) { Fail "No radius-admin*.tar.gz found in $downloads. Pass -Package <file>." }
    $Package = $latest.FullName
}
if (-not (Test-Path -LiteralPath $Package -PathType Leaf)) { Fail "Package not found: $Package" }
$item = Get-Item -LiteralPath $Package
$hash = Get-Sha256Hex $item.FullName
$remoteName = "radius-admin-$($hash.Substring(0, 12)).tar.gz"

Write-Host ''
Write-Host "Package : $($item.FullName)" -ForegroundColor Cyan
Write-Host ("          {0:N0} KB, saved {1}" -f ($item.Length / 1KB), $item.LastWriteTime)
Write-Host "SHA-256 : $hash"
Write-Host "Server  : $target (port $Port)"
Write-Host ''

Write-Host "Copying package to ${Server}:~/$remoteName ..." -ForegroundColor Cyan
# The package is fed to 'cat' on the server through ssh's standard input (Start-Process
# redirects it straight from the file, so the bytes are not altered). Password and host-key
# prompts still appear in this window.
$copyArgs = @($sshArgs) + @('-T', $target, "umask 077; cat > ~/$remoteName && echo radius-admin-upload-ok")
$outFile = Join-Path $env:TEMP ("radius-admin-push-{0}.txt" -f (Get-Random))
try {
    $p = Start-Process -FilePath $ssh.Source -ArgumentList (($copyArgs | ForEach-Object { ConvertTo-QuotedArgument $_ }) -join ' ') `
        -RedirectStandardInput $item.FullName -RedirectStandardOutput $outFile -NoNewWindow -Wait -PassThru
    $copyOut = Get-Content -LiteralPath $outFile -Raw -ErrorAction SilentlyContinue
} finally {
    Remove-Item -LiteralPath $outFile -ErrorAction SilentlyContinue
}
if ($p.ExitCode -ne 0 -or "$copyOut" -notmatch 'radius-admin-upload-ok') {
    Write-Host ''
    Write-Host "The copy failed (ssh exit $($p.ExitCode))." -ForegroundColor Red
    Write-Host 'Check the login by hand first:'
    $keyHint = if ($IdentityFile) { " -i `"$IdentityFile`" -o IdentitiesOnly=yes" } else { '' }
    Write-Host "    ssh -p $Port$keyHint -o KexAlgorithms=ecdh-sha2-nistp384 -o HostKeyAlgorithms=ecdsa-sha2-nistp384,rsa-sha2-512 -o Ciphers=aes256-gcm@openssh.com $target" -ForegroundColor Yellow
    Write-Host 'If that also closes at once, run it with -v and look at the last lines; or run this'
    Write-Host 'script again with -SshVerbose.'
    exit 1
}

$flags = @()
if ($WithFreeradius) { $flags += '--with-freeradius' }
if ($Force) { $flags += '--force' }
if ($Yes) { $flags += '-y' }

# Runs in your login shell on the server. The SHA-256 is checked before anything from the
# package is executed; update.sh is then run as root and checks it again.
# (No double quotes in this string: Windows PowerShell 5.1 mangles them for native programs.)
$remote = @'
set -e; cd ~; echo '__HASH__  __NAME__' | sha256sum -c --quiet -; t=$(mktemp); tar -xzOf __NAME__ radius-admin/deploy/update.sh > $t; rc=0; sudo bash $t --package ~/__NAME__ --sha256 __HASH__ __FLAGS__ || rc=$?; rm -f $t; exit $rc
'@
$remote = $remote.Trim().Replace('__HASH__', $hash).Replace('__NAME__', $remoteName).Replace('__FLAGS__', ($flags -join ' '))

Write-Host "Installing on $Server (you may be asked for your sudo password)..." -ForegroundColor Cyan
& $ssh.Source @sshArgs -t $target $remote
$rc = $LASTEXITCODE
Write-Host ''
if ($rc -eq 0) {
    Write-Host 'Done.' -ForegroundColor Green
} else {
    Write-Host "The update did not complete (exit $rc). See the messages above." -ForegroundColor Yellow
    Write-Host "The package is still on the server as ~/$remoteName; nothing was switched over."
}
exit $rc
