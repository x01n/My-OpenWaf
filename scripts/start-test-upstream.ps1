param(
    [string]$Bind = "127.0.0.1:8800",
    [int]$Status = 200,
    [string]$Body = "OK`n",
    [string]$ContentType = "text/plain; charset=utf-8",
    [int]$DelayMs = 0,
    [switch]$Background
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
if (-not $root) { $root = (Get-Location).Path }

$tempDir = Join-Path $root "temp"
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null

$serverDir = Join-Path $tempDir "_test-upstream-server"
New-Item -ItemType Directory -Force -Path $serverDir | Out-Null

$sourcePath = Join-Path $serverDir "main.go"
$exePath = Join-Path $tempDir "test-upstream-server.exe"
$stdoutPath = Join-Path $tempDir "test-upstream-server.out.log"
$stderrPath = Join-Path $tempDir "test-upstream-server.err.log"

function Get-BindInfo {
    param([string]$Value)

    if ($Value -match '^\[(.+)\]:(\d+)$') {
        $listenHost = $Matches[1]
        $port = [int]$Matches[2]
    }
    elseif ($Value -match '^:(\d+)$') {
        $listenHost = ""
        $port = [int]$Matches[1]
    }
    elseif ($Value -match '^(.+):(\d+)$') {
        $listenHost = $Matches[1]
        $port = [int]$Matches[2]
    }
    else {
        throw "Bind must use host:port, [ipv6]:port, or :port. Got: $Value"
    }

    $connectHost = $listenHost
    if ($connectHost -eq "" -or $connectHost -eq "0.0.0.0" -or $connectHost -eq "::") {
        $connectHost = "127.0.0.1"
    }

    [PSCustomObject]@{
        ListenHost  = $listenHost
        ConnectHost = $connectHost
        Port        = $port
        Url         = "http://$($connectHost):$port"
    }
}

function Test-TcpReady {
    param(
        [string]$HostName,
        [int]$Port,
        [int]$TimeoutMs = 800
    )

    $client = $null
    try {
        $client = [System.Net.Sockets.TcpClient]::new()
        $task = $client.ConnectAsync($HostName, $Port)
        if (-not $task.Wait($TimeoutMs)) {
            return $false
        }
        if ($task.IsFaulted -or $task.IsCanceled) {
            return $false
        }
        return $client.Connected
    }
    catch {
        return $false
    }
    finally {
        if ($client -ne $null) {
            $client.Dispose()
        }
    }
}

function Test-HTTPReady {
    param(
        [string]$Url,
        [int]$TimeoutSec = 2
    )

    try {
        $null = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec $TimeoutSec -Headers @{ Connection = "close" }
        return $true
    }
    catch [System.Net.WebException] {
        if ($_.Exception.Response -ne $null) {
            $_.Exception.Response.Close()
            return $true
        }
        return $false
    }
    catch {
        return $false
    }
}

function Get-ListenPid {
    param([int]$Port)

    $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $conn) {
        return $null
    }
    return $conn.OwningProcess
}

function Get-ProcessNameById {
    param([object]$PidValue)

    if ($null -eq $PidValue) {
        return ""
    }
    $proc = Get-Process -Id $PidValue -ErrorAction SilentlyContinue
    if ($null -eq $proc) {
        return ""
    }
    return $proc.ProcessName
}

function ConvertTo-ProcessArgumentString {
    param([string[]]$Items)

    $quoted = foreach ($item in $Items) {
        if ($null -eq $item) {
            $item = ""
        }
        '"' + ($item -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
    }
    return ($quoted -join " ")
}

$bindInfo = Get-BindInfo -Value $Bind
$listenPid = Get-ListenPid -Port $bindInfo.Port
$listenProcessName = Get-ProcessNameById -PidValue $listenPid
$readyHTTP = Test-HTTPReady -Url $bindInfo.Url
$readyExistingUpstream = $readyHTTP -or ((Test-TcpReady -HostName $bindInfo.ConnectHost -Port $bindInfo.Port) -and $listenProcessName -eq "test-upstream-server")
if ($Background -and $readyExistingUpstream) {
    [PSCustomObject]@{
        Pid    = $listenPid
        Bind   = $Bind
        Url    = $bindInfo.Url
        Stdout = $stdoutPath
        Stderr = $stderrPath
        Reused = $true
    }
    return
}

$source = @'
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func main() {
	bind := flag.String("bind", "127.0.0.1:8800", "listen address")
	status := flag.Int("status", 200, "response status code")
	body := flag.String("body", "OK\n", "response body")
	contentType := flag.String("content-type", "text/plain; charset=utf-8", "response content type")
	delayMs := flag.Int("delay-ms", 0, "per-request delay in milliseconds")
	flag.Parse()

	payload := []byte(*body)
	delay := time.Duration(*delayMs) * time.Millisecond

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
		}
		if delay > 0 {
			time.Sleep(delay)
		}
		w.Header().Set("Content-Type", *contentType)
		w.Header().Set("X-Test-Upstream", "my-openwaf")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		w.WriteHeader(*status)
		if r.Method != http.MethodHead && len(payload) > 0 {
			_, _ = w.Write(payload)
		}
	})

	server := &http.Server{
		Addr:              *bind,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("test upstream listening on http://%s status=%d body_bytes=%d delay_ms=%d", *bind, *status, len(payload), *delayMs)
		errCh <- server.ListenAndServe()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("received %s, shutting down", sig)
		_ = server.Close()
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
'@

[System.IO.File]::WriteAllText($sourcePath, $source, [System.Text.UTF8Encoding]::new($false))

Push-Location $root
try {
    go build -o $exePath $sourcePath
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    Pop-Location
}

$argsList = @(
    "-bind", $Bind,
    "-status", $Status.ToString(),
    "-body", $Body,
    "-content-type", $ContentType,
    "-delay-ms", $DelayMs.ToString()
)

if ($Background) {
    $p = Start-Process -FilePath $exePath -ArgumentList (ConvertTo-ProcessArgumentString -Items $argsList) -WorkingDirectory $root -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -WindowStyle Hidden -PassThru
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ((Test-TcpReady -HostName $bindInfo.ConnectHost -Port $bindInfo.Port -TimeoutMs 200) -and (Test-HTTPReady -Url $bindInfo.Url -TimeoutSec 1)) {
            break
        }
        if ($p.HasExited) {
            throw "test upstream exited early with code $($p.ExitCode). stderr: $stderrPath"
        }
        Start-Sleep -Milliseconds 100
    }
    if (-not (Test-HTTPReady -Url $bindInfo.Url -TimeoutSec 1)) {
        throw "test upstream did not become ready at $($bindInfo.Url). stderr: $stderrPath"
    }
    [PSCustomObject]@{
        Pid    = $p.Id
        Bind   = $Bind
        Url    = $bindInfo.Url
        Stdout = $stdoutPath
        Stderr = $stderrPath
        Reused = $false
    }
    return
}

& $exePath @argsList
