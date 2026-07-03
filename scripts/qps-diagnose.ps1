param(
    [string]$TargetUrl = "http://127.0.0.1/",
    [string]$MetricsUrl = "http://127.0.0.1:9443/metrics",
    [int]$Requests = 1000,
    [int]$Concurrency = 40,
    [string]$Method = "GET",
    [string[]]$Header = @(),
    [string[]]$MetricsHeader = @(),
    [string]$Body = "",
    [int]$TimeoutSec = 30,
    [switch]$SkipLoad,
    [switch]$CompileOnly,
    [switch]$SelfTest
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
if (-not $root) { $root = (Get-Location).Path }

$tempDir = Join-Path $root "temp"
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null

$loaderDir = Join-Path $tempDir "_qps-diagnose-loader"
New-Item -ItemType Directory -Force -Path $loaderDir | Out-Null

$sourcePath = Join-Path $loaderDir "main.go"
$exePath = Join-Path $tempDir "qps-diagnose-loader.exe"

function Write-LoaderSource {
    param([string]$Path)

    $source = @'
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type repeatedFlags []string

func (r *repeatedFlags) String() string {
	return strings.Join(*r, ",")
}

func (r *repeatedFlags) Set(value string) error {
	*r = append(*r, value)
	return nil
}

type headerPair struct {
	name  string
	value string
}

type summary struct {
	TargetURL    string  `json:"target_url"`
	Method       string  `json:"method"`
	Requests     int     `json:"requests"`
	Concurrency  int     `json:"concurrency"`
	Completed    int64   `json:"completed"`
	Errors       int64   `json:"errors"`
	Status2xx    int64   `json:"status_2xx"`
	Status3xx    int64   `json:"status_3xx"`
	Status4xx    int64   `json:"status_4xx"`
	Status5xx    int64   `json:"status_5xx"`
	StatusOther  int64   `json:"status_other"`
	DurationMs   int64   `json:"duration_ms"`
	RPS          float64 `json:"rps"`
	LatencyP50Ms float64 `json:"latency_p50_ms"`
	LatencyP95Ms float64 `json:"latency_p95_ms"`
	LatencyP99Ms float64 `json:"latency_p99_ms"`
	LatencyMaxMs float64 `json:"latency_max_ms"`
}

func main() {
	var headers repeatedFlags
	targetURL := flag.String("url", "http://127.0.0.1/", "target URL")
	method := flag.String("method", "GET", "HTTP method")
	requests := flag.Int("requests", 1000, "total request count")
	concurrency := flag.Int("concurrency", 40, "worker count")
	body := flag.String("body", "", "request body")
	timeoutSec := flag.Int("timeout-sec", 30, "per-request timeout in seconds")
	flag.Var(&headers, "header", "HTTP header, formatted as 'Name: value'")
	flag.Parse()

	if strings.TrimSpace(*targetURL) == "" {
		exitf("url is required")
	}
	if *requests < 0 {
		exitf("requests must be >= 0")
	}
	if *concurrency <= 0 {
		exitf("concurrency must be > 0")
	}
	if *timeoutSec <= 0 {
		exitf("timeout-sec must be > 0")
	}

	headerPairs, err := parseHeaders(headers)
	if err != nil {
		exitf("%v", err)
	}

	result := runLoad(*targetURL, strings.ToUpper(strings.TrimSpace(*method)), *requests, *concurrency, []byte(*body), time.Duration(*timeoutSec)*time.Second, headerPairs)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		exitf("encode result: %v", err)
	}
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func parseHeaders(values []string) ([]headerPair, error) {
	pairs := make([]headerPair, 0, len(values))
	for _, raw := range values {
		idx := strings.Index(raw, ":")
		if idx <= 0 {
			return nil, fmt.Errorf("header must use 'Name: value': %q", raw)
		}
		name := strings.TrimSpace(raw[:idx])
		value := strings.TrimSpace(raw[idx+1:])
		if name == "" {
			return nil, fmt.Errorf("header name is empty: %q", raw)
		}
		pairs = append(pairs, headerPair{name: name, value: value})
	}
	return pairs, nil
}

func runLoad(targetURL string, method string, requests int, concurrency int, body []byte, timeout time.Duration, headers []headerPair) summary {
	if requests == 0 {
		return summary{TargetURL: targetURL, Method: method, Requests: requests, Concurrency: concurrency}
	}
	if concurrency > requests {
		concurrency = requests
	}

	transport := &http.Transport{
		MaxIdleConns:        concurrency * 4,
		MaxIdleConnsPerHost: concurrency * 4,
		DisableCompression:  true,
		ForceAttemptHTTP2:   true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
	defer transport.CloseIdleConnections()

	var completed atomic.Int64
	var errorsCount atomic.Int64
	var status2xx atomic.Int64
	var status3xx atomic.Int64
	var status4xx atomic.Int64
	var status5xx atomic.Int64
	var statusOther atomic.Int64

	latencies := make([]int64, requests)
	jobs := make(chan int)
	var wg sync.WaitGroup

	startedAt := time.Now()
	for worker := 0; worker < concurrency; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				start := time.Now()
				req, err := http.NewRequest(method, targetURL, bytes.NewReader(body))
				if err != nil {
					errorsCount.Add(1)
					continue
				}
				for _, header := range headers {
					req.Header.Set(header.name, header.value)
				}
				resp, err := client.Do(req)
				elapsed := time.Since(start).Microseconds()
				latencies[idx] = elapsed
				if err != nil {
					errorsCount.Add(1)
					continue
				}
				if resp.Body != nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
				}
				completed.Add(1)
				switch {
				case resp.StatusCode >= 200 && resp.StatusCode < 300:
					status2xx.Add(1)
				case resp.StatusCode >= 300 && resp.StatusCode < 400:
					status3xx.Add(1)
				case resp.StatusCode >= 400 && resp.StatusCode < 500:
					status4xx.Add(1)
				case resp.StatusCode >= 500 && resp.StatusCode < 600:
					status5xx.Add(1)
				default:
					statusOther.Add(1)
				}
			}
		}()
	}

	for idx := 0; idx < requests; idx++ {
		jobs <- idx
	}
	close(jobs)
	wg.Wait()
	duration := time.Since(startedAt)

	values := make([]int64, 0, requests)
	for _, latency := range latencies {
		if latency > 0 {
			values = append(values, latency)
		}
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })

	rps := 0.0
	if duration > 0 {
		rps = float64(requests) / duration.Seconds()
	}

	return summary{
		TargetURL:    targetURL,
		Method:       method,
		Requests:     requests,
		Concurrency:  concurrency,
		Completed:    completed.Load(),
		Errors:       errorsCount.Load(),
		Status2xx:    status2xx.Load(),
		Status3xx:    status3xx.Load(),
		Status4xx:    status4xx.Load(),
		Status5xx:    status5xx.Load(),
		StatusOther:  statusOther.Load(),
		DurationMs:   duration.Milliseconds(),
		RPS:          rps,
		LatencyP50Ms: percentileMs(values, 50),
		LatencyP95Ms: percentileMs(values, 95),
		LatencyP99Ms: percentileMs(values, 99),
		LatencyMaxMs: percentileMs(values, 100),
	}
}

func percentileMs(values []int64, percentile float64) float64 {
	if len(values) == 0 {
		return 0
	}
	if percentile <= 0 {
		return float64(values[0]) / 1000.0
	}
	if percentile >= 100 {
		return float64(values[len(values)-1]) / 1000.0
	}
	index := int(math.Ceil((percentile / 100.0) * float64(len(values)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(values) {
		index = len(values) - 1
	}
	return float64(values[index]) / 1000.0
}
'@

    [System.IO.File]::WriteAllText($Path, $source, [System.Text.UTF8Encoding]::new($false))
}

function ConvertTo-HeaderMap {
    param([string[]]$Items)

    $map = @{}
    foreach ($item in $Items) {
        $idx = $item.IndexOf(":")
        if ($idx -le 0) {
            throw "Header must use 'Name: value'. Got: $item"
        }
        $name = $item.Substring(0, $idx).Trim()
        $value = $item.Substring($idx + 1).Trim()
        if ($name -eq "") {
            throw "Header name is empty. Got: $item"
        }
        $map[$name] = $value
    }
    return $map
}

function Get-MetricsText {
    param(
        [string]$Url,
        [hashtable]$Headers,
        [int]$Timeout
    )

    $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -Headers $Headers -TimeoutSec $Timeout
    return [string]$response.Content
}

function ConvertFrom-PrometheusText {
    param([string]$Text)

    $map = @{}
    foreach ($line in ($Text -split "`r?`n")) {
        $trimmed = $line.Trim()
        if ($trimmed -eq "" -or $trimmed.StartsWith("#")) {
            continue
        }
        if ($trimmed -match '^([a-zA-Z_:][a-zA-Z0-9_:]*(?:\{[^}]*\})?)\s+([-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?|\+Inf|-Inf|Inf|NaN)\b') {
            $key = $Matches[1]
            $rawValue = $Matches[2]
            if ($rawValue -eq "+Inf" -or $rawValue -eq "Inf") {
                $map[$key] = [double]::PositiveInfinity
            }
            elseif ($rawValue -eq "-Inf") {
                $map[$key] = [double]::NegativeInfinity
            }
            elseif ($rawValue -eq "NaN") {
                $map[$key] = [double]::NaN
            }
            else {
                $map[$key] = [double]::Parse($rawValue, [System.Globalization.CultureInfo]::InvariantCulture)
            }
        }
    }
    return $map
}

function Get-MetricValue {
    param(
        [hashtable]$Map,
        [string]$Key
    )

    if ($Map.ContainsKey($Key)) {
        return [double]$Map[$Key]
    }
    return $null
}

function ConvertTo-DisplayNumber {
    param([object]$Value)

    if ($null -eq $Value) {
        return $null
    }
    if ([double]::IsInfinity([double]$Value) -or [double]::IsNaN([double]$Value)) {
        return [string]$Value
    }
    return [math]::Round([double]$Value, 3)
}

function New-MetricRows {
    param(
        [hashtable]$Before,
        [hashtable]$After
    )

    $metrics = @(
        @{ Key = 'openwaf_dataplane_qps{window="1s"}'; Name = "dataplane_qps_1s" },
        @{ Key = 'openwaf_dataplane_qps{window="5s"}'; Name = "dataplane_qps_5s" },
        @{ Key = "openwaf_dataplane_requests_total"; Name = "dataplane_requests_total" },
        @{ Key = 'openwaf_dataplane_status_total{class="2xx"}'; Name = "dataplane_status_2xx" },
        @{ Key = 'openwaf_dataplane_status_total{class="4xx"}'; Name = "dataplane_status_4xx" },
        @{ Key = 'openwaf_dataplane_status_total{class="5xx"}'; Name = "dataplane_status_5xx" },
        @{ Key = 'openwaf_dataplane_waf_actions_total{action="block"}'; Name = "waf_blocks" },
        @{ Key = 'openwaf_dataplane_waf_actions_total{action="observe"}'; Name = "waf_observes" },
        @{ Key = "openwaf_writer_flushes_total"; Name = "writer_flushes_total" },
        @{ Key = "openwaf_writer_flush_errors_total"; Name = "writer_flush_errors_total" },
        @{ Key = "openwaf_writer_last_flush_records"; Name = "writer_last_flush_records" },
        @{ Key = "openwaf_writer_last_flush_duration_ms"; Name = "writer_last_flush_duration_ms" },
        @{ Key = 'openwaf_writer_queue_len{type="security_event"}'; Name = "writer_queue_security_event" },
        @{ Key = 'openwaf_writer_queue_len{type="access_log"}'; Name = "writer_queue_access_log" },
        @{ Key = 'openwaf_writer_queue_len{type="drop_event"}'; Name = "writer_queue_drop_event" },
        @{ Key = 'openwaf_writer_queue_len{type="bot_score"}'; Name = "writer_queue_bot_score" },
        @{ Key = 'openwaf_writer_dropped_total{type="security_event"}'; Name = "writer_dropped_security_event" },
        @{ Key = 'openwaf_writer_dropped_total{type="access_log"}'; Name = "writer_dropped_access_log" },
        @{ Key = 'openwaf_writer_dropped_total{type="drop_event"}'; Name = "writer_dropped_drop_event" },
        @{ Key = 'openwaf_writer_dropped_total{type="bot_score"}'; Name = "writer_dropped_bot_score" },
        @{ Key = "openwaf_upstream_healthy_total"; Name = "upstream_healthy_total" },
        @{ Key = "openwaf_upstream_unhealthy_total"; Name = "upstream_unhealthy_total" },
        @{ Key = "openwaf_upstream_known_total"; Name = "upstream_known_total" },
        @{ Key = "openwaf_upstream_checked_total"; Name = "upstream_checked_total" },
        @{ Key = "openwaf_upstream_average_latency_ms"; Name = "upstream_average_latency_ms" },
        @{ Key = "openwaf_upstream_max_last_latency_ms"; Name = "upstream_max_last_latency_ms" },
        @{ Key = "openwaf_upstream_latency_samples_total"; Name = "upstream_latency_samples_total" }
    )

    foreach ($metric in $metrics) {
        $beforeValue = Get-MetricValue -Map $Before -Key $metric.Key
        $afterValue = Get-MetricValue -Map $After -Key $metric.Key
        $delta = $null
        if ($null -ne $beforeValue -and $null -ne $afterValue) {
            $delta = [double]$afterValue - [double]$beforeValue
        }
        [PSCustomObject]@{
            Metric = $metric.Name
            Before = ConvertTo-DisplayNumber $beforeValue
            After = ConvertTo-DisplayNumber $afterValue
            Delta = ConvertTo-DisplayNumber $delta
        }
    }
}

function Get-DiagnosticHints {
    param(
        [object]$LoadSummary,
        [object[]]$MetricRows
    )

    $hints = New-Object System.Collections.Generic.List[string]
    $rowByMetric = @{}
    foreach ($row in $MetricRows) {
        $rowByMetric[$row.Metric] = $row
    }

    if ($null -ne $LoadSummary -and $LoadSummary.requests -gt 0) {
        $errorRate = 0.0
        if ($LoadSummary.requests -gt 0) {
            $errorRate = [double]$LoadSummary.errors / [double]$LoadSummary.requests
        }
        if ($errorRate -gt 0.01) {
            $hints.Add("load_errors_detected: request errors are above 1 percent")
        }
    }

    foreach ($metric in @("writer_dropped_security_event", "writer_dropped_access_log", "writer_dropped_drop_event", "writer_dropped_bot_score")) {
        if ($rowByMetric.ContainsKey($metric) -and $null -ne $rowByMetric[$metric].Delta -and [double]$rowByMetric[$metric].Delta -gt 0) {
            $hints.Add("writer_drops_detected: $metric increased by $($rowByMetric[$metric].Delta)")
        }
    }

    if ($rowByMetric.ContainsKey("writer_flush_errors_total") -and $null -ne $rowByMetric["writer_flush_errors_total"].Delta -and [double]$rowByMetric["writer_flush_errors_total"].Delta -gt 0) {
        $hints.Add("writer_flush_errors_detected: writer flush errors increased")
    }

    if ($rowByMetric.ContainsKey("upstream_unhealthy_total") -and $null -ne $rowByMetric["upstream_unhealthy_total"].After -and [double]$rowByMetric["upstream_unhealthy_total"].After -gt 0) {
        $hints.Add("upstream_unhealthy_detected: one or more upstream targets are unhealthy")
    }

    if ($rowByMetric.ContainsKey("upstream_average_latency_ms") -and $null -ne $rowByMetric["upstream_average_latency_ms"].After -and [double]$rowByMetric["upstream_average_latency_ms"].After -gt 1000) {
        $hints.Add("upstream_latency_high: upstream average latency is above 1000 ms")
    }

    if ($hints.Count -eq 0) {
        $hints.Add("no_immediate_metrics_alarm: inspect RPS, latency, status codes, and pprof for the next split")
    }
    return $hints
}

Write-LoaderSource -Path $sourcePath

if ($SelfTest) {
    $beforeMetrics = ConvertFrom-PrometheusText -Text @'
openwaf_dataplane_qps{window="1s"} 1.5
openwaf_dataplane_qps{window="5s"} 1.25
openwaf_dataplane_requests_total 42
openwaf_writer_flush_errors_total 0
openwaf_upstream_unhealthy_total 0
openwaf_upstream_average_latency_ms 25
openwaf_upstream_max_last_latency_ms 40
'@
    $afterMetrics = ConvertFrom-PrometheusText -Text @'
openwaf_dataplane_qps{window="1s"} 4
openwaf_dataplane_qps{window="5s"} 3
openwaf_dataplane_requests_total 54
openwaf_writer_flush_errors_total 1
openwaf_upstream_unhealthy_total 0
openwaf_upstream_average_latency_ms 30
openwaf_upstream_max_last_latency_ms 45
'@
    $rows = @(New-MetricRows -Before $beforeMetrics -After $afterMetrics)
    $requestsRow = $rows | Where-Object { $_.Metric -eq "dataplane_requests_total" } | Select-Object -First 1
    $qpsRow = $rows | Where-Object { $_.Metric -eq "dataplane_qps_1s" } | Select-Object -First 1
    $flushErrorRow = $rows | Where-Object { $_.Metric -eq "writer_flush_errors_total" } | Select-Object -First 1
    if ($null -eq $requestsRow -or [double]$requestsRow.Delta -ne 12) {
        throw "SelfTest failed: dataplane_requests_total delta mismatch"
    }
    if ($null -eq $qpsRow -or [double]$qpsRow.After -ne 4) {
        throw "SelfTest failed: dataplane_qps_1s after mismatch"
    }
    if ($null -eq $flushErrorRow -or [double]$flushErrorRow.Delta -ne 1) {
        throw "SelfTest failed: writer_flush_errors_total delta mismatch"
    }
    [PSCustomObject]@{
        Status = "self-test passed"
        Rows   = $rows.Count
    }
    return
}

if ($CompileOnly) {
    Push-Location $root
    try {
        & go build -o $exePath $sourcePath
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    finally {
        Pop-Location
    }
    [PSCustomObject]@{
        Source = $sourcePath
        Binary = $exePath
        Status = "compiled"
    }
    return
}

$metricsHeaders = ConvertTo-HeaderMap -Items $MetricsHeader

try {
    $beforeText = Get-MetricsText -Url $MetricsUrl -Headers $metricsHeaders -Timeout $TimeoutSec
}
catch {
    throw "无法读取 MetricsUrl $MetricsUrl：$($_.Exception.Message)"
}
$beforeMetrics = ConvertFrom-PrometheusText -Text $beforeText

$loadSummary = $null
$loadError = $null
if (-not $SkipLoad) {
    Push-Location $root
    try {
        & go build -o $exePath $sourcePath
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    finally {
        Pop-Location
    }

    $loaderArgs = @(
        "-url", $TargetUrl,
        "-method", $Method,
        "-requests", $Requests.ToString(),
        "-concurrency", $Concurrency.ToString(),
        "-timeout-sec", $TimeoutSec.ToString()
    )
    if ($Body -ne "") {
        $loaderArgs += @("-body", $Body)
    }
    foreach ($item in $Header) {
        $loaderArgs += @("-header", $item)
    }
    Push-Location $root
    try {
        $jsonText = (& $exePath @loaderArgs 2>&1) -join "`n"
        if ($LASTEXITCODE -ne 0) {
            $loadError = "压测执行失败，退出码 $LASTEXITCODE：$($jsonText.Trim())"
        }
        elseif (-not [string]::IsNullOrWhiteSpace($jsonText)) {
            $loadSummary = $jsonText | ConvertFrom-Json
        }
        else {
            $loadError = "压测执行失败，未返回可解析的 JSON 结果"
        }
    }
    finally {
        Pop-Location
    }
}

Start-Sleep -Milliseconds 500
try {
    $afterText = Get-MetricsText -Url $MetricsUrl -Headers $metricsHeaders -Timeout $TimeoutSec
}
catch {
    throw "无法重新读取 MetricsUrl $MetricsUrl：$($_.Exception.Message)"
}
$afterMetrics = ConvertFrom-PrometheusText -Text $afterText
$rows = @(New-MetricRows -Before $beforeMetrics -After $afterMetrics)
$hints = @(Get-DiagnosticHints -LoadSummary $loadSummary -MetricRows $rows)

if ($null -ne $loadSummary) {
    "Load summary"
    $loadSummary | Format-List
}
elseif ($loadError) {
    "Load error"
    $loadError
}

"Metric delta"
$rows | Format-Table -AutoSize

"Diagnostic hints"
foreach ($hint in $hints) {
    "- $hint"
}
