<#
.SYNOPSIS
    Passive check whether websites look like they run on a Java backend.

.DESCRIPTION
    For every URL two GET requests are sent: the URL itself and a random, non-existent
    path (to provoke an error page). Headers, cookies, page body and the error page are
    checked for Java signs (Tomcat, Jetty, JBoss/WildFly, Spring Boot, Struts, JSF ...).

    Every hit has a weight: strong (3), medium (2) or weak (1). The result is
      YES       strong or medium evidence (or at least two weak hits)
      POSSIBLE  one weak hit only
      NO        nothing found (this is NOT proof that the site is not Java)
      ERROR     the site could not be fetched; the Notes column says why

.PARAMETER Url
    One or more URLs or host names. Also accepts pipeline input.

.PARAMETER Path
    Text file with one URL per line. Empty lines and lines starting with # are ignored.

.PARAMETER CsvReport
    CSV output file. Use an empty string to skip the CSV.

.PARAMETER TimeoutSec
    Timeout per request in seconds (default 12).

.EXAMPLE
    .\Test-WebsiteJavaBackend.ps1 -Url example.com

.EXAMPLE
    "example.com", "example.org" | .\Test-WebsiteJavaBackend.ps1

.EXAMPLE
    .\Test-WebsiteJavaBackend.ps1 -Path .\sites.txt -CsvReport .\results.csv
#>
[CmdletBinding(DefaultParameterSetName = "SingleUrl")]
param (
    [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "SingleUrl", ValueFromPipeline = $true)]
    [string[]]$Url,

    [Parameter(Mandatory = $true, ParameterSetName = "FileList")]
    [string]$Path,

    [Parameter(Mandatory = $false)]
    [string]$CsvReport = "Java_Scan_Results.csv",

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 300)]
    [int]$TimeoutSec = 12
)

begin {
    $targetUrls = [System.Collections.Generic.List[string]]::new()

    $userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    # Browser-like Accept header: Spring Boot only serves its HTML "Whitelabel" error page when HTML is accepted.
    $acceptHeader = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

    # Real curl binary only (not the Windows PowerShell "curl" alias for Invoke-WebRequest).
    $curlCmd = Get-Command -CommandType Application -Name 'curl.exe', 'curl' -ErrorAction SilentlyContinue | Select-Object -First 1
    $curlPath = if ($curlCmd) { $curlCmd.Source } else { $null }

    function Format-TargetUrl {
        param([string]$Raw)
        $clean = $Raw.Trim()
        if (-not $clean) { return $null }
        if ($clean -notmatch '^https?://') { $clean = "https://$clean" }
        return $clean
    }

    function Get-CurlError {
        param([int]$ExitCode)
        switch ($ExitCode) {
            6       { return "DNS lookup failed" }
            7       { return "connection refused" }
            28      { return "timed out" }
            35      { return "TLS handshake failed" }
            47      { return "too many redirects" }
            52      { return "empty reply from server" }
            56      { return "connection reset" }
            60      { return "TLS certificate problem" }
            default { return "curl exit code $ExitCode" }
        }
    }

    function New-FetchResult {
        param(
            [bool]$Ok,
            [string]$ErrorText = "",
            [int]$StatusCode = 0,
            [string]$FinalHeaders = "",
            [string]$AllHeaders = "",
            [string]$Body = ""
        )
        [PSCustomObject]@{
            Ok           = $Ok
            Error        = $ErrorText
            StatusCode   = $StatusCode
            FinalHeaders = $FinalHeaders   # headers of the last response in the redirect chain
            AllHeaders   = $AllHeaders     # headers of every response in the chain (cookies set on redirects count)
            Body         = $Body
        }
    }

    # Fetch one URL. Never throws; a failed request returns Ok = $false with an error text.
    function Invoke-FastRequest {
        param([string]$TargetUrl)

        if ($curlPath) {
            $hdrFile = [System.IO.Path]::GetTempFileName()
            $bodyFile = [System.IO.Path]::GetTempFileName()
            try {
                $code = & $curlPath -s -k -L --max-redirs 10 -m $TimeoutSec -A $userAgent -H "Accept: $acceptHeader" -D $hdrFile -o $bodyFile -w '%{http_code}' $TargetUrl
                $exit = $LASTEXITCODE
                if ($exit -ne 0) {
                    return New-FetchResult -Ok $false -ErrorText (Get-CurlError $exit)
                }

                $status = 0
                [void][int]::TryParse(("$code").Trim(), [ref]$status)

                # -D writes the header block of every hop (redirects included), separated by blank lines.
                $hdrText = [System.IO.File]::ReadAllText($hdrFile)
                $blocks = @($hdrText -split '(?:\r?\n){2,}' | Where-Object { $_ -match '^HTTP/' })
                if ($blocks.Count -eq 0) {
                    return New-FetchResult -Ok $false -ErrorText "no HTTP response received"
                }

                $body = [System.IO.File]::ReadAllText($bodyFile)
                return New-FetchResult -Ok $true -StatusCode $status -FinalHeaders $blocks[-1] -AllHeaders ($blocks -join "`n") -Body $body
            } catch {
                return New-FetchResult -Ok $false -ErrorText $_.Exception.Message
            } finally {
                Remove-Item -LiteralPath $hdrFile, $bodyFile -Force -ErrorAction SilentlyContinue
            }
        }

        # Fallback without curl: .NET HttpWebRequest
        $oldCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        $oldProtocol = [System.Net.ServicePointManager]::SecurityProtocol
        $resp = $null
        try {
            [System.Net.ServicePointManager]::SecurityProtocol = $oldProtocol -bor [System.Net.SecurityProtocolType]::Tls12
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

            $jar = New-Object System.Net.CookieContainer
            $req = [System.Net.HttpWebRequest]::Create($TargetUrl)
            $req.Method = "GET"
            $req.UserAgent = $userAgent
            $req.Accept = $acceptHeader
            $req.AllowAutoRedirect = $true
            $req.MaximumAutomaticRedirections = 10
            $req.Timeout = $TimeoutSec * 1000
            $req.ReadWriteTimeout = $TimeoutSec * 1000
            $req.CookieContainer = $jar

            try {
                $resp = $req.GetResponse()
            } catch [System.Net.WebException] {
                # 4xx/5xx still carry headers and a body, so keep that response.
                if ($_.Exception.Response) { $resp = $_.Exception.Response }
                else { return New-FetchResult -Ok $false -ErrorText $_.Exception.Message }
            }

            $headers = New-Object System.Text.StringBuilder
            [void]$headers.AppendLine("HTTP/1.1 $([int]$resp.StatusCode) $($resp.StatusDescription)")
            foreach ($key in $resp.Headers.AllKeys) {
                foreach ($val in $resp.Headers.GetValues($key)) {
                    [void]$headers.AppendLine("${key}: $val")
                }
            }
            # Cookies collected along the redirect chain
            foreach ($c in $jar.GetCookies($resp.ResponseUri)) {
                [void]$headers.AppendLine("Set-Cookie: $($c.Name)=$($c.Value)")
            }

            $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
            try { $body = $reader.ReadToEnd() } finally { $reader.Dispose() }

            $text = $headers.ToString()
            return New-FetchResult -Ok $true -StatusCode ([int]$resp.StatusCode) -FinalHeaders $text -AllHeaders $text -Body $body
        } catch {
            return New-FetchResult -Ok $false -ErrorText $_.Exception.Message
        } finally {
            if ($resp) { $resp.Close() }
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $oldCallback
            [System.Net.ServicePointManager]::SecurityProtocol = $oldProtocol
        }
    }

    # Random non-existent path below the target path; query string and fragment are dropped.
    function New-ProbeUrl {
        param([string]$Target)
        $ub = New-Object System.UriBuilder($Target)
        $ub.Query = ''
        $ub.Fragment = ''
        $ub.Path = $ub.Path.TrimEnd('/') + '/probe_' + (Get-Random)
        return $ub.Uri.AbsoluteUri
    }

    function Add-Evidence {
        param($List, [string]$Text, [int]$Weight)
        $List.Add([PSCustomObject]@{ Text = $Text; Weight = $Weight })
    }
}

process {
    # Needed so that "a.com","b.com" | .\Test-WebsiteJavaBackend.ps1 scans every item, not only the last.
    if ($PSCmdlet.ParameterSetName -eq "SingleUrl") {
        foreach ($u in $Url) {
            $t = Format-TargetUrl $u
            if ($t) { $targetUrls.Add($t) }
        }
    }
}

end {
    if ($PSCmdlet.ParameterSetName -eq "FileList") {
        if (-not (Test-Path -LiteralPath $Path)) {
            Write-Error "File not found: $Path"
            return
        }
        foreach ($line in (Get-Content -LiteralPath $Path)) {
            $l = $line.Trim()
            if ($l -and -not $l.StartsWith("#")) {
                $t = Format-TargetUrl $l
                if ($t) { $targetUrls.Add($t) }
            }
        }
    }

    if ($targetUrls.Count -eq 0) {
        Write-Warning "No valid URLs provided to scan."
        return
    }

    Write-Host "Loaded $($targetUrls.Count) URL(s) to scan.`n" -ForegroundColor Cyan
    if (-not $curlPath) {
        Write-Host "curl not found: using the .NET HTTP fallback." -ForegroundColor DarkYellow
    }

    $summaryList = [System.Collections.Generic.List[PSCustomObject]]::new()
    $counter = 0

    # Body patterns. Weak on purpose: such strings can also appear in text or links of non-Java sites.
    $javaPatterns = @(
        @{ Label = "JSP endpoint";      Weight = 1; Regex = '(?i)/[a-zA-Z0-9_\-\.]+\.jsp(?=[?#"''\s\/>]|$)' },
        @{ Label = "Struts action";     Weight = 1; Regex = '(?i)/[a-zA-Z0-9_\-\.]+\.action(?=[?#"''\s\/>]|$)' },
        @{ Label = "Struts/Spring .do"; Weight = 1; Regex = '(?i)/[a-zA-Z0-9_\-\.]+\.do(?=[?#"''\s\/>]|$)' },
        @{ Label = "JSF";               Weight = 2; Regex = '(?i)javax\.faces(?=[?#"''\s\/>\.]|$)' }
    )

    foreach ($target in $targetUrls) {
        $counter++
        Write-Host "[$counter/$($targetUrls.Count)] Checking: $target" -ForegroundColor Yellow

        $evidence = [System.Collections.Generic.List[object]]::new()
        $notes = [System.Collections.Generic.List[string]]::new()
        $serverBanner = "N/A"
        $httpStatus = ""
        $failed = $false

        try {
            $main = Invoke-FastRequest -TargetUrl $target

            if (-not $main.Ok) {
                $failed = $true
                $notes.Add("Request failed: $($main.Error)")
            } else {
                $httpStatus = $main.StatusCode

                # Headers: the final response decides; cookies set on any hop of a redirect chain count.
                $finalHeaders = $main.FinalHeaders
                $allHeaders = $main.AllHeaders

                if ($finalHeaders -match '(?im)^Server:\s*(.*)') {
                    $serverBanner = $matches[1].Trim()
                } elseif ($allHeaders -match '(?im)^Server:\s*(.*)') {
                    $serverBanner = $matches[1].Trim()
                }
                if ($serverBanner -match '(?i)Tomcat|Jetty|JBoss|WildFly|GlassFish|WebLogic|WebSphere|Apache-Coyote|Undertow') {
                    Add-Evidence $evidence "Server: $serverBanner" 3
                }

                if ($finalHeaders -match '(?im)^X-Powered-By:\s*(.*)') {
                    $poweredBy = $matches[1].Trim()
                    if ($poweredBy -match '(?i)Servlet|JSP|JSF|Java|Spring') {
                        Add-Evidence $evidence "X-Powered-By: $poweredBy" 3
                    }
                }

                if ($allHeaders -match '(?im)^Set-Cookie:.*(JSESSIONID=[^;\s\r\n]+)') {
                    Add-Evidence $evidence "Cookie: $($matches[1])" 3
                }

                foreach ($pat in $javaPatterns) {
                    if ($main.Body -match $pat.Regex) {
                        $hit = $matches[0]
                        if ($hit.Length -gt 60) { $hit = $hit.Substring(0, 60) }
                        Add-Evidence $evidence "HTML: $($pat.Label) ($hit)" $pat.Weight
                    }
                }

                # 404 probe: only a real error response (HTTP >= 400) counts. A site that answers every
                # unknown path with its normal page (soft 404) would otherwise produce false positives.
                try {
                    $probe = Invoke-FastRequest -TargetUrl (New-ProbeUrl -Target $target)
                    if (-not $probe.Ok) {
                        $notes.Add("404 probe failed: $($probe.Error); error-page checks skipped")
                    } elseif ($probe.StatusCode -lt 400) {
                        $notes.Add("404 probe returned HTTP $($probe.StatusCode) (soft 404); error-page checks skipped")
                    } else {
                        $errText = "$($probe.FinalHeaders)`n$($probe.Body)"

                        if ($errText -match 'Whitelabel Error Page') {
                            Add-Evidence $evidence "404: Spring Boot Whitelabel Page" 3
                        }
                        if ($probe.StatusCode -eq 404 -and
                            $errText -match '"timestamp"\s*:' -and
                            $errText -match '"error"\s*:\s*"Not Found"' -and
                            $errText -match '"path"\s*:') {
                            Add-Evidence $evidence "404: Spring Boot JSON error body" 2
                        }
                        if ($errText -match 'Apache Tomcat|org\.apache\.catalina') {
                            Add-Evidence $evidence "404: Apache Tomcat Error Page" 3
                        }
                        if ($errText -match 'org\.springframework') {
                            Add-Evidence $evidence "404: org.springframework in error page" 2
                        }
                        if ($errText -match 'java\.lang\.[A-Za-z0-9]+Exception') {
                            Add-Evidence $evidence "404: Stack trace ($($matches[0]))" 2
                        }
                    }
                } catch {
                    $notes.Add("404 probe error: $($_.Exception.Message)")
                }
            }
        } catch {
            $failed = $true
            $notes.Add("Error: $($_.Exception.Message)")
        }

        # Verdict
        $maxWeight = 0
        if ($evidence.Count -gt 0) {
            $maxWeight = ($evidence | Measure-Object -Property Weight -Maximum).Maximum
        }
        $weakCount = @($evidence | Where-Object { $_.Weight -eq 1 }).Count

        if ($failed) {
            $verdict = "ERROR"; $confidence = "-"
        } elseif ($maxWeight -ge 3) {
            $verdict = "YES"; $confidence = "HIGH"
        } elseif ($maxWeight -eq 2 -or $weakCount -ge 2) {
            $verdict = "YES"; $confidence = "MEDIUM"
        } elseif ($weakCount -eq 1) {
            $verdict = "POSSIBLE"; $confidence = "LOW"
        } else {
            $verdict = "NO"; $confidence = "-"
        }

        $evidenceText = ($evidence | ForEach-Object { $_.Text }) -join " ; "
        $notesText = $notes -join " ; "

        switch ($verdict) {
            "YES"      { Write-Host "  -> [!] Java/JVM detected ($confidence): $evidenceText" -ForegroundColor Green }
            "POSSIBLE" { Write-Host "  -> [?] Possible Java (weak evidence only): $evidenceText" -ForegroundColor DarkYellow }
            "ERROR"    { Write-Host "  -> [x] Not scanned: $notesText" -ForegroundColor Red }
            default    { Write-Host "  -> [-] No Java signs found (Server: $serverBanner). This is not proof that the site is not Java." -ForegroundColor DarkGray }
        }
        if ($verdict -ne "ERROR" -and $notesText) {
            Write-Host "     Note: $notesText" -ForegroundColor DarkGray
        }

        $summaryList.Add([PSCustomObject]@{
            URL          = $target
            JavaDetected = $verdict
            Confidence   = $confidence
            HttpStatus   = $httpStatus
            ServerHeader = $serverBanner
            Evidence     = $evidenceText
            Notes        = $notesText
        })
    }

    # Final Table Output
    Write-Host "`n=================== SCAN SUMMARY ===================" -ForegroundColor Cyan
    $summaryList | Format-Table -Wrap -Property URL, JavaDetected, Confidence, HttpStatus, ServerHeader, Evidence, Notes

    # Export to CSV
    if ($CsvReport) {
        $summaryList | Export-Csv -Path $CsvReport -NoTypeInformation -Encoding UTF8
        Write-Host "`nDetailed report saved to: $CsvReport" -ForegroundColor Cyan
    }
}
