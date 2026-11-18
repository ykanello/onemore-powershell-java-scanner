
[CmdletBinding(DefaultParameterSetName = "SingleUrl")]
param (
    [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "SingleUrl", ValueFromPipeline = $true)]
    [string[]]$Url,

    [Parameter(Mandatory = $true, ParameterSetName = "FileList")]
    [string]$Path,

    [Parameter(Mandatory = $false)]
    [string]$CsvReport = "Java_Scan_Results.csv"
)

# 1. Gather all target URLs
$targetUrls = [System.Collections.Generic.List[string]]::new()

if ($PSCmdlet.ParameterSetName -eq "FileList") {
    if (-not (Test-Path $Path)) {
        Write-Error "File not found: $Path"
        return
    }
    Get-Content $Path | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#")) {
            if (-not ($line -match '^https?://')) { $line = "https://$line" }
            $targetUrls.Add($line)
        }
    }
} else {
    foreach ($u in $Url) {
        $clean = $u.Trim()
        if ($clean) {
            if (-not ($clean -match '^https?://')) { $clean = "https://$clean" }
            $targetUrls.Add($clean)
        }
    }
}

if ($targetUrls.Count -eq 0) {
    Write-Warning "No valid URLs provided to scan."
    return
}

Write-Host "Loaded $($targetUrls.Count) URL(s) to scan.`n" -ForegroundColor Cyan

$userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

# Helper for HTTP requests
function Invoke-FastRequest {
    param([string]$TargetUrl)
    
    if (Get-Command "curl.exe" -ErrorAction SilentlyContinue) {
        $rawOutput = & curl.exe -i -L -s -k -m 12 -A $userAgent $TargetUrl
        return ($rawOutput -join "`n")
    } else {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        
        $req = [System.Net.HttpWebRequest]::Create($TargetUrl)
        $req.Method = "GET"
        $req.UserAgent = $userAgent
        $req.AllowAutoRedirect = $true
        $req.Timeout = 12000
        
        try {
            $resp = $req.GetResponse()
            $stream = $resp.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($stream)
            $body = $reader.ReadToEnd()
            
            $headers = ""
            foreach ($key in $resp.Headers.AllKeys) {
                $headers += "$key`: $($resp.Headers[$key])`n"
            }
            return "$headers`n`n$body"
        } catch [System.Net.WebException] {
            if ($_.Response) {
                $stream = $_.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($stream)
                return $reader.ReadToEnd()
            }
            throw $_
        }
    }
}

$summaryList = [System.Collections.Generic.List[PSCustomObject]]::new()
$counter = 0

foreach ($target in $targetUrls) {
    $counter++
    Write-Host "[$counter/$($targetUrls.Count)] Checking: $target" -ForegroundColor Yellow

    $detected = $false
    $proofList = [System.Collections.Generic.List[string]]::new()
    $serverBanner = "N/A"

    try {
        # Main request
        $mainResponse = Invoke-FastRequest -TargetUrl $target

        $splitIndex = $mainResponse.IndexOf("`r`n`r`n")
        if ($splitIndex -eq -1) { $splitIndex = $mainResponse.IndexOf("`n`n") }
        
        $headersText = if ($splitIndex -gt 0) { $mainResponse.Substring(0, $splitIndex) } else { "" }
        $bodyText = if ($splitIndex -gt 0) { $mainResponse.Substring($splitIndex) } else { $mainResponse }

        # Server Header
        if ($headersText -match '(?im)^Server:\s*(.*)') {
            $serverBanner = $matches[1].Trim()
            if ($serverBanner -match '(?i)Tomcat|Jetty|JBoss|WildFly|GlassFish|WebLogic|WebSphere|Apache-Coyote|Undertow') {
                $proofList.Add("Server: $serverBanner")
                $detected = $true
            }
        }

        # X-Powered-By
        if ($headersText -match '(?im)^X-Powered-By:\s*(.*)') {
            $poweredBy = $matches[1].Trim()
            if ($poweredBy -match '(?i)Servlet|JSP|JSF|Java|Spring') {
                $proofList.Add("X-Powered-By: $poweredBy")
                $detected = $true
            }
        }

        # JSESSIONID Cookie
        if ($headersText -match '(?im)^Set-Cookie:.*(JSESSIONID=[^;\s\r\n]+)') {
            $proofList.Add("Cookie: $($matches[1])")
            $detected = $true
        }

        # Body patterns
        $javaPatterns = @(
            @{ Label = "JSP endpoint"; Regex = '(?i)/[a-zA-Z0-9_\-\.]+\.jsp(?=[?#"''\s\/>]|$)' },
            @{ Label = "Struts action"; Regex = '(?i)/[a-zA-Z0-9_\-\.]+\.action(?=[?#"''\s\/>]|$)' },
            @{ Label = "Struts/Spring .do"; Regex = '(?i)/[a-zA-Z0-9_\-\.]+\.do(?=[?#"''\s\/>]|$)' },
            @{ Label = "JSF"; Regex = '(?i)javax\.faces(?=[?#"''\s\/>\.]|$)' }
        )

        foreach ($pat in $javaPatterns) {
            if ($bodyText -match $pat.Regex) {
                $proofList.Add("HTML: $($pat.Label) ($($matches[0]))")
                $detected = $true
            }
        }

    } catch {
        $proofList.Add("Error: $($_.Exception.Message)")
    }

    # 404 test probe
    try {
        $test404Url = "$($target.TrimEnd('/'))/probe_$(Get-Random)"
        $errResponse = Invoke-FastRequest -TargetUrl $test404Url

        if ($errResponse -match 'Whitelabel Error Page' -or $errResponse -match 'org\.springframework') {
            $proofList.Add("404: Spring Boot Whitelabel Page")
            $detected = $true
        }
        if ($errResponse -match 'Apache Tomcat' -or $errResponse -match 'org\.apache\.catalina') {
            $proofList.Add("404: Apache Tomcat Error Page")
            $detected = $true
        }
        if ($errResponse -match 'java\.lang\.[A-Za-z0-9]+Exception') {
            $proofList.Add("404: Stack trace ($($matches[0]))")
            $detected = $true
        }
    } catch {
        # ignore probe timeouts
    }

    if ($detected) {
        Write-Host "  -> [!] Java/JVM Detected: $($proofList -join ' | ')" -ForegroundColor Green
    } else {
        Write-Host "  -> [-] No Java detected (Server: $serverBanner)" -ForegroundColor DarkGray
    }

    $summaryList.Add([PSCustomObject]@{
        URL          = $target
        JavaDetected = if ($detected) { "YES" } else { "NO" }
        ServerHeader = $serverBanner
        Evidence     = ($proofList -join " ; ")
    })
}

# Final Table Output
Write-Host "`n=================== SCAN SUMMARY ===================" -ForegroundColor Cyan
$summaryList | Format-Table -AutoSize -Property URL, JavaDetected, ServerHeader, Evidence

# Export to CSV
if ($CsvReport) {
    $summaryList | Export-Csv -Path $CsvReport -NoTypeInformation -Encoding UTF8
    Write-Host "`nDetailed report saved to: $CsvReport" -ForegroundColor Cyan
}
