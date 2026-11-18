# onemore-powershell-java-scanner

A small PowerShell script, `Test-WebsiteJavaBackend.ps1`, that checks whether a website **looks like** it is served by a Java backend (Tomcat, Jetty, JBoss/WildFly, Spring Boot, Struts, JSF and similar).

It is a passive fingerprinting tool: for each URL it makes two plain `GET` requests and looks for tell-tale signs in the response. It does not log in, submit forms, fuzz or exploit anything.

> **Only scan sites you own or are allowed to test.**

## How it works

For each target the script sends two requests:

1. **The URL itself.** It looks at:
   | Signal | What counts as evidence | Weight |
   |---|---|---|
   | `Server` header (final response) | Tomcat, Jetty, JBoss, WildFly, GlassFish, WebLogic, WebSphere, Apache-Coyote, Undertow | strong |
   | `X-Powered-By` header | Servlet, JSP, JSF, Java, Spring | strong |
   | `Set-Cookie` header on **any** hop of a redirect chain | a `JSESSIONID` cookie | strong |
   | Page body | `javax.faces` (JSF) | medium |
   | Page body | links to `*.jsp`, `*.action` (Struts), `*.do` (Struts/Spring) | weak |
2. **A random, non-existent path** (`/probe_<random number>` below the path you gave, without its query string). Only if the answer is a real error (HTTP 400 or higher) it is searched for the Spring Boot "Whitelabel Error Page" (strong), the Apache Tomcat error page / `org.apache.catalina` (strong), the Spring Boot JSON error body (medium), `org.springframework` (medium) and `java.lang.*Exception` stack traces (medium). If the site answers an unknown path with HTTP 200 (a "soft 404"), these checks are skipped and a note is added, so a normal page that merely mentions Java is not counted.

Both requests send a browser-like `Accept` header, because Spring Boot only shows its HTML error page when HTML is accepted.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+.
- `curl` (`curl.exe` on Windows, which ships with Windows 10 and later) is used when it is on the `PATH`. Otherwise the script falls back to .NET `HttpWebRequest`.

## Usage

```powershell
# One URL (https:// is added if you leave the scheme out)
.\Test-WebsiteJavaBackend.ps1 -Url example.com

# Several URLs
.\Test-WebsiteJavaBackend.ps1 -Url example.com, https://example.org

# A list from a file: one URL per line, blank lines and lines starting with # are ignored
.\Test-WebsiteJavaBackend.ps1 -Path .\sites.txt

# Pipe URLs in
"example.com", "example.org" | .\Test-WebsiteJavaBackend.ps1

# Choose the CSV report name (default: Java_Scan_Results.csv)
.\Test-WebsiteJavaBackend.ps1 -Path .\sites.txt -CsvReport .\results.csv
```

Example `sites.txt`:

```text
# my sites
example.com
https://example.org/app
```

### Parameters

| Parameter | Description |
|---|---|
| `-Url` | One or more URLs or host names (parameter set `SingleUrl`, position 0). |
| `-Path` | Text file with one URL per line (parameter set `FileList`). |
| `-CsvReport` | CSV output path. Default `Java_Scan_Results.csv`. Pass an empty string to skip the CSV. |
| `-TimeoutSec` | Timeout per request in seconds. Default 12. |

## Output

The script prints a line per site while it runs, then a summary table, and saves the same data to the CSV file.

| Column | Meaning |
|---|---|
| `URL` | The URL that was scanned. |
| `JavaDetected` | `YES`, `POSSIBLE`, `NO` or `ERROR` (see below). |
| `Confidence` | `HIGH` (a strong sign), `MEDIUM` (a medium sign or two weak ones), `LOW` (one weak sign), or `-`. |
| `HttpStatus` | HTTP status of the final response of the main request. |
| `ServerHeader` | Value of the `Server` header, or `N/A`. |
| `Evidence` | All matched signals, separated by ` ; `. |
| `Notes` | Why a site was not scanned, or which check was skipped (failed or soft-404 probe). |

`JavaDetected`: `YES` = strong or medium evidence; `POSSIBLE` = one weak hit only; `NO` = nothing found; `ERROR` = the site could not be fetched (DNS, timeout, refused, TLS), see `Notes`.

## Limitations: read before trusting the result

- **`YES` with `LOW`/`MEDIUM` confidence is a hint, not proof.** Weak signals (`.do`, `.action`, `.jsp` links) can also appear on sites that are not Java, for example a page about Java.
- **`NO` means "found nothing", not "not Java".** Only the start page and one error page are checked. A reverse proxy or CDN often hides the `Server` header. Many Java apps set no `JSESSIONID` until you log in, or use another cookie name.
- **`ERROR` rows were not scanned.** Re-run them and read the `Notes` column.
- **TLS certificates are not verified** (`curl -k` / a certificate callback that always accepts). That is convenient for scanning sites with broken certificates, but the result could be spoofed by someone in the network path.
- **Sequential and slow for big lists.** Each site needs two requests, each with a timeout of `-TimeoutSec` seconds (default 12).
- The browser-like `User-Agent` is only there so that simple bot filters do not block the request.
- The `curl` path is the one to trust. The .NET fallback (used when no `curl` is found) is less tested.

## Files

| File | Purpose |
|---|---|
| `Test-WebsiteJavaBackend.ps1` | The scanner. |
| `README.md` | This file. |
