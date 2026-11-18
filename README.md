# onemore-powershell-java-scanner

A small PowerShell script, `Test-WebsiteJavaBackend.ps1`, that checks whether a website **looks like** it is served by a Java backend (Tomcat, Jetty, JBoss/WildFly, Spring Boot, Struts, JSF and similar).

It is a passive fingerprinting tool: for each URL it makes two plain `GET` requests and looks for tell-tale signs in the response. It does not log in, submit forms, fuzz or exploit anything.

> **Only scan sites you own or are allowed to test.**

## How it works

For each target the script sends two requests:

1. **The URL itself.** It looks at:
   | Signal | What counts as evidence |
   |---|---|
   | `Server` header | Tomcat, Jetty, JBoss, WildFly, GlassFish, WebLogic, WebSphere, Apache-Coyote, Undertow |
   | `X-Powered-By` header | Servlet, JSP, JSF, Java, Spring |
   | `Set-Cookie` header | a `JSESSIONID` cookie |
   | Page body | links to `*.jsp`, `*.action` (Struts), `*.do` (Struts/Spring) and `javax.faces` (JSF) |
2. **A random, non-existent path** (`/probe_<random number>`), to provoke an error page. It looks for the Spring Boot "Whitelabel Error Page", `org.springframework`, the Apache Tomcat error page / `org.apache.catalina`, and `java.lang.*Exception` stack traces.

Any single hit marks the site as `JavaDetected = YES`, and every hit is listed as evidence.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+.
- `curl.exe` is used when it is on the `PATH` (it ships with Windows 10 and later). Otherwise the script falls back to .NET `HttpWebRequest`.

## Usage

```powershell
# One URL (https:// is added if you leave the scheme out)
.\Test-WebsiteJavaBackend.ps1 -Url example.com

# Several URLs
.\Test-WebsiteJavaBackend.ps1 -Url example.com, https://example.org

# A list from a file: one URL per line, blank lines and lines starting with # are ignored
.\Test-WebsiteJavaBackend.ps1 -Path .\sites.txt

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

## Output

The script prints a line per site while it runs, then a summary table, and saves the same data to the CSV file.

| Column | Meaning |
|---|---|
| `URL` | The URL that was scanned. |
| `JavaDetected` | `YES` if at least one signal matched, otherwise `NO`. |
| `ServerHeader` | Value of the `Server` header, or `N/A`. |
| `Evidence` | All matched signals, separated by ` ; `. |

## Limitations: read before trusting the result

- **`YES` means "found a Java sign". It is not proof.** The weakest signals (`.do`, `.action`, `.jsp` links in the page, and exception names in a probe response) can also appear on sites that are not Java, for example a blog or documentation page about Java, or a site that returns its home page for every unknown URL.
- **`NO` means "found nothing", not "not Java".** Only the start page and one error page are checked. A reverse proxy or CDN often hides the `Server` header. Many Java apps set no `JSESSIONID` until you log in, or use another cookie name, and an API-only Spring Boot app answers errors in JSON instead of the HTML pages this script looks for.
- **Failed requests can look like `NO`.** A timeout or DNS failure may end up as `NO` with `N/A` as the server header. Check the `Evidence` column for `Error:` lines and re-run those hosts.
- **Redirect chains.** With `curl.exe` the script follows redirects (`-L`), but it reads the headers of the first response. Cookies and headers set on the final page of a redirect chain can be missed.
- **TLS certificates are not verified** (`curl -k` / a certificate callback that always accepts). That is convenient for scanning sites with broken certificates, but the result could be spoofed by someone in the network path.
- **Sequential and slow for big lists.** Each site takes up to two 12-second timeouts.
- The browser-like `User-Agent` is only there so that simple bot filters do not block the request.

## Files

| File | Purpose |
|---|---|
| `Test-WebsiteJavaBackend.ps1` | The scanner. |
| `README.md` | This file. |
