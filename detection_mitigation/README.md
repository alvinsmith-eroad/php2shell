# Detection and mitigation

This directory contains an offline, heuristic triage PoC and the existing cPanel partial mitigation material for CVE-2026-109618 and CVE-2026-109619.

## Public HTTPS information check

[`php2shell-http-check.py`](php2shell-http-check.py) makes one ordinary HTTPS `GET` to the exact URL you supply and reports public response status plus `Server` and `X-Powered-By` headers. It is for information disclosure only: it does not send an exploit, submit a login form, inspect the response body, or follow redirects. It accepts public hosts on the default HTTPS port only.

```sh
python3 detection_mitigation/php2shell-http-check.py \
  'https://your-authorized-host.example/wp-login.php'
```

Use `--format json` for JSON output. If the site advertises `X-Powered-By: PHP/8.2.1`, the tool reports `php_version_disclosed` and the advertised version. If it does not, the status is `no_php_version_disclosed`. Either way `vulnerability_status` is always `not_determined`: a public URL cannot confirm which PHP binary/SAPI/pool serves the WordPress endpoint, vendor backports, or whether it can be exploited. A hidden version does not mean safe, and an advertised version by itself does not prove vulnerable or pwnable. The tool does not compare against release numbers because upstream/vendor fix details referenced by this repository were not independently verified here.

The checker does not access this repository's prior example host unless its operator explicitly supplies that URL. Do not use it against systems without authorization. The program has no exploit mode and performs one request per invocation; DNS is resolved and pinned to a publicly routable address, TLS certificates are verified, redirects are not followed, and the response body is not read. It uses Python's standard library. We do not run it against production during development.

## Detection PoC

[`php2shell-triage.py`](php2shell-triage.py) analyzes only local files explicitly supplied on the command line. It makes no network requests, changes no configuration, restarts no services, and never executes discovered code. It uses only the Python 3 standard library.

**No trustworthy CVE-specific indicator was verified for this PoC.** As of 21 October 2026, direct retrieval of the cited PHP archive, CERT-EU advisory, and Calif research page failed in this environment; the linked video was not inspected. Therefore, this tool does not claim to detect either CVE, infer exploit success, or validate the CVE details stated elsewhere in this repository. The patterns below are generic operational heuristics, not exploit signatures.

No production site or live service was tested in building or validating this PoC.

### Quick start

From the repository root:

```sh
python3 detection_mitigation/php2shell-triage.py \
  --error-log /var/log/php-fpm/www-error.log \
  --error-log /var/log/apache2/error.log \
  --access-log /var/log/apache2/access.log
```

Human output is the default. Machine-readable output:

```sh
python3 detection_mitigation/php2shell-triage.py \
  --error-log /path/to/php-fpm-error.log \
  --access-log /path/to/apache-access.log \
  --format json
```

For the bundled, harmless synthetic example:

```sh
python3 detection_mitigation/php2shell-triage.py \
  --error-log detection_mitigation/tests/fixtures/error-positive.log \
  --access-log detection_mitigation/tests/fixtures/access.log
```

Expected output includes:

```text
PHP2Shell defensive triage (offline heuristic; not a vulnerability scanner)
Status: telemetry_anomaly_observed
CVE-specific indicator verified: no
Observed generic signals: 2 (memory errors: 1, web-worker crashes: 1)
Access requests in supplied logs: 2
Runtime evidence: not confirmed
Signals (log contents omitted):
  input 1, line 1: web_worker_crash; nearby access records: 0
  input 1, line 2: memory_error; nearby access records: 0
No findings do not mean not vulnerable or not compromised.
Use the documented operator steps to verify and patch the actual serving runtime.
```

The fixture's PHP timestamps have no timezone, while the access-log timestamps include UTC offsets. The tool deliberately does **not** correlate those records because the timezone relationship is unknown. Correlation is reported only when timestamps have compatible timezone information; bracketed ISO-8601 timestamps with offsets are also supported. Adjust the window with `--window-seconds N` (0–3600; default 60). Temporal proximity is weak context, not proof of causation. Worker correlation is only attempted when a worker ID is actually present in both records.

### Status, confidence, and exit codes

The JSON `statuses` array (and human `Status`) uses these distinct outcomes:

| Status | Meaning |
| --- | --- |
| `telemetry_anomaly_observed` | Generic PHP memory-error or web-worker crash wording was found. This is low-confidence triage evidence and is not CVE-specific. |
| `potential_exposure` | Explicit runtime evidence says the confirmed serving runtime has an unpatched vendor package. The tool does not independently verify that operator-supplied assessment. |
| `insufficient_evidence` | No generic signal or confirmed-unpatched serving runtime was supplied. This does not mean safe, patched, or uncompromised. |

More than one status can be present. `status` is the first item in `statuses`; there is no “not vulnerable” or “not compromised” result, and no stronger determination is supported by this tool. Exit code `0` means analysis completed, including an inconclusive result. Exit code `2` means invalid arguments or unsafe/unreadable input.

The heuristics look for generic PHP memory exhaustion/corruption wording and PHP-FPM/php-cgi/Apache worker crash wording. A generic crash can have unrelated causes; an application warning, PHP child process, filesystem change, or normal PHP function call alone is not evidence of these CVEs. A PHP error/access log pair cannot establish successful code execution. Empty, rotated, incomplete, or uncollected telemetry remains unknown.

### Optional operator-supplied runtime evidence

The CLI does not run `php -v`, inspect the host, compare PHP version strings, or assume CLI PHP is the web-serving runtime. To report potential exposure, provide an explicitly selected local JSON file such as:

```json
{
  "serving_runtime_confirmed": true,
  "vendor_patch_status": "unpatched"
}
```

`vendor_patch_status` must be `patched`, `unpatched`, or `unknown`; omitted means `unknown`. Use `patched` or `unpatched` only after verifying the actual serving binary/package and vendor advisory, including any backport. Extra identity or version details may be retained in the operator's private evidence but are not needed or echoed by this tool. The JSON is an operator assertion, not tool verification. Version comparison alone cannot establish vendor backport status or cover unsupported branches.

```sh
python3 detection_mitigation/php2shell-triage.py \
  --runtime-evidence /secure/local/runtime-assessment.json --format json
```

### Safe offline tests

Run the deterministic, synthetic tests with:

```sh
python3 -m unittest discover -s detection_mitigation/tests -v
python3 -m py_compile detection_mitigation/php2shell-triage.py \
  detection_mitigation/tests/test_php2shell_triage.py
```

Fixtures exercise generic positive/negative cases, malformed and missing timestamps, time windows, timezone mismatch, worker-ID correlation, JSON redaction, symlink rejection, and size limits. They are synthetic telemetry demonstrations, **not** validation of either vulnerability or an exploit. No exploit, webshell, remote probe, attack payload, or vulnerable runtime is included or required.

### Input and privacy limits

- Select each input with `--error-log`, `--access-log`, or `--runtime-evidence`; the tool has no URL or recursive-discovery mode.
- Only regular files up to 10 MiB each, 10,000 lines each, and at most 20 files are accepted. Reports include at most 1,000 signal records and correlation retains at most 10,000 access timestamps; omission counts are included in JSON. The reported input number follows the CLI's grouped order (error logs, then access logs). Final-component symlinks are rejected where the operating system supports `O_NOFOLLOW`; permission and other read errors fail closed. No file is modified.
- Text is decoded as UTF-8 with replacement for invalid bytes. Reports omit log contents, request paths, client addresses, and package/version strings; they contain counts, statuses, generic event types, input identifiers, and line numbers. Protect source logs and reports as sensitive operational data.
- Apache common access timestamps, PHP/FPM timestamps of the form `[21-Oct-2026 10:00:00]`, Apache error timestamps, and bracketed ISO-8601 timestamps are recognized. Unrecognized or timezone-incompatible timestamps are not correlated.
- Log formats vary. Missing fields, truncation, timezone changes, clock skew, worker reuse, and log rotation can prevent or mislead correlation. No automatic process, filesystem, network, PHP configuration, or WordPress inspection is performed.

## Operator next steps

1. Preserve relevant PHP-FPM/Apache error and access logs, rotation metadata, and deployment/package records before restarting workers or changing systems. Record collection time and host timezone; preserve originals and work from copies.
2. Identify the **runtime actually serving requests**: map the site/vhost to its handler, SAPI, PHP-FPM pool or Apache module, container/image, and running worker executable. A shell's `php -v` may report a different CLI binary. Do not publish a `phpinfo()` endpoint.
3. Establish package provenance for that serving binary with the operating-system or image vendor's package tools. Check the vendor's advisory and package changelog for the relevant fix or backport; do not infer patch status from the upstream version string alone, especially on EOL branches or vendor-maintained builds.
4. Apply the vendor-supported fixed package/image, then reload/restart the **serving** workers as required and verify that new workers use the remediated binary/package and intended deployment. WordPress core, plugin, and theme updates do not remediate PHP runtime defects.
5. If suspicious signals exist, treat them as a reason to preserve evidence and investigate with the incident-response process—not as proof of PHP2Shell. PHP child processes or filesystem changes alone do not prove these CVEs, and normal PHP functions are not reliable indicators.

## Other material

| Directory | Purpose |
| --- | --- |
| [cpanel](cpanel) | Existing cPanel EasyApache 4 **partial** mitigation material. Updating the actual serving PHP package/image or applying a verified vendor backport remains the remediation; the partial settings are not a fix. |
