# Code Citations

## License: unknown
https://github.com/district09/symfony_bundle_domainator9k-core/blob/79d673237ab1c3f476ef10a837d16426b2492c3e/Entity/ApplicationEnvironment.php

```
Here is a structured analysis of the issues found in [spat_cli/spat_cli.py](spat_cli/spat_cli.py):

---

## Security

### 1. HTML injection in exported reports (Medium)
[Lines 1854–1870](spat_cli/spat_cli.py#L1854-L1870) — Finding fields like `description` and `remediation` are interpolated into HTML without `html.escape()`. Several of these fields include external data: TLS certificate CN/issuer values, DNS record content, server header values, CORS origins. A malicious server could embed `<script>` tags that execute when the report is opened in a browser.
```python
# e.g. check_tls sets description to:
f"Valid for {days_left} days. CN={cn}, Issuer={issuer_name}"
# ...then export_html does:
f"<td>{f.get('description','')}</td>"  # no html.escape()
```
**Fix:** wrap all user-derived fields with `html.escape()`.

---

## Bugs

### 2. Uncaught `ValueError` from `strptime` in `check_tls` ([line 217](spat_cli/spat_cli.py#L217))
```python
not_after = datetime.strptime(
    cert["notAfter"].rsplit(" ", 1)[0], "%b %d %H:%M:%S %Y"
)
```
This is inside the outer `try` block but the `except` clauses only catch `ssl.CertificateError` and `(socket.timeout, ConnectionRefusedError, OSError)` — a non-standard cert date format raises an unhandled `ValueError` that propagates to `run_scan` and gets swallowed as a generic error.

### 3. `_ssl_context()` defined but not used by the main TLS checks ([lines 57–62](spat_cli/spat_cli.py#L57-L62), [line 212](spat_cli/spat_cli.py#L212), [line 1218](spat_cli/spat_cli.py#L1218))
`_ssl_context()` was created specifically for PyInstaller/Windows certifi compatibility, but both `check_tls` and `check_tls_ciphers` call `ssl.create_default_context()` directly instead. The fix this function provides (certifi CA bundle) is never applied to the scan's primary TLS handshakes.

### 4. Dead code in `proto_map` in `check_tls_protocols` ([line 273](spat_cli/spat_cli.py#L273))
```python
proto_map = {
    "TLSv1": (ssl.PROTOCOL_TLS_CLIENT, {"minimum_version": ...}, True),
    ...
}
for proto_name, (_, opts, is_weak) in proto_map.items():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # first tuple element ignored
```
The first element of every tuple is `ssl.PROTOCOL_TLS_CLIENT` but it's captured as `_` and the context is hardcoded to `ssl.PROTOCOL_TLS_CLIENT` anyway. The first tuple element is never used.

---

## Code Quality

### 5. Unused `threading` import ([line 18](spat_cli/spat_cli.py#L18))
`threading` is imported but never referenced. `ThreadPoolExecutor` is imported from `concurrent.futures`.

### 6. Hostname regex allows consecutive dots ([line 2376](spat_cli/spat_cli.py#L2376))
```python
if not re.match(r"^[a-z0-9][a-z0-9.\-]{0,252}[a-z0-9]$", hostname):
```
`a..b.com` passes this check. Use `r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$
```


## License: unknown
https://github.com/district09/symfony_bundle_domainator9k-core/blob/79d673237ab1c3f476ef10a837d16426b2492c3e/Entity/ApplicationEnvironment.php

```
Here is a structured analysis of the issues found in [spat_cli/spat_cli.py](spat_cli/spat_cli.py):

---

## Security

### 1. HTML injection in exported reports (Medium)
[Lines 1854–1870](spat_cli/spat_cli.py#L1854-L1870) — Finding fields like `description` and `remediation` are interpolated into HTML without `html.escape()`. Several of these fields include external data: TLS certificate CN/issuer values, DNS record content, server header values, CORS origins. A malicious server could embed `<script>` tags that execute when the report is opened in a browser.
```python
# e.g. check_tls sets description to:
f"Valid for {days_left} days. CN={cn}, Issuer={issuer_name}"
# ...then export_html does:
f"<td>{f.get('description','')}</td>"  # no html.escape()
```
**Fix:** wrap all user-derived fields with `html.escape()`.

---

## Bugs

### 2. Uncaught `ValueError` from `strptime` in `check_tls` ([line 217](spat_cli/spat_cli.py#L217))
```python
not_after = datetime.strptime(
    cert["notAfter"].rsplit(" ", 1)[0], "%b %d %H:%M:%S %Y"
)
```
This is inside the outer `try` block but the `except` clauses only catch `ssl.CertificateError` and `(socket.timeout, ConnectionRefusedError, OSError)` — a non-standard cert date format raises an unhandled `ValueError` that propagates to `run_scan` and gets swallowed as a generic error.

### 3. `_ssl_context()` defined but not used by the main TLS checks ([lines 57–62](spat_cli/spat_cli.py#L57-L62), [line 212](spat_cli/spat_cli.py#L212), [line 1218](spat_cli/spat_cli.py#L1218))
`_ssl_context()` was created specifically for PyInstaller/Windows certifi compatibility, but both `check_tls` and `check_tls_ciphers` call `ssl.create_default_context()` directly instead. The fix this function provides (certifi CA bundle) is never applied to the scan's primary TLS handshakes.

### 4. Dead code in `proto_map` in `check_tls_protocols` ([line 273](spat_cli/spat_cli.py#L273))
```python
proto_map = {
    "TLSv1": (ssl.PROTOCOL_TLS_CLIENT, {"minimum_version": ...}, True),
    ...
}
for proto_name, (_, opts, is_weak) in proto_map.items():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # first tuple element ignored
```
The first element of every tuple is `ssl.PROTOCOL_TLS_CLIENT` but it's captured as `_` and the context is hardcoded to `ssl.PROTOCOL_TLS_CLIENT` anyway. The first tuple element is never used.

---

## Code Quality

### 5. Unused `threading` import ([line 18](spat_cli/spat_cli.py#L18))
`threading` is imported but never referenced. `ThreadPoolExecutor` is imported from `concurrent.futures`.

### 6. Hostname regex allows consecutive dots ([line 2376](spat_cli/spat_cli.py#L2376))
```python
if not re.match(r"^[a-z0-9][a-z0-9.\-]{0,252}[a-z0-9]$", hostname):
```
`a..b.com` passes this check. Use `r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$
```


## License: unknown
https://github.com/district09/symfony_bundle_domainator9k-core/blob/79d673237ab1c3f476ef10a837d16426b2492c3e/Entity/ApplicationEnvironment.php

```
Here is a structured analysis of the issues found in [spat_cli/spat_cli.py](spat_cli/spat_cli.py):

---

## Security

### 1. HTML injection in exported reports (Medium)
[Lines 1854–1870](spat_cli/spat_cli.py#L1854-L1870) — Finding fields like `description` and `remediation` are interpolated into HTML without `html.escape()`. Several of these fields include external data: TLS certificate CN/issuer values, DNS record content, server header values, CORS origins. A malicious server could embed `<script>` tags that execute when the report is opened in a browser.
```python
# e.g. check_tls sets description to:
f"Valid for {days_left} days. CN={cn}, Issuer={issuer_name}"
# ...then export_html does:
f"<td>{f.get('description','')}</td>"  # no html.escape()
```
**Fix:** wrap all user-derived fields with `html.escape()`.

---

## Bugs

### 2. Uncaught `ValueError` from `strptime` in `check_tls` ([line 217](spat_cli/spat_cli.py#L217))
```python
not_after = datetime.strptime(
    cert["notAfter"].rsplit(" ", 1)[0], "%b %d %H:%M:%S %Y"
)
```
This is inside the outer `try` block but the `except` clauses only catch `ssl.CertificateError` and `(socket.timeout, ConnectionRefusedError, OSError)` — a non-standard cert date format raises an unhandled `ValueError` that propagates to `run_scan` and gets swallowed as a generic error.

### 3. `_ssl_context()` defined but not used by the main TLS checks ([lines 57–62](spat_cli/spat_cli.py#L57-L62), [line 212](spat_cli/spat_cli.py#L212), [line 1218](spat_cli/spat_cli.py#L1218))
`_ssl_context()` was created specifically for PyInstaller/Windows certifi compatibility, but both `check_tls` and `check_tls_ciphers` call `ssl.create_default_context()` directly instead. The fix this function provides (certifi CA bundle) is never applied to the scan's primary TLS handshakes.

### 4. Dead code in `proto_map` in `check_tls_protocols` ([line 273](spat_cli/spat_cli.py#L273))
```python
proto_map = {
    "TLSv1": (ssl.PROTOCOL_TLS_CLIENT, {"minimum_version": ...}, True),
    ...
}
for proto_name, (_, opts, is_weak) in proto_map.items():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # first tuple element ignored
```
The first element of every tuple is `ssl.PROTOCOL_TLS_CLIENT` but it's captured as `_` and the context is hardcoded to `ssl.PROTOCOL_TLS_CLIENT` anyway. The first tuple element is never used.

---

## Code Quality

### 5. Unused `threading` import ([line 18](spat_cli/spat_cli.py#L18))
`threading` is imported but never referenced. `ThreadPoolExecutor` is imported from `concurrent.futures`.

### 6. Hostname regex allows consecutive dots ([line 2376](spat_cli/spat_cli.py#L2376))
```python
if not re.match(r"^[a-z0-9][a-z0-9.\-]{0,252}[a-z0-9]$", hostname):
```
`a..b.com` passes this check. Use `r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$
```


## License: unknown
https://github.com/district09/symfony_bundle_domainator9k-core/blob/79d673237ab1c3f476ef10a837d16426b2492c3e/Entity/ApplicationEnvironment.php

```
Here is a structured analysis of the issues found in [spat_cli/spat_cli.py](spat_cli/spat_cli.py):

---

## Security

### 1. HTML injection in exported reports (Medium)
[Lines 1854–1870](spat_cli/spat_cli.py#L1854-L1870) — Finding fields like `description` and `remediation` are interpolated into HTML without `html.escape()`. Several of these fields include external data: TLS certificate CN/issuer values, DNS record content, server header values, CORS origins. A malicious server could embed `<script>` tags that execute when the report is opened in a browser.
```python
# e.g. check_tls sets description to:
f"Valid for {days_left} days. CN={cn}, Issuer={issuer_name}"
# ...then export_html does:
f"<td>{f.get('description','')}</td>"  # no html.escape()
```
**Fix:** wrap all user-derived fields with `html.escape()`.

---

## Bugs

### 2. Uncaught `ValueError` from `strptime` in `check_tls` ([line 217](spat_cli/spat_cli.py#L217))
```python
not_after = datetime.strptime(
    cert["notAfter"].rsplit(" ", 1)[0], "%b %d %H:%M:%S %Y"
)
```
This is inside the outer `try` block but the `except` clauses only catch `ssl.CertificateError` and `(socket.timeout, ConnectionRefusedError, OSError)` — a non-standard cert date format raises an unhandled `ValueError` that propagates to `run_scan` and gets swallowed as a generic error.

### 3. `_ssl_context()` defined but not used by the main TLS checks ([lines 57–62](spat_cli/spat_cli.py#L57-L62), [line 212](spat_cli/spat_cli.py#L212), [line 1218](spat_cli/spat_cli.py#L1218))
`_ssl_context()` was created specifically for PyInstaller/Windows certifi compatibility, but both `check_tls` and `check_tls_ciphers` call `ssl.create_default_context()` directly instead. The fix this function provides (certifi CA bundle) is never applied to the scan's primary TLS handshakes.

### 4. Dead code in `proto_map` in `check_tls_protocols` ([line 273](spat_cli/spat_cli.py#L273))
```python
proto_map = {
    "TLSv1": (ssl.PROTOCOL_TLS_CLIENT, {"minimum_version": ...}, True),
    ...
}
for proto_name, (_, opts, is_weak) in proto_map.items():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # first tuple element ignored
```
The first element of every tuple is `ssl.PROTOCOL_TLS_CLIENT` but it's captured as `_` and the context is hardcoded to `ssl.PROTOCOL_TLS_CLIENT` anyway. The first tuple element is never used.

---

## Code Quality

### 5. Unused `threading` import ([line 18](spat_cli/spat_cli.py#L18))
`threading` is imported but never referenced. `ThreadPoolExecutor` is imported from `concurrent.futures`.

### 6. Hostname regex allows consecutive dots ([line 2376](spat_cli/spat_cli.py#L2376))
```python
if not re.match(r"^[a-z0-9][a-z0-9.\-]{0,252}[a-z0-9]$", hostname):
```
`a..b.com` passes this check. Use `r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$
```


## License: unknown
https://github.com/district09/symfony_bundle_domainator9k-core/blob/79d673237ab1c3f476ef10a837d16426b2492c3e/Entity/ApplicationEnvironment.php

```
Here is a structured analysis of the issues found in [spat_cli/spat_cli.py](spat_cli/spat_cli.py):

---

## Security

### 1. HTML injection in exported reports (Medium)
[Lines 1854–1870](spat_cli/spat_cli.py#L1854-L1870) — Finding fields like `description` and `remediation` are interpolated into HTML without `html.escape()`. Several of these fields include external data: TLS certificate CN/issuer values, DNS record content, server header values, CORS origins. A malicious server could embed `<script>` tags that execute when the report is opened in a browser.
```python
# e.g. check_tls sets description to:
f"Valid for {days_left} days. CN={cn}, Issuer={issuer_name}"
# ...then export_html does:
f"<td>{f.get('description','')}</td>"  # no html.escape()
```
**Fix:** wrap all user-derived fields with `html.escape()`.

---

## Bugs

### 2. Uncaught `ValueError` from `strptime` in `check_tls` ([line 217](spat_cli/spat_cli.py#L217))
```python
not_after = datetime.strptime(
    cert["notAfter"].rsplit(" ", 1)[0], "%b %d %H:%M:%S %Y"
)
```
This is inside the outer `try` block but the `except` clauses only catch `ssl.CertificateError` and `(socket.timeout, ConnectionRefusedError, OSError)` — a non-standard cert date format raises an unhandled `ValueError` that propagates to `run_scan` and gets swallowed as a generic error.

### 3. `_ssl_context()` defined but not used by the main TLS checks ([lines 57–62](spat_cli/spat_cli.py#L57-L62), [line 212](spat_cli/spat_cli.py#L212), [line 1218](spat_cli/spat_cli.py#L1218))
`_ssl_context()` was created specifically for PyInstaller/Windows certifi compatibility, but both `check_tls` and `check_tls_ciphers` call `ssl.create_default_context()` directly instead. The fix this function provides (certifi CA bundle) is never applied to the scan's primary TLS handshakes.

### 4. Dead code in `proto_map` in `check_tls_protocols` ([line 273](spat_cli/spat_cli.py#L273))
```python
proto_map = {
    "TLSv1": (ssl.PROTOCOL_TLS_CLIENT, {"minimum_version": ...}, True),
    ...
}
for proto_name, (_, opts, is_weak) in proto_map.items():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # first tuple element ignored
```
The first element of every tuple is `ssl.PROTOCOL_TLS_CLIENT` but it's captured as `_` and the context is hardcoded to `ssl.PROTOCOL_TLS_CLIENT` anyway. The first tuple element is never used.

---

## Code Quality

### 5. Unused `threading` import ([line 18](spat_cli/spat_cli.py#L18))
`threading` is imported but never referenced. `ThreadPoolExecutor` is imported from `concurrent.futures`.

### 6. Hostname regex allows consecutive dots ([line 2376](spat_cli/spat_cli.py#L2376))
```python
if not re.match(r"^[a-z0-9][a-z0-9.\-]{0,252}[a-z0-9]$", hostname):
```
`a..b.com` passes this check. Use `r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$
```


## License: unknown
https://github.com/district09/symfony_bundle_domainator9k-core/blob/79d673237ab1c3f476ef10a837d16426b2492c3e/Entity/ApplicationEnvironment.php

```
Here is a structured analysis of the issues found in [spat_cli/spat_cli.py](spat_cli/spat_cli.py):

---

## Security

### 1. HTML injection in exported reports (Medium)
[Lines 1854–1870](spat_cli/spat_cli.py#L1854-L1870) — Finding fields like `description` and `remediation` are interpolated into HTML without `html.escape()`. Several of these fields include external data: TLS certificate CN/issuer values, DNS record content, server header values, CORS origins. A malicious server could embed `<script>` tags that execute when the report is opened in a browser.
```python
# e.g. check_tls sets description to:
f"Valid for {days_left} days. CN={cn}, Issuer={issuer_name}"
# ...then export_html does:
f"<td>{f.get('description','')}</td>"  # no html.escape()
```
**Fix:** wrap all user-derived fields with `html.escape()`.

---

## Bugs

### 2. Uncaught `ValueError` from `strptime` in `check_tls` ([line 217](spat_cli/spat_cli.py#L217))
```python
not_after = datetime.strptime(
    cert["notAfter"].rsplit(" ", 1)[0], "%b %d %H:%M:%S %Y"
)
```
This is inside the outer `try` block but the `except` clauses only catch `ssl.CertificateError` and `(socket.timeout, ConnectionRefusedError, OSError)` — a non-standard cert date format raises an unhandled `ValueError` that propagates to `run_scan` and gets swallowed as a generic error.

### 3. `_ssl_context()` defined but not used by the main TLS checks ([lines 57–62](spat_cli/spat_cli.py#L57-L62), [line 212](spat_cli/spat_cli.py#L212), [line 1218](spat_cli/spat_cli.py#L1218))
`_ssl_context()` was created specifically for PyInstaller/Windows certifi compatibility, but both `check_tls` and `check_tls_ciphers` call `ssl.create_default_context()` directly instead. The fix this function provides (certifi CA bundle) is never applied to the scan's primary TLS handshakes.

### 4. Dead code in `proto_map` in `check_tls_protocols` ([line 273](spat_cli/spat_cli.py#L273))
```python
proto_map = {
    "TLSv1": (ssl.PROTOCOL_TLS_CLIENT, {"minimum_version": ...}, True),
    ...
}
for proto_name, (_, opts, is_weak) in proto_map.items():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # first tuple element ignored
```
The first element of every tuple is `ssl.PROTOCOL_TLS_CLIENT` but it's captured as `_` and the context is hardcoded to `ssl.PROTOCOL_TLS_CLIENT` anyway. The first tuple element is never used.

---

## Code Quality

### 5. Unused `threading` import ([line 18](spat_cli/spat_cli.py#L18))
`threading` is imported but never referenced. `ThreadPoolExecutor` is imported from `concurrent.futures`.

### 6. Hostname regex allows consecutive dots ([line 2376](spat_cli/spat_cli.py#L2376))
```python
if not re.match(r"^[a-z0-9][a-z0-9.\-]{0,252}[a-z0-9]$", hostname):
```
`a..b.com` passes this check. Use `r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$
```


## License: unknown
https://github.com/district09/symfony_bundle_domainator9k-core/blob/79d673237ab1c3f476ef10a837d16426b2492c3e/Entity/ApplicationEnvironment.php

```
Here is a structured analysis of the issues found in [spat_cli/spat_cli.py](spat_cli/spat_cli.py):

---

## Security

### 1. HTML injection in exported reports (Medium)
[Lines 1854–1870](spat_cli/spat_cli.py#L1854-L1870) — Finding fields like `description` and `remediation` are interpolated into HTML without `html.escape()`. Several of these fields include external data: TLS certificate CN/issuer values, DNS record content, server header values, CORS origins. A malicious server could embed `<script>` tags that execute when the report is opened in a browser.
```python
# e.g. check_tls sets description to:
f"Valid for {days_left} days. CN={cn}, Issuer={issuer_name}"
# ...then export_html does:
f"<td>{f.get('description','')}</td>"  # no html.escape()
```
**Fix:** wrap all user-derived fields with `html.escape()`.

---

## Bugs

### 2. Uncaught `ValueError` from `strptime` in `check_tls` ([line 217](spat_cli/spat_cli.py#L217))
```python
not_after = datetime.strptime(
    cert["notAfter"].rsplit(" ", 1)[0], "%b %d %H:%M:%S %Y"
)
```
This is inside the outer `try` block but the `except` clauses only catch `ssl.CertificateError` and `(socket.timeout, ConnectionRefusedError, OSError)` — a non-standard cert date format raises an unhandled `ValueError` that propagates to `run_scan` and gets swallowed as a generic error.

### 3. `_ssl_context()` defined but not used by the main TLS checks ([lines 57–62](spat_cli/spat_cli.py#L57-L62), [line 212](spat_cli/spat_cli.py#L212), [line 1218](spat_cli/spat_cli.py#L1218))
`_ssl_context()` was created specifically for PyInstaller/Windows certifi compatibility, but both `check_tls` and `check_tls_ciphers` call `ssl.create_default_context()` directly instead. The fix this function provides (certifi CA bundle) is never applied to the scan's primary TLS handshakes.

### 4. Dead code in `proto_map` in `check_tls_protocols` ([line 273](spat_cli/spat_cli.py#L273))
```python
proto_map = {
    "TLSv1": (ssl.PROTOCOL_TLS_CLIENT, {"minimum_version": ...}, True),
    ...
}
for proto_name, (_, opts, is_weak) in proto_map.items():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # first tuple element ignored
```
The first element of every tuple is `ssl.PROTOCOL_TLS_CLIENT` but it's captured as `_` and the context is hardcoded to `ssl.PROTOCOL_TLS_CLIENT` anyway. The first tuple element is never used.

---

## Code Quality

### 5. Unused `threading` import ([line 18](spat_cli/spat_cli.py#L18))
`threading` is imported but never referenced. `ThreadPoolExecutor` is imported from `concurrent.futures`.

### 6. Hostname regex allows consecutive dots ([line 2376](spat_cli/spat_cli.py#L2376))
```python
if not re.match(r"^[a-z0-9][a-z0-9.\-]{0,252}[a-z0-9]$", hostname):
```
`a..b.com` passes this check. Use `r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$
```


## License: unknown
https://github.com/district09/symfony_bundle_domainator9k-core/blob/79d673237ab1c3f476ef10a837d16426b2492c3e/Entity/ApplicationEnvironment.php

```
Here is a structured analysis of the issues found in [spat_cli/spat_cli.py](spat_cli/spat_cli.py):

---

## Security

### 1. HTML injection in exported reports (Medium)
[Lines 1854–1870](spat_cli/spat_cli.py#L1854-L1870) — Finding fields like `description` and `remediation` are interpolated into HTML without `html.escape()`. Several of these fields include external data: TLS certificate CN/issuer values, DNS record content, server header values, CORS origins. A malicious server could embed `<script>` tags that execute when the report is opened in a browser.
```python
# e.g. check_tls sets description to:
f"Valid for {days_left} days. CN={cn}, Issuer={issuer_name}"
# ...then export_html does:
f"<td>{f.get('description','')}</td>"  # no html.escape()
```
**Fix:** wrap all user-derived fields with `html.escape()`.

---

## Bugs

### 2. Uncaught `ValueError` from `strptime` in `check_tls` ([line 217](spat_cli/spat_cli.py#L217))
```python
not_after = datetime.strptime(
    cert["notAfter"].rsplit(" ", 1)[0], "%b %d %H:%M:%S %Y"
)
```
This is inside the outer `try` block but the `except` clauses only catch `ssl.CertificateError` and `(socket.timeout, ConnectionRefusedError, OSError)` — a non-standard cert date format raises an unhandled `ValueError` that propagates to `run_scan` and gets swallowed as a generic error.

### 3. `_ssl_context()` defined but not used by the main TLS checks ([lines 57–62](spat_cli/spat_cli.py#L57-L62), [line 212](spat_cli/spat_cli.py#L212), [line 1218](spat_cli/spat_cli.py#L1218))
`_ssl_context()` was created specifically for PyInstaller/Windows certifi compatibility, but both `check_tls` and `check_tls_ciphers` call `ssl.create_default_context()` directly instead. The fix this function provides (certifi CA bundle) is never applied to the scan's primary TLS handshakes.

### 4. Dead code in `proto_map` in `check_tls_protocols` ([line 273](spat_cli/spat_cli.py#L273))
```python
proto_map = {
    "TLSv1": (ssl.PROTOCOL_TLS_CLIENT, {"minimum_version": ...}, True),
    ...
}
for proto_name, (_, opts, is_weak) in proto_map.items():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # first tuple element ignored
```
The first element of every tuple is `ssl.PROTOCOL_TLS_CLIENT` but it's captured as `_` and the context is hardcoded to `ssl.PROTOCOL_TLS_CLIENT` anyway. The first tuple element is never used.

---

## Code Quality

### 5. Unused `threading` import ([line 18](spat_cli/spat_cli.py#L18))
`threading` is imported but never referenced. `ThreadPoolExecutor` is imported from `concurrent.futures`.

### 6. Hostname regex allows consecutive dots ([line 2376](spat_cli/spat_cli.py#L2376))
```python
if not re.match(r"^[a-z0-9][a-z0-9.\-]{0,252}[a-z0-9]$", hostname):
```
`a..b.com` passes this check. Use `r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$
```


## License: unknown
https://github.com/district09/symfony_bundle_domainator9k-core/blob/79d673237ab1c3f476ef10a837d16426b2492c3e/Entity/ApplicationEnvironment.php

```
Here is a structured analysis of the issues found in [spat_cli/spat_cli.py](spat_cli/spat_cli.py):

---

## Security

### 1. HTML injection in exported reports (Medium)
[Lines 1854–1870](spat_cli/spat_cli.py#L1854-L1870) — Finding fields like `description` and `remediation` are interpolated into HTML without `html.escape()`. Several of these fields include external data: TLS certificate CN/issuer values, DNS record content, server header values, CORS origins. A malicious server could embed `<script>` tags that execute when the report is opened in a browser.
```python
# e.g. check_tls sets description to:
f"Valid for {days_left} days. CN={cn}, Issuer={issuer_name}"
# ...then export_html does:
f"<td>{f.get('description','')}</td>"  # no html.escape()
```
**Fix:** wrap all user-derived fields with `html.escape()`.

---

## Bugs

### 2. Uncaught `ValueError` from `strptime` in `check_tls` ([line 217](spat_cli/spat_cli.py#L217))
```python
not_after = datetime.strptime(
    cert["notAfter"].rsplit(" ", 1)[0], "%b %d %H:%M:%S %Y"
)
```
This is inside the outer `try` block but the `except` clauses only catch `ssl.CertificateError` and `(socket.timeout, ConnectionRefusedError, OSError)` — a non-standard cert date format raises an unhandled `ValueError` that propagates to `run_scan` and gets swallowed as a generic error.

### 3. `_ssl_context()` defined but not used by the main TLS checks ([lines 57–62](spat_cli/spat_cli.py#L57-L62), [line 212](spat_cli/spat_cli.py#L212), [line 1218](spat_cli/spat_cli.py#L1218))
`_ssl_context()` was created specifically for PyInstaller/Windows certifi compatibility, but both `check_tls` and `check_tls_ciphers` call `ssl.create_default_context()` directly instead. The fix this function provides (certifi CA bundle) is never applied to the scan's primary TLS handshakes.

### 4. Dead code in `proto_map` in `check_tls_protocols` ([line 273](spat_cli/spat_cli.py#L273))
```python
proto_map = {
    "TLSv1": (ssl.PROTOCOL_TLS_CLIENT, {"minimum_version": ...}, True),
    ...
}
for proto_name, (_, opts, is_weak) in proto_map.items():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # first tuple element ignored
```
The first element of every tuple is `ssl.PROTOCOL_TLS_CLIENT` but it's captured as `_` and the context is hardcoded to `ssl.PROTOCOL_TLS_CLIENT` anyway. The first tuple element is never used.

---

## Code Quality

### 5. Unused `threading` import ([line 18](spat_cli/spat_cli.py#L18))
`threading` is imported but never referenced. `ThreadPoolExecutor` is imported from `concurrent.futures`.

### 6. Hostname regex allows consecutive dots ([line 2376](spat_cli/spat_cli.py#L2376))
```python
if not re.match(r"^[a-z0-9][a-z0-9.\-]{0,252}[a-z0-9]$", hostname):
```
`a..b.com` passes this check. Use `r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$
```


## License: unknown
https://github.com/district09/symfony_bundle_domainator9k-core/blob/79d673237ab1c3f476ef10a837d16426b2492c3e/Entity/ApplicationEnvironment.php

```
Here is a structured analysis of the issues found in [spat_cli/spat_cli.py](spat_cli/spat_cli.py):

---

## Security

### 1. HTML injection in exported reports (Medium)
[Lines 1854–1870](spat_cli/spat_cli.py#L1854-L1870) — Finding fields like `description` and `remediation` are interpolated into HTML without `html.escape()`. Several of these fields include external data: TLS certificate CN/issuer values, DNS record content, server header values, CORS origins. A malicious server could embed `<script>` tags that execute when the report is opened in a browser.
```python
# e.g. check_tls sets description to:
f"Valid for {days_left} days. CN={cn}, Issuer={issuer_name}"
# ...then export_html does:
f"<td>{f.get('description','')}</td>"  # no html.escape()
```
**Fix:** wrap all user-derived fields with `html.escape()`.

---

## Bugs

### 2. Uncaught `ValueError` from `strptime` in `check_tls` ([line 217](spat_cli/spat_cli.py#L217))
```python
not_after = datetime.strptime(
    cert["notAfter"].rsplit(" ", 1)[0], "%b %d %H:%M:%S %Y"
)
```
This is inside the outer `try` block but the `except` clauses only catch `ssl.CertificateError` and `(socket.timeout, ConnectionRefusedError, OSError)` — a non-standard cert date format raises an unhandled `ValueError` that propagates to `run_scan` and gets swallowed as a generic error.

### 3. `_ssl_context()` defined but not used by the main TLS checks ([lines 57–62](spat_cli/spat_cli.py#L57-L62), [line 212](spat_cli/spat_cli.py#L212), [line 1218](spat_cli/spat_cli.py#L1218))
`_ssl_context()` was created specifically for PyInstaller/Windows certifi compatibility, but both `check_tls` and `check_tls_ciphers` call `ssl.create_default_context()` directly instead. The fix this function provides (certifi CA bundle) is never applied to the scan's primary TLS handshakes.

### 4. Dead code in `proto_map` in `check_tls_protocols` ([line 273](spat_cli/spat_cli.py#L273))
```python
proto_map = {
    "TLSv1": (ssl.PROTOCOL_TLS_CLIENT, {"minimum_version": ...}, True),
    ...
}
for proto_name, (_, opts, is_weak) in proto_map.items():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # first tuple element ignored
```
The first element of every tuple is `ssl.PROTOCOL_TLS_CLIENT` but it's captured as `_` and the context is hardcoded to `ssl.PROTOCOL_TLS_CLIENT` anyway. The first tuple element is never used.

---

## Code Quality

### 5. Unused `threading` import ([line 18](spat_cli/spat_cli.py#L18))
`threading` is imported but never referenced. `ThreadPoolExecutor` is imported from `concurrent.futures`.

### 6. Hostname regex allows consecutive dots ([line 2376](spat_cli/spat_cli.py#L2376))
```python
if not re.match(r"^[a-z0-9][a-z0-9.\-]{0,252}[a-z0-9]$", hostname):
```
`a..b.com` passes this check. Use `r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$
```

