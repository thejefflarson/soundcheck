---
name: file-upload
description: Use when writing file upload handlers, processing multipart form data,
  saving uploaded files to disk or cloud storage. Also invoke when accepting user-supplied
  filenames or storing uploads in a web-accessible directory.
---

# File Upload Security Check (A04:2025)

## What this checks

Protects against unrestricted file upload attacks where an attacker uploads executable
files (web shells, scripts, HTML with embedded JS) that the server later serves or
executes. Exploitation leads to remote code execution, stored XSS, or full server
compromise.

## Vulnerable patterns

- `file.save(os.path.join('uploads/', file.filename))` -- user-controlled filename stored directly, enabling path traversal and extension bypass
- `Path(uploadDir).resolve().toString() + originalFilename` -- original filename preserved, no extension allowlist
- `io.Copy(dst, file)` with destination in webroot -- uploaded content served directly by the web server
- No `Content-Length` or stream-size check -- attacker uploads multi-GB file to exhaust disk

## Fix immediately

For each vulnerable upload handler, apply all of the following controls:

1. **Extension allowlist** -- reject any file whose extension is not in an explicit allowlist (e.g., `.png`, `.jpg`, `.pdf`). Never use a denylist.
2. **Rename the file** -- replace the user-supplied filename with a random identifier (UUID/CSPRNG hex). Preserve only the validated extension.
3. **Store outside webroot** -- write uploads to a directory the web server does not serve directly. Serve files through an application route that sets `Content-Disposition: attachment` and a safe `Content-Type`.
4. **Enforce size limit** -- cap upload size at the framework level (e.g., Flask `MAX_CONTENT_LENGTH`, Spring `max-file-size`, nginx `client_max_body_size`).
5. **Validate MIME type** -- check the file's magic bytes, not just the `Content-Type` header.

**Python (Flask) secure pattern:**

```python
import uuid, os
from werkzeug.utils import secure_filename

ALLOWED_EXT = {'.png', '.jpg', '.jpeg', '.gif', '.pdf'}
UPLOAD_DIR = '/var/data/uploads'  # outside webroot
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in ALLOWED_EXT:
        abort(400, 'File type not allowed')
    safe_name = f"{uuid.uuid4().hex}{ext}"
    f.save(os.path.join(UPLOAD_DIR, safe_name))
    return jsonify(id=safe_name), 201
```

**Why this works:** The allowlist blocks executable extensions, the random name prevents path traversal and overwrites, storing outside webroot prevents direct execution, and the size cap prevents resource exhaustion.

## Verification

Confirm the following properties hold (language-agnostic):

- [ ] Only explicitly-allowed file extensions are accepted -- enforced via an allowlist, not a denylist
- [ ] The user-supplied filename is never used as the storage path -- files are renamed to a random or hashed identifier
- [ ] Uploaded files are stored outside the web-accessible document root
- [ ] A maximum upload size is enforced at the framework or reverse-proxy level
- [ ] Files are served with `Content-Disposition: attachment` and a safe, explicit `Content-Type` -- never inferred from the filename

## References

- CWE-434 ([Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html))
- CWE-22 ([Path Traversal](https://cwe.mitre.org/data/definitions/22.html))
- [OWASP A04:2025 Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
