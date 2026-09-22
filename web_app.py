#!/usr/bin/env python3
"""Local browser interface for the AES file encryption demo."""

import os
import tempfile
from pathlib import Path

from flask import Flask, request, send_file
from werkzeug.utils import secure_filename

import crypto_tool


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024 * 1024


PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Secure File Vault</title>
  <style>
    body { margin: 0; min-height: 100vh; background: #edf2f4; color: #17202a; font: 16px system-ui, sans-serif; }
    main { width: min(620px, calc(100% - 32px)); margin: 8vh auto; background: white; padding: 32px; border-radius: 14px; box-shadow: 0 12px 35px #1b273320; }
    h1 { margin-top: 0; color: #123b4a; } p { color: #52616b; }
    label { display: block; margin: 18px 0 7px; font-weight: 650; }
    input, select, button { box-sizing: border-box; width: 100%; padding: 12px; border: 1px solid #b9c5ca; border-radius: 7px; font: inherit; }
    button { margin-top: 24px; border: 0; background: #087f8c; color: white; font-weight: 700; cursor: pointer; }
    button:hover { background: #05636e; } .note { margin-top: 22px; font-size: .9rem; }
  </style>
</head>
<body><main>
  <h1>Secure File Vault</h1>
  <p>AES-256-GCM encryption with password-based key derivation.</p>
  <form method="post" enctype="multipart/form-data">
    <label for="mode">Operation</label>
    <select id="mode" name="mode"><option value="encrypt">Encrypt file</option><option value="decrypt">Decrypt file</option></select>
    <label for="file">File</label>
    <input id="file" name="file" type="file" required>
    <label for="password">Password</label>
    <input id="password" name="password" type="password" required autocomplete="off">
    <button type="submit">Process file</button>
  </form>
  <p class="note">This demo runs locally. Passwords are not saved. Do not expose this development server to the internet.</p>
</main></body></html>"""


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return PAGE

    uploaded = request.files.get("file")
    password = request.form.get("password", "")
    mode = request.form.get("mode", "encrypt")
    if uploaded is None or not uploaded.filename or not password:
        return "A file and password are required.", 400
    if mode not in {"encrypt", "decrypt"}:
        return "Invalid operation.", 400

    input_name = secure_filename(uploaded.filename) or "input.bin"
    output_name = crypto_tool.default_output_path(input_name, mode)
    input_path = output_path = None

    try:
        input_file = tempfile.NamedTemporaryFile(delete=False)
        input_path = input_file.name
        input_file.close()
        uploaded.save(input_path)

        output_file = tempfile.NamedTemporaryFile(delete=False)
        output_path = output_file.name
        output_file.close()

        if mode == "encrypt":
            crypto_tool.encrypt_file(input_path, output_path, password)
        else:
            crypto_tool.decrypt_file(input_path, output_path, password)

        response = send_file(output_path, as_attachment=True, download_name=output_name)

        def cleanup():
            for path in (input_path, output_path):
                if path:
                    try:
                        os.unlink(path)
                    except FileNotFoundError:
                        pass

        response.call_on_close(cleanup)
        return response
    except (OSError, ValueError, SystemExit) as error:
        for path in (input_path, output_path):
            if path:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
        return f"Operation failed: {error}", 400


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)