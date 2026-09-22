# Secure File Vault Demo

# SECURE-FILE-ENCRYPTION-AND-DECRYPTION-TOOLS

This project is a small desktop demonstration of password-based file encryption.
It uses AES-256-GCM for confidentiality and tamper detection, with PBKDF2-HMAC-SHA256 for password-based key derivation.

## Run locally

Install Python 3.11 or newer from [python.org](https://www.python.org/downloads/windows/). During installation, enable **Add python.exe to PATH**.

Open Command Prompt in this folder and run:

```bat
cd "C:\Users\fearl\Downloads\New folder\.py"
py -m pip install cryptography
py app.py
```

For the browser interface, run:

```bat
py -m pip install -r requirements.txt
py web_app.py
```

Then open `http://127.0.0.1:5000`.

## Deploy to Vercel

This repository includes `api/index.py` and `vercel.json` for Vercel's Python serverless runtime. Import the GitHub repository into Vercel, leave the framework preset as **Other**, and deploy from the repository root. The browser interface will be available at the deployed Vercel URL.

## Demonstration

1. Create a text file containing sample confidential information.
2. Open the application and select **Encrypt**.
3. Browse to the sample file, enter a password, and click **Encrypt File**.
4. Select the generated `.enc` file, choose **Decrypt**, and use the same password.
5. Open the restored file and compare it with the original.
6. Repeat decryption with a wrong password to demonstrate authentication failure.

## Important security notes

- The password is not stored by the application.
- Losing the password means the encrypted file cannot be recovered.
- The current crypto implementation loads a complete file into memory. It is suitable for a classroom demo, but large-file streaming should be implemented before production use.
- Do not use real sensitive files for a classroom demonstration until the implementation has received a security review.