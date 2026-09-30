# Secure Research API Vault

A small, local Streamlit application for researchers who need to store and organise API credentials without committing secrets to GitHub.

## Features

- Encrypts credentials locally using a key derived from a master password (PBKDF2-HMAC-SHA256 and Fernet encryption)
- Groups credentials by service, project, and label
- Keeps an audit log without recording secret values
- Masks keys in the interface
- Scans source folders for common exposed-key patterns and reports only redacted previews

## Run locally

```powershell
cd secure-research-api-vault
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

On first run, create a unique master password with at least 12 characters. The app creates `vault_config.json` and `vault.db` locally. Both are excluded by `.gitignore`.

## Important security notes

- Never commit real API keys, `vault.db`, or `vault_config.json`.
- Do not share your master password. If it is lost, the vault cannot be decrypted.
- The scanner is a convenience check, not a replacement for GitHub secret scanning or a formal security review.
- Rotate any key that has been committed, shared, or otherwise exposed.

## Suggested next improvements

- Add time-limited clipboard copying in a native desktop client.
- Add export/import using an encrypted backup file.
- Add a separate per-project access policy for team use.

