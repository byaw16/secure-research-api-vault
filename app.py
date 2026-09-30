"""Streamlit interface for Secure Research API Vault."""

from __future__ import annotations

from pathlib import Path

import streamlit as st

import crypto
import database
from scanner import scan_folder

st.set_page_config(page_title="Secure Research API Vault", page_icon="🔐", layout="wide")


def mask(value: str) -> str:
    return f"{value[:3]}{'•' * max(8, len(value) - 7)}{value[-4:]}" if len(value) > 7 else "••••••••"


def login() -> None:
    st.title("🔐 Secure Research API Vault")
    st.caption("Local encrypted storage for research API credentials. Your master password is never stored.")
    with st.form("unlock"):
        password = st.text_input("Master password", type="password")
        confirm = st.text_input("Confirm master password", type="password") if not crypto.is_initialized() else None
        submitted = st.form_submit_button("Create vault" if not crypto.is_initialized() else "Unlock vault")
    if submitted:
        try:
            if crypto.is_initialized():
                st.session_state.cipher = crypto.unlock(password)
            else:
                if password != confirm:
                    raise ValueError("The passwords do not match.")
                if len(password) < 12:
                    raise ValueError("Use a master password of at least 12 characters.")
                st.session_state.cipher = crypto.initialize(password)
            database.initialize()
            st.rerun()
        except ValueError as exc:
            st.error(str(exc))
    st.info("Use a unique, long master password. Losing it means the encrypted credentials cannot be recovered.")


def main() -> None:
    if "cipher" not in st.session_state:
        login()
        return
    database.initialize()
    cipher = st.session_state.cipher
    with st.sidebar:
        st.title("Secure Vault")
        page = st.radio("Navigate", ["Credentials", "Add credential", "Secret scanner", "Audit log"])
        if st.button("Lock vault"):
            st.session_state.clear()
            st.rerun()
    if page == "Credentials":
        st.title("Credentials")
        credentials = database.list_credentials()
        projects = sorted({item["project"] for item in credentials})
        selected_project = st.selectbox("Filter by project", ["All projects", *projects])
        query = st.text_input("Search service or label")
        filtered = [
            item for item in credentials
            if (selected_project == "All projects" or item["project"] == selected_project)
            and query.lower() in f"{item['service']} {item['label']}".lower()
        ]
        if not filtered:
            st.info("No credentials match your filters.")
            return
        for item in filtered:
            with st.expander(f"{item['service']} — {item['label']}  ·  {item['project']}"):
                st.caption(f"Last updated: {item['updated_at']}")
                if st.button("Reveal key", key=f"reveal-{item['id']}"):
                    st.session_state[f"secret-{item['id']}"] = database.get_secret(item["id"], cipher)
                if secret := st.session_state.get(f"secret-{item['id']}"):
                    st.code(mask(secret), language=None)
                    st.warning("The key is masked on screen. Use it only in a trusted environment.")
                with st.form(f"edit-{item['id']}"):
                    service = st.text_input("Service", item["service"])
                    project = st.text_input("Project", item["project"])
                    label = st.text_input("Label", item["label"])
                    replacement = st.text_input("Replace API key (leave blank to keep it)", type="password")
                    if st.form_submit_button("Save changes"):
                        database.update_credential(item["id"], service, project, label, replacement, cipher)
                        st.success("Saved.")
                        st.rerun()
                if st.button("Delete credential", key=f"delete-{item['id']}"):
                    database.delete_credential(item["id"])
                    st.success("Credential deleted.")
                    st.rerun()
    elif page == "Add credential":
        st.title("Add credential")
        with st.form("add"):
            service = st.text_input("Service", placeholder="e.g. OpenAI")
            project = st.text_input("Project", placeholder="e.g. thesis-nlp")
            label = st.text_input("Label", placeholder="e.g. development key")
            secret = st.text_input("API key or secret", type="password")
            if st.form_submit_button("Encrypt and save"):
                try:
                    database.add_credential(service, project, label, secret, cipher)
                    st.success("Credential encrypted and stored locally.")
                except ValueError as exc:
                    st.error(str(exc))
    elif page == "Secret scanner":
        st.title("Secret scanner")
        st.caption("Scans local source files and reports redacted matches only. It skips .git, virtual environments, and files above 2 MB.")
        folder = st.text_input("Folder to scan", value=str(Path.cwd()))
        if st.button("Scan folder"):
            path = Path(folder)
            if not path.is_dir():
                st.error("Enter an existing folder.")
            else:
                findings = scan_folder(path)
                if findings:
                    st.warning(f"Found {len(findings)} possible secret(s). Remove them, rotate exposed keys, and use environment variables or this vault.")
                    st.dataframe(findings, use_container_width=True, hide_index=True)
                else:
                    st.success("No matching secret patterns found.")
    else:
        st.title("Audit log")
        st.caption("Local activity log. It intentionally contains no secret values.")
        st.dataframe(database.list_audit_log(), use_container_width=True, hide_index=True)


if __name__ == "__main__":
    main()

