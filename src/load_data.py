#load_data.py
import os
import imaplib
import email as py_email
from main_helpers import get_sender_domain


def analyze_single_paste():
    print("\nPaste email content. End with ENTER twice:\n")
    lines = []
    while True:
        line = input()
        if line.strip() == "":
            break
        lines.append(line)
    return "\n".join(lines)


def analyze_single_file():
    path = input("Enter .txt file path: ").strip()
    if not os.path.exists(path):
        print("Error: File not found.")
        return ""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def analyze_batch_folder():
    folder = input("Enter folder path: ").strip()
    if not os.path.exists(folder):
        print("Error: Folder not found.")
        return

    # FIX: Import here at call-time (not module level) to avoid circular import.
    # Also import from the correct modules — not from a non-existent ".main".
    from analysis_engine import analyze_email
    from database import log_analysis
    from cli import print_report

    files = [f for f in os.listdir(folder) if f.endswith(".txt")]
    if not files:
        print("No .txt files found in this folder.")
        return

    for file in files:
        filepath = os.path.join(folder, file)
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            result = analyze_email(content)
            log_analysis(result)
            print(f"\n--- Analysis for: {file} ---")
            print_report(result)


def fetch_emails_imap(server, user, password, mailbox="INBOX", limit=5):
    try:
        mail = imaplib.IMAP4_SSL(server)
        mail.login(user, password)
        mail.select(mailbox)

        status, data = mail.search(None, "ALL")
        if status != "OK" or not data[0]:
            print("No emails found or failed to search.")
            return []

        ids = data[0].split()[-limit:]
        emails = []

        print(f"Fetching last {len(ids)} emails...")

        for eid in ids:
            _, msg_data = mail.fetch(eid, "(RFC822)")
            msg = py_email.message_from_bytes(msg_data[0][1])

            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode(errors="ignore")
                        break
            else:
                body = msg.get_payload(decode=True).decode(errors="ignore")

            if not body:
                body = "(No readable text content)"

            emails.append({
                "body": body,
                "sender_domain": get_sender_domain(str(msg))
            })

        mail.logout()
        return emails

    except Exception as e:
        print(f"IMAP Error: {e}")
        return []


# ===== WEB HELPERS =====

def read_txt_file(file_storage):
    """file_storage: Flask uploaded file (request.files[])"""
    return file_storage.read().decode("utf-8", errors="ignore")


def read_multiple_txt_files(files):
    contents = []
    for f in files:
        if f.filename.endswith(".txt"):
            contents.append(f.read().decode("utf-8", errors="ignore"))
    return contents


def fetch_gmail_web(user, app_password, limit=5):
    emails = fetch_emails_imap(
        server="imap.gmail.com",
        user=user,
        password=app_password,
        limit=limit
    )
    return [e["body"] for e in emails]
