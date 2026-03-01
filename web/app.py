import os
import re
import sys
from flask import Flask, render_template, request

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR  = os.path.join(BASE_DIR, "src")

if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from analysis_engine import analyze_email
from database import get_all_analysis, log_analysis
from load_data import read_txt_file, read_multiple_txt_files, fetch_gmail_web

app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static"
)


# --------------------------------------------------
# Input Validator
# --------------------------------------------------
def is_valid_email_text(text):
    has_sender  = bool(re.search(r'@[\w.-]+\.[a-z]{2,}', text, re.IGNORECASE))
    has_content = len(text.strip().split()) > 10
    return has_sender or has_content


# --------------------------------------------------
# Dashboard
# --------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def dashboard():
    result   = None
    results  = None   # STEP 6: for batch upload — multiple results
    warning  = None

    if request.method == "POST":
        text = request.form.get("email_text")
        mode = request.form.get("mode")

        # 1️⃣ Textarea input
        if text and text.strip():
            if not is_valid_email_text(text.strip()):
                warning = "⚠️ Please paste a proper email with sufficient content."
                return render_template("dashboard.html", result=None, warning=warning)
            result = analyze_email(text.strip())
            log_analysis(result)

        # 2️⃣ Single file upload
        elif mode == "file":
            file = request.files.get("txt_file")
            if file:
                content = file.read().decode("utf-8", errors="ignore")
                if not is_valid_email_text(content):
                    warning = "⚠️ The uploaded file does not appear to contain a valid email."
                    return render_template("dashboard.html", result=None, warning=warning)
                result = analyze_email(content)
                log_analysis(result)
            else:
                warning = "⚠️ No file selected. Please upload a .txt file."

        # STEP 6: Batch file upload — multiple .txt files at once
        elif mode == "batch":
            files = request.files.getlist("batch_files")
            if not files or all(f.filename == "" for f in files):
                warning = "⚠️ No files selected for batch upload."
            else:
                contents = read_multiple_txt_files(files)
                if not contents:
                    warning = "⚠️ No valid .txt files found in selection."
                else:
                    results = []
                    for content in contents:
                        if is_valid_email_text(content):
                            r = analyze_email(content)
                            log_analysis(r)
                            results.append(r)
                    if not results:
                        warning = "⚠️ None of the uploaded files contained valid email content."

        # 3️⃣ Gmail fetch
        elif mode == "gmail":
            user     = request.form.get("gmail_address")
            password = request.form.get("gmail_password")

            if not user or not password:
                warning = "⚠️ Please enter both Gmail address and app password."
                return render_template("dashboard.html", result=None, warning=warning)

            warning = "ℹ️ Your Gmail app-password is used only for this IMAP fetch and is never stored."
            emails  = fetch_gmail_web(user, password)
            if emails:
                result = analyze_email(emails[0])
                log_analysis(result)
            else:
                warning = "⚠️ No emails found or could not connect to Gmail."

        else:
            warning = "⚠️ Please paste an email or select an input type."

    return render_template("dashboard.html", result=result, results=results, warning=warning)


# --------------------------------------------------
# History
# --------------------------------------------------
@app.route("/history", methods=["GET"])
def history():
    selected_date = request.args.get("date")
    records, phishing_count, legit_count, suspicious_count = get_all_analysis(selected_date)
    return render_template(
        "history.html",
        records=records,
        phishing_count=phishing_count,
        legit_count=legit_count,
        suspicious_count=suspicious_count,
    )


# --------------------------------------------------
# Run server
# --------------------------------------------------
if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_DEBUG", "true").lower() == "true"
    app.run(host="127.0.0.1", port=5000, debug=debug_mode)
