#cli.py
import re
from urllib.parse import urlparse
import tldextract
from colorama import init, Fore, Style

init(autoreset=True)

from load_data import (
    analyze_single_paste,
    analyze_single_file,
    analyze_batch_folder,
    fetch_emails_imap,
)
from analysis_engine import analyze_email
from database import log_analysis


# ---------------- REPORT ----------------
def print_report(result):
    print("\n================ EMAIL CONTENT =================")
    print(result["email_content"])
    print("================================================")

    if result["decision"] == "Phishing":
        decision_color = Fore.RED
    elif result["decision"] == "Suspicious":
        decision_color = Fore.YELLOW
    else:
        decision_color = Fore.GREEN

    print("\n================ PHISHING ANALYSIS REPORT ================\n")
    print(f"Final Decision      : {decision_color}{result['decision']}{Style.RESET_ALL}")
    print(f"Combined Risk Score : {result['risk_score']}\n")
    print(f"Phishing %          : {result['phishing_pct']}%")
    print(f"Suspicious %        : {result['suspicious_pct']}%")
    print(f"Legitimate %        : {result['legit_pct']}%\n")
    print(f"Rule-based Score    : {result['rule_score']}\n")
    print("ML Predictions:")
    print(" - Hugging Face Model: ",  result["huggingface_probs"])
    print(" - Trained Model:      ",  result["trained_probs"])
    print(" - Combined (Weighted):",  result["ml_probs_combined"], "\n")

    print("Detected Keywords:")
    if result["keywords"]:
        for k in result["keywords"]:
            print(f"  - {k}")
    else:
        print("  - None")

    print("\nLinks:")
    if result["links"]:
        for l in result["links"]:
            print(f"  - {l['url']} -> {l['status']}")
    else:
        print("  - No links detected")

    print("\nEmotion Probabilities:")
    for emotion, score in result["emotions"].items():
        print(f"  - {emotion.title():<10}: {round(score, 3)}")

    print("\nBrand Verification:")
    print(f"  - {result['brand_verified']}")

    # FIX: 'explain' key was missing from original analyze_email result dict.
    # Now safely accessed with .get() as a fallback guard.
    explanations = result.get("explain", [])
    print("\nExplanations:")
    if explanations:
        for e in explanations:
            print(f"  - {e}")
    else:
        print("  - No additional explanations.")

    print("\nNote:")
    print(f"  {result['note']}")
    print("\n=========================================================\n")


# ---------------- MAIN MENU ----------------
def main():
    print("\n=== EMAIL PHISHING DETECTION SYSTEM ===\n")
    print("1. Single email (paste text)")
    print("2. Single email from .txt file")
    print("3. Batch analyze folder (.txt files)")
    print("4. Automated email fetching via IMAP")

    choice = input("\nEnter choice: ").strip()

    if choice == "1":
        result = analyze_email(analyze_single_paste())
        log_analysis(result)
        print_report(result)

    elif choice == "2":
        result = analyze_email(analyze_single_file())
        log_analysis(result)
        print_report(result)

    elif choice == "3":
        analyze_batch_folder()

    elif choice == "4":
        server      = input("IMAP server (e.g., imap.gmail.com): ").strip()
        user        = input("Email: ").strip()
        from getpass import getpass
        password    = getpass("Password / App password: ")
        limit_input = input("Number of latest emails: ").strip()
        limit       = int(limit_input) if limit_input.isdigit() else 5

        emails = fetch_emails_imap(server, user, password, limit=limit)
        for i, mail in enumerate(emails, 1):
            print(f"\n--- Email #{i} ---")
            result = analyze_email(mail["body"])
            log_analysis(result)
            print_report(result)
    else:
        print("Invalid choice")


if __name__ == "__main__":
    main()
