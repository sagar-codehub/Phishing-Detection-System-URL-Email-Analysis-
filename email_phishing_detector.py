import re
import urllib.parse


SUSPICIOUS_KEYWORDS = [
    "verify", "update", "confirm", "suspend", "login", "secure",
    "account", "password", "credit", "bank", "urgent", "click",
    "immediately", "limited", "offer", "winner", "free", "prize",
    "congratulations", "alert", "warning", "unusual", "activity"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click",
    ".download", ".link", ".online", ".site", ".info", ".biz"
]

TRUSTED_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "amazon.com",
    "microsoft.com", "apple.com", "github.com", "linkedin.com",
    "twitter.com", "instagram.com", "wikipedia.org", "reddit.com"
]


def extract_domain(url):
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    except Exception:
        return ""


def check_email(text):
    findings = []
    risk_score = 0
    lower = text.lower()

    urgency_phrases = [
        "act now", "immediately", "urgent", "as soon as possible",
        "account will be closed", "verify now", "confirm now",
        "limited time", "expires soon", "action required", "respond now"
    ]
    matched = [p for p in urgency_phrases if p in lower]
    if matched:
        findings.append("[HIGH]   Urgency language detected: {}.".format(", ".join(matched)))
        risk_score += 30

    threat_phrases = [
        "will be suspended", "permanently deleted", "account blocked",
        "unauthorized access", "your account has been", "security alert",
        "will be terminated", "legal action"
    ]
    matched = [p for p in threat_phrases if p in lower]
    if matched:
        findings.append("[HIGH]   Threat-based language to pressure the reader: {}.".format(", ".join(matched)))
        risk_score += 25

    prize_phrases = [
        "you have won", "you are selected", "free gift",
        "claim your prize", "congratulations", "lottery",
        "lucky winner", "reward waiting"
    ]
    matched = [p for p in prize_phrases if p in lower]
    if matched:
        findings.append("[HIGH]   Prize or reward bait language detected: {}.".format(", ".join(matched)))
        risk_score += 30

    personal_fields = [
        "social security", "ssn", "credit card", "debit card",
        "password", "pin number", "date of birth", "bank account",
        "card number", "cvv", "mother maiden"
    ]
    matched = [p for p in personal_fields if p in lower]
    if matched:
        findings.append("[HIGH]   Requests for sensitive personal information: {}.".format(", ".join(matched)))
        risk_score += 35

    urls_in_email = re.findall(r"https?://[^\s<>\"]+", text)
    suspicious_urls = []
    trusted_urls = []
    ip_urls = []
    for url in urls_in_email:
        domain = extract_domain(url)
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        if ip_pattern.match(hostname):
            ip_urls.append(url)
        elif any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            suspicious_urls.append(url)
        elif any(domain == t or domain.endswith("." + t) for t in TRUSTED_DOMAINS):
            trusted_urls.append(url)

    if ip_urls:
        findings.append("[HIGH]   URL(s) using raw IP addresses found: {}.".format(len(ip_urls)))
        risk_score += 30
    if suspicious_urls:
        findings.append("[HIGH]   URL(s) with suspicious domains found: {}.".format(len(suspicious_urls)))
        risk_score += 25
    if trusted_urls:
        findings.append("[OK]     URL(s) from trusted domains found: {}.".format(len(trusted_urls)))
    if urls_in_email and not suspicious_urls and not ip_urls and not trusted_urls:
        findings.append("[LOW]    Email contains {} URL(s). Verify they are legitimate.".format(len(urls_in_email)))
        risk_score += 5

    sender_match = re.search(r"from\s*:?\s*([^\n<]+)?<([^>]+)>", text, re.IGNORECASE)
    if sender_match:
        sender_email = sender_match.group(2).lower()
        sender_name = (sender_match.group(1) or "").strip().lower()
        sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""
        for trusted in TRUSTED_DOMAINS:
            base = trusted.split(".")[0]
            if base in sender_name and sender_domain != trusted:
                findings.append("[HIGH]   Sender name claims to be '{}' but email domain is '{}'.".format(trusted, sender_domain))
                risk_score += 35
                break
        if any(c in sender_email for c in ["0", "1"]):
            if re.search(r"(paypa[l1]|app[l1]e|goog[l1]e|m[i1]crosoft)", sender_email):
                findings.append("[HIGH]   Sender email uses character substitution to fake a brand.")
                risk_score += 30

    keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower]
    if len(keyword_hits) >= 5:
        findings.append("[MEDIUM] High density of suspicious keywords: {}.".format(", ".join(keyword_hits[:6])))
        risk_score += 20
    elif len(keyword_hits) >= 2:
        findings.append("[LOW]    Some suspicious keywords present: {}.".format(", ".join(keyword_hits[:3])))
        risk_score += 8

    grammar_errors = len(re.findall(r"\b(\w+)\s+\1\b", lower))
    if grammar_errors >= 2:
        findings.append("[LOW]    Email contains repeated words, possibly indicating poor grammar.")
        risk_score += 5

    if len(text) < 80 and urls_in_email:
        findings.append("[MEDIUM] Very short email body with a URL. Common in phishing attempts.")
        risk_score += 15

    if not findings:
        findings.append("[OK]     No phishing indicators detected in this email.")

    return findings, min(risk_score, 100)


def classify(score):
    if score <= 30:
        return "SAFE"
    elif score <= 65:
        return "SUSPICIOUS"
    else:
        return "DANGEROUS"


def print_line():
    print("-" * 60)


def display_result(findings, risk_score):
    verdict = classify(risk_score)
    print_line()
    print("Findings:")
    for f in findings:
        print("  " + f)
    print_line()
    print("Risk Score : {}/100".format(risk_score))
    print("Verdict    : {}".format(verdict))
    print_line()
    messages = {
        "SAFE":       "No significant threats found. This email appears safe.",
        "SUSPICIOUS": "Caution advised. This email has suspicious characteristics.",
        "DANGEROUS":  "High risk. Do not click links or reply to this email."
    }
    print("Summary    :", messages[verdict])
    print_line()


def get_email_input():
    print("\nPaste the email content below.")
    print("Include From, Subject, and body if available.")
    print("Type END on a new line when done:")
    print()
    lines = []
    while True:
        line = input()
        if line.strip().upper() == "END":
            break
        lines.append(line)
    return "\n".join(lines)


def main():
    print("=" * 60)
    print("  Email Phishing Detector")
    print("  Checks email content for phishing and social engineering")
    print("=" * 60)

    while True:
        print("\nOptions:")
        print("  1. Analyze an email")
        print("  2. Exit")
        choice = input("Enter choice (1/2): ").strip()

        if choice == "2":
            print("Exiting. Stay safe online.")
            break
        elif choice == "1":
            email_text = get_email_input()
            if not email_text.strip():
                print("No content entered. Please try again.")
                continue
            print_line()
            print("EMAIL PHISHING DETECTOR - Analysis Report")
            findings, risk_score = check_email(email_text)
            display_result(findings, risk_score)
        else:
            print("Invalid choice. Enter 1 or 2.")
            continue

        again = input("\nAnalyze another email? (y/n): ").strip().lower()
        if again != "y":
            print("Exiting. Stay safe online.")
            break


if __name__ == "__main__":
    main()
