import re
import urllib.parse


SUSPICIOUS_KEYWORDS = [
    "verify", "update", "confirm", "suspend", "login", "secure",
    "account", "password", "credit", "bank", "urgent", "click",
    "immediately", "limited", "offer", "winner", "free", "prize",
    "congratulations", "alert", "warning", "unusual", "activity"
]

TRUSTED_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "amazon.com",
    "microsoft.com", "apple.com", "github.com", "linkedin.com",
    "twitter.com", "instagram.com", "wikipedia.org", "reddit.com"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click",
    ".download", ".link", ".online", ".site", ".info", ".biz"
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


def check_url(url):
    findings = []
    risk_score = 0

    parsed = urllib.parse.urlparse(url)
    domain = extract_domain(url)

    if parsed.scheme == "http":
        findings.append("[HIGH] Connection is not encrypted (HTTP instead of HTTPS).")
        risk_score += 20
    elif parsed.scheme == "https":
        findings.append("[OK] Connection uses HTTPS.")

    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    hostname = parsed.hostname or ""
    if ip_pattern.match(hostname):
        findings.append("[HIGH] URL uses a raw IP address instead of a domain name.")
        risk_score += 30

    if len(url) > 75:
        findings.append("[MEDIUM] URL is unusually long ({} characters).".format(len(url)))
        risk_score += 15

    if url.count(".") > 4:
        findings.append("[MEDIUM] URL contains an excessive number of subdomains.")
        risk_score += 15

    for trusted in TRUSTED_DOMAINS:
        base = trusted.split(".")[0]
        if base in domain and domain != trusted and not domain.endswith("." + trusted):
            findings.append("[HIGH] Domain impersonates a trusted brand: '{}'.".format(trusted))
            risk_score += 35
            break

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            findings.append("[MEDIUM] Domain uses a suspicious top-level domain: '{}'.".format(tld))
            risk_score += 20
            break

    suspicious_chars = re.findall(r"[@%]", url)
    if suspicious_chars:
        findings.append("[HIGH] URL contains suspicious characters: {}.".format(", ".join(set(suspicious_chars))))
        risk_score += 25

    double_slash = re.findall(r"(?<!:)//", url)
    if double_slash:
        findings.append("[MEDIUM] URL contains double slashes which may be used to redirect.")
        risk_score += 15

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            findings.append("[LOW] URL contains suspicious keyword: '{}'.".format(keyword))
            risk_score += 5
            break

    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith("." + trusted):
            findings.append("[OK] Domain matches a known trusted website: '{}'.".format(trusted))
            risk_score = max(0, risk_score - 20)
            break

    return findings, min(risk_score, 100)


def check_email(text):
    findings = []
    risk_score = 0
    lower_text = text.lower()

    urgency_phrases = [
        "act now", "immediately", "urgent", "as soon as possible",
        "account will be closed", "verify now", "confirm now",
        "limited time", "expires", "action required"
    ]
    matched_urgency = [p for p in urgency_phrases if p in lower_text]
    if matched_urgency:
        findings.append("[HIGH] Email uses urgency language: {}.".format(", ".join(matched_urgency)))
        risk_score += 30

    threat_phrases = [
        "will be suspended", "permanently deleted", "blocked",
        "unauthorized access", "your account has been", "security alert"
    ]
    matched_threats = [p for p in threat_phrases if p in lower_text]
    if matched_threats:
        findings.append("[HIGH] Email contains threat language to pressure the reader.")
        risk_score += 25

    prize_phrases = [
        "you have won", "you are selected", "free gift",
        "claim your prize", "congratulations", "lottery"
    ]
    matched_prize = [p for p in prize_phrases if p in lower_text]
    if matched_prize:
        findings.append("[HIGH] Email contains prize or reward bait language.")
        risk_score += 30

    urls_in_email = re.findall(r"https?://[^\s]+", text)
    suspicious_url_count = 0
    for url in urls_in_email:
        domain = extract_domain(url)
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                suspicious_url_count += 1
                break
        ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        hostname = urllib.parse.urlparse(url).hostname or ""
        if ip_pattern.match(hostname):
            suspicious_url_count += 1
    if suspicious_url_count > 0:
        findings.append("[HIGH] Email contains {} suspicious URL(s).".format(suspicious_url_count))
        risk_score += 25
    elif urls_in_email:
        findings.append("[LOW] Email contains {} URL(s) — verify they lead to legitimate sites.".format(len(urls_in_email)))
        risk_score += 5

    keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower_text]
    if len(keyword_hits) >= 4:
        findings.append("[MEDIUM] Email contains multiple suspicious keywords: {}.".format(", ".join(keyword_hits[:5])))
        risk_score += 20
    elif keyword_hits:
        findings.append("[LOW] Email contains some sensitive keywords: {}.".format(", ".join(keyword_hits[:3])))
        risk_score += 8

    personal_requests = ["ssn", "social security", "credit card", "password", "pin number", "date of birth"]
    matched_personal = [p for p in personal_requests if p in lower_text]
    if matched_personal:
        findings.append("[HIGH] Email requests sensitive personal information: {}.".format(", ".join(matched_personal)))
        risk_score += 35

    if not findings:
        findings.append("[OK] No obvious phishing indicators detected in the email text.")

    return findings, min(risk_score, 100)


def classify(risk_score):
    if risk_score <= 30:
        return "SAFE"
    elif risk_score <= 65:
        return "SUSPICIOUS"
    else:
        return "DANGEROUS"


def print_separator():
    print("-" * 55)


def analyze(input_text, mode):
    print_separator()
    print("Phishing Detection System")
    print_separator()
    print("Mode    : {}".format(mode.upper()))
    print("Input   : {}".format(input_text[:60] + "..." if len(input_text) > 60 else input_text))
    print_separator()

    if mode == "url":
        findings, risk_score = check_url(input_text)
    else:
        findings, risk_score = check_email(input_text)

    verdict = classify(risk_score)

    print("Findings:")
    for finding in findings:
        print("  " + finding)

    print_separator()
    print("Risk Score : {}/100".format(risk_score))
    print("Verdict    : {}".format(verdict))
    print_separator()

    if verdict == "SAFE":
        print("Result: No significant threats found. Appears to be safe.")
    elif verdict == "SUSPICIOUS":
        print("Result: Some red flags detected. Proceed with caution.")
    else:
        print("Result: High risk detected. Do not interact with this input.")

    print_separator()


def get_mode():
    while True:
        print("\nSelect analysis mode:")
        print("  1. URL")
        print("  2. Email")
        print("  3. Exit")
        choice = input("Enter choice (1/2/3): ").strip()
        if choice == "1":
            return "url"
        elif choice == "2":
            return "email"
        elif choice == "3":
            return None
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")


def main():
    print("=" * 55)
    print("  Phishing Detection System")
    print("  Analyzes URLs and emails for phishing indicators")
    print("=" * 55)

    while True:
        mode = get_mode()
        if mode is None:
            print("Exiting. Stay safe online.")
            break

        if mode == "url":
            user_input = input("Enter URL to analyze: ").strip()
        else:
            print("Paste email content below.")
            print("Type END on a new line when done:")
            lines = []
            while True:
                line = input()
                if line.strip().upper() == "END":
                    break
                lines.append(line)
            user_input = "\n".join(lines)

        if not user_input:
            print("No input provided. Please try again.")
            continue

        analyze(user_input, mode)

        again = input("\nAnalyze another? (y/n): ").strip().lower()
        if again != "y":
            print("Exiting. Stay safe online.")
            break


if __name__ == "__main__":
    main()
