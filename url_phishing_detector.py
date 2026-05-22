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
    hostname = parsed.hostname or ""

    if parsed.scheme == "http":
        findings.append("[HIGH]   Connection is not encrypted (HTTP instead of HTTPS).")
        risk_score += 20
    elif parsed.scheme == "https":
        findings.append("[OK]     Connection uses HTTPS.")
    else:
        findings.append("[MEDIUM] URL has an unrecognized or missing scheme.")
        risk_score += 10

    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    if ip_pattern.match(hostname):
        findings.append("[HIGH]   URL uses a raw IP address instead of a domain name.")
        risk_score += 30

    if len(url) > 75:
        findings.append("[MEDIUM] URL is unusually long ({} characters).".format(len(url)))
        risk_score += 15

    subdomain_count = domain.count(".")
    if subdomain_count > 3:
        findings.append("[MEDIUM] URL contains an excessive number of subdomains ({}).".format(subdomain_count))
        risk_score += 15

    for trusted in TRUSTED_DOMAINS:
        base = trusted.split(".")[0]
        if base in domain and domain != trusted and not domain.endswith("." + trusted):
            findings.append("[HIGH]   Domain impersonates a trusted brand: '{}'.".format(trusted))
            risk_score += 35
            break

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            findings.append("[MEDIUM] Domain uses a suspicious top-level domain: '{}'.".format(tld))
            risk_score += 20
            break

    if re.search(r"[@%]", url):
        suspicious_chars = re.findall(r"[@%]", url)
        findings.append("[HIGH]   URL contains suspicious characters: {}.".format(", ".join(set(suspicious_chars))))
        risk_score += 25

    if re.search(r"(?<!:)//", url):
        findings.append("[MEDIUM] URL contains double slashes, possibly used for redirect tricks.")
        risk_score += 15

    if re.search(r"-{2,}", domain):
        findings.append("[MEDIUM] Domain contains multiple consecutive hyphens.")
        risk_score += 10

    digit_ratio = sum(c.isdigit() for c in domain) / max(len(domain), 1)
    if digit_ratio > 0.4:
        findings.append("[MEDIUM] Domain contains an unusually high number of digits.")
        risk_score += 15

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            findings.append("[LOW]    URL path contains suspicious keyword: '{}'.".format(keyword))
            risk_score += 5
            break

    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith("." + trusted):
            findings.append("[OK]     Domain matches a known trusted website: '{}'.".format(trusted))
            risk_score = max(0, risk_score - 20)
            break

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


def display_result(url, findings, risk_score):
    verdict = classify(risk_score)
    print_line()
    print("URL PHISHING DETECTOR - Analysis Report")
    print_line()
    print("URL     : {}".format(url[:55] + "..." if len(url) > 55 else url))
    print_line()
    print("Findings:")
    for f in findings:
        print("  " + f)
    print_line()
    print("Risk Score : {}/100".format(risk_score))
    print("Verdict    : {}".format(verdict))
    print_line()
    messages = {
        "SAFE":       "No significant threats detected. This URL appears safe.",
        "SUSPICIOUS": "Caution advised. This URL has suspicious characteristics.",
        "DANGEROUS":  "High risk. Do not visit or share this URL."
    }
    print("Summary    :", messages[verdict])
    print_line()


def main():
    print("=" * 60)
    print("  URL Phishing Detector")
    print("  Checks URLs for phishing and social engineering signals")
    print("=" * 60)

    while True:
        print("\nOptions:")
        print("  1. Analyze a URL")
        print("  2. Exit")
        choice = input("Enter choice (1/2): ").strip()

        if choice == "2":
            print("Exiting. Stay safe online.")
            break
        elif choice == "1":
            url = input("Enter URL: ").strip()
            if not url:
                print("No URL entered. Please try again.")
                continue
            if not url.startswith("http"):
                url = "http://" + url
                print("Note: Scheme not found. Assuming HTTP.")
            findings, risk_score = check_url(url)
            display_result(url, findings, risk_score)
        else:
            print("Invalid choice. Enter 1 or 2.")

        again = input("\nAnalyze another URL? (y/n): ").strip().lower()
        if again != "y":
            print("Exiting. Stay safe online.")
            break


if __name__ == "__main__":
    main()
