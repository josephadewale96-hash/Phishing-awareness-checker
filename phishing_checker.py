from urllib.parse import urlparse
import re


def check_url(url):
    warnings = []

    # Add scheme if the user leaves it out
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # 1. Check for HTTPS
    if parsed.scheme != "https":
        warnings.append("The website does not use HTTPS.")

    # 2. Check for IP address instead of domain name
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        warnings.append("The URL uses an IP address instead of a normal domain name.")

    # 3. Check for @ symbol
    if "@" in url:
        warnings.append("The URL contains an @ symbol, which can be suspicious.")

    # 4. Check for unusually long URL
    if len(url) > 100:
        warnings.append("The URL is unusually long.")

    # 5. Check for many subdomains
    if domain.count(".") >= 3:
        warnings.append("The domain contains many subdomains.")

    # 6. Check for suspicious words
    suspicious_words = [
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "password",
        "confirm",
        "update",
        "bank",
        "payment",
        "signin"
    ]

    found_words = []

    for word in suspicious_words:
        if word in url.lower():
            found_words.append(word)

    if found_words:
        warnings.append(
            "The URL contains potentially suspicious words: "
            + ", ".join(found_words)
        )

    # 7. Check for hyphens
    if domain.count("-") >= 2:
        warnings.append("The domain contains several hyphens.")

    # Result
    if not warnings:
        return {
            "status": "LOW RISK",
            "warnings": []
        }

    if len(warnings) <= 2:
        status = "SUSPICIOUS"
    else:
        status = "HIGH RISK"

    return {
        "status": status,
        "warnings": warnings
    }


def main():
    print("=" * 50)
    print(" PHISHING AWARENESS CHECKER")
    print("=" * 50)

    url = input("\nEnter a website URL: ").strip()

    if not url:
        print("Please enter a URL.")
        return

    result = check_url(url)

    print("\nResult:", result["status"])

    if result["warnings"]:
        print("\nWarnings:")
        for warning in result["warnings"]:
            print("- " + warning)
    else:
        print("\nNo obvious warning signs were detected.")

    print("\nIMPORTANT:")
    print("This checker uses simple warning signs.")
    print("A LOW RISK result does not guarantee that a website is safe.")


if __name__ == "__main__":
    main()
