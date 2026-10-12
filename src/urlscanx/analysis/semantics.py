"""Local control semantics; page text and request activity are never inputs."""

import re

AUTOCOMPLETE_ROLES = {
    "username": "username", "identifier": "username", "email": "email",
    "current-password": "password", "new-password": "password",
    "one-time-code": "otp_candidate", "cc-number": "payment_pan",
    "cc-exp": "payment_expiry", "cc-exp-month": "payment_expiry", "cc-exp-year": "payment_expiry",
    "cc-csc": "payment_cvc", "name": "person_name", "given-name": "person_name",
    "family-name": "person_name", "cc-name": "person_name", "organization": "company",
    "postal-code": "postal_code", "tel": "phone", "tel-national": "phone",
    "tel-country-code": "phone", "tel-local": "phone",
}
# Ordering avoids promoting CAPTCHA/postal/card codes into OTP candidates.
LOCAL_RULES = (
    ("captcha_or_challenge", r"\b(?:captcha|recaptcha|hcaptcha|security challenge|challenge code|human verification)\b"),
    ("postal_code", r"\b(?:postal code|postalcode|zip code|zipcode)\b"),
    ("payment_cvc", r"\b(?:cvc|cvv|card cvc|card cvv|card security code)\b"),
    ("payment_pan", r"\b(?:pan|card number|cardnumber)\b"),
    ("payment_expiry", r"\b(?:expiry|expiration|card exp|mm / yy)\b"),
    ("password", r"\b(?:password|passwd)\b"),
    ("otp_candidate", r"\b(?:otp|passcode|one time code|authentication code|authenticationcode|verification code|verificationcode|authenticator|two factor|2fa)\b"),
    ("email", r"\b(?:email|e mail)\b"),
    ("username", r"\b(?:username|user name|identifier|loginfmt)\b"),
    ("phone", r"\b(?:phone|telephone)\b"),
    ("company", r"\b(?:company|organization)\b"),
    ("person_name", r"\b(?:first name|last name|full name|billing name|given name|family name)\b"),
    ("contact_data", r"\b(?:contact|address|country|city)\b"),
)

TEXT_ENTRY_TYPES = frozenset({"", "text", "search", "email", "tel", "url", "number", "password", "hidden"})
SELECT_ROLES = frozenset({"payment_expiry", "company", "postal_code", "contact_data"})


def compatible(tag: str, kind: str, role: str) -> bool:
    """A local word cannot turn a toggle, upload or action into a value-entry field."""
    if tag == "textarea":
        return True
    if tag == "select":
        # Country/company/postal selections and expiry selectors are meaningful;
        # password/email/PAN/OTP selectors do not establish those entry semantics.
        return role in SELECT_ROLES
    if tag == "input":
        return kind in TEXT_ENTRY_TYPES or (kind in {"date", "datetime-local", "month", "time", "week"}
                                           and role == "payment_expiry")
    return False


def classify(tag: str, attrs: dict, associated: list[dict]) -> tuple[str, list[dict]]:
    kind = attrs.get("type", "text").lower()
    if kind == "password" and tag == "input":
        return "password", [{"source": "attribute", "attribute": "type", "rule": "password"}]
    autos = attrs.get("autocomplete", "").lower().split()
    # Auth/payment autocomplete is stronger than weak name/label matches.
    for token in autos:
        if token in AUTOCOMPLETE_ROLES and compatible(tag, kind, AUTOCOMPLETE_ROLES[token]):
            return AUTOCOMPLETE_ROLES[token], [{"source": "attribute", "attribute": "autocomplete", "rule": token}]
    if tag == "input" and kind == "email":
        return "email", [{"source": "attribute", "attribute": "type", "rule": "email"}]
    sources = [{"source": "attribute", "attribute": key, "text": attrs.get(key, "")}
               for key in ("name", "id", "placeholder", "aria-label")] + associated
    for role, pattern in LOCAL_RULES:
        if not compatible(tag, kind, role):
            continue
        support = []
        for source in sources:
            words = re.sub(r"([a-z])([A-Z])", r"\1 \2", source["text"][:1000])
            words = re.sub(r"[_-]+", " ", words).lower()
            if re.search(pattern, words):
                support.append({k: v for k, v in source.items() if k != "text"} | {"rule": role})
        if support:
            return role, support
    # Length/pattern/inputmode alone do not establish OTP, PAN or CVC semantics.
    return ("generic_text" if tag == "textarea" or kind in {"text", "search", "number", ""} and tag == "input"
            else "unknown"), []
