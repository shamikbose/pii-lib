import json
import ipaddress
import random
import string
from collections.abc import Iterable
from utils.emails_ip_addresses_detection import detect_email_addresses
from utils.keys_detection import detect_keys

_REPLACEMENTS_IP = {
    "IPv4": [
        "172.16.31.10",
        "172.16.58.3",
        "172.16.17.32",
        "192.168.127.12",
        "192.168.3.11",
    ],
    "IPv6": [
        "fd00:c2b6:b24b:be67:2827:688d:e6a1:6a3b",
        "fd00:a516:7c1b:17cd:6d81:2137:bd2a:2c5b",
        "fc00:e968:6179::de52:7100",
        "fc00:db20:35b:7399::5",
        "fdf8:f53e:61e4::18",
    ],
}

# providergs = ["google", "cloudfare", "alternate-dns", "quad9","open-dns", "comodo", "adguard"]
_POPULAR_DNS_SERVERS = [
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "76.76.19.19",
    "76.223.122.150",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "8.26.56.26",
    "8.20.247.20",
    "94.140.14.14",
    "94.140.15.15",
]


def _postprocess_secrets(secrets):
    if secrets:
        matches = json.dumps(secrets)
        has_secrets = True
    else:
        matches = json.dumps([])
        has_secrets = False
    return matches, has_secrets


def _random_replacements(n=10):
    """Build dictionaries of random replacements for PII (key, email, IP address)

    Emails: replace with one of n [random string of 5 characters + @example.com]
    IP addresses: replace with one of n synthetic private IP addresses (IPv4 or IPv6)
    Keys: replace with one of n [sequence of 32 random characters/digits]

    TODO: add IPv6 and IPv4 separation
    """
    letters = string.ascii_lowercase
    lettters_digits = string.ascii_lowercase + string.digits
    emails = [
        "".join(random.choice(letters) for i in range(5)) + "@example.com"
        for i in range(n)
    ]
    keys = [
        "".join(random.choice(lettters_digits) for i in range(32)) for i in range(n)
    ]
    ip_addresses = _REPLACEMENTS_IP
    return {"EMAIL": emails, "KEY": keys, "IP_ADDRESS": ip_addresses}


def _load_json(sample):
    try:
        return json.loads(sample)
    except ValueError:
        return []


def _is_private_ip(ip):
    """Check if an IP address is allocated for private networks"""
    ip = ipaddress.ip_address(ip)
    return ip.is_private


def _replace_ip(value, replacements_dict):
    """Replace an IP address with a synthetic IP address of the same format"""
    try:
        ipaddress.IPv4Address(value)
        return random.choice(replacements_dict["IP_ADDRESS"]["IPv4"])
    except ValueError:
        try:
            ipaddress.IPv6Address(value)
            return random.choice(replacements_dict["IP_ADDRESS"]["IPv6"])
        except ValueError:
            # this doesn't happen if we already use ipaddress filter in the detection
            print("Invalid IP address")
            return value


def _detect_batch(examples, key_detector):
    list_secrets = []
    list_has_secrets = []
    number_secrets = []
    for text in examples["content"]:
        matches, has_secrets, secret_count = _detect_text(text, key_detector)
        list_secrets.append(matches)
        list_has_secrets.append(has_secrets)
        number_secrets.append(secret_count)
    return {
        "secrets": list_secrets,
        "has_secrets": list_has_secrets,
        "number_secrets": number_secrets,
    }


def _detect_text(text, key_detector):
    secrets = []
    if key_detector == "regex":
        secrets += detect_email_addresses(
            text, tag_types={"KEY", "EMAIL", "IP_ADDRESS"}
        )
    else:
        secrets += detect_email_addresses(text, tag_types={"EMAIL", "IP_ADDRESS"})
        secrets += detect_keys(text)
    matches, has_secrets = _postprocess_secrets(secrets)
    return matches, has_secrets, len(secrets)


def detect(input_value, key_detector="other"):
    """
    Detect PII in text or an Iterable object
    Args:
        input_value (str/Iterable): Text or Iterable in which to detect PII
        key_detection (str): Method used to look for secret keys. default: "other", options are "regex" and "other"
    Returns:
        dictionary: In case of Iterable input_value, keys are column names

    This function takes in a batch of examples and detects different kinds of PII, such as DNS addresses, emails, etc.
    This add two columns to the dataset:
    - secrets: (list) of secrets/PII found
    - has_secrets: (bool) whether the example contains secrets/PII
    """
    if type(input_value) == str:
        # For when input value is a string
        matches, has_secrets, secret_count = _detect_text(input_value, key_detector)
        return {
            "secrets": matches,
            "has_secrets": has_secrets,
            "number_secrets": [secret_count],
        }
    elif isinstance(input_value, Iterable):
        # For other kind of iterable e.g. huggingface datasets
        return _detect_batch(input_value, key_detector)


def _redact_batch():
    pass


def _redact_text():
    pass


def redact(input_value, secrets, replacements, add_references=False):
    """Redact PII in an input
    Args:
        input_value: text/Iterable to redact
        secrets (json): json string with the secrets to redact
        replacements (dict): dictionary of replacements for each PII type
        add_references (bool): whether to add references to the redacted text (delimiters to PII)
        for vizualization
    Returns:
        text (str): new text with redacted secrets
    """
