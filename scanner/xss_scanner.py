import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
import warnings

warnings.filterwarnings("ignore", message="Unverified HTTPS request")


# -----------------------------------------------------------
# Submit HTML Form With Injected Payload
# -----------------------------------------------------------
def submit(form, url, method, inputs, payload):
    action = form.get("action")
    target_url = urljoin(url, action)

    data = {}

    for name, value in inputs.items():
        if value == "input_text":
            data[name] = payload
        else:
            data[name] = value

    try:
        if method.lower() == "post":
            return requests.post(target_url, data=data, verify=False, timeout=6)
        else:
            return requests.get(target_url, params=data, verify=False, timeout=6)

    except Exception:
        return None


# -----------------------------------------------------------
# Extract Forms From a Web Page
# -----------------------------------------------------------
def extract_forms(url):
    try:
        response = requests.get(url, verify=False, timeout=6)
        soup = BeautifulSoup(response.text, "html.parser")
        return soup.find_all("form")
    except Exception:
        return []


# -----------------------------------------------------------
# Extract Input Fields From Each Form
# -----------------------------------------------------------
def extract_inputs(form):
    inputs = {}

    for input_tag in form.find_all("input"):
        name = input_tag.get("name")
        input_type = input_tag.get("type", "text")

        if not name:
            continue

        if input_type in ("text", "search", "email"):
            inputs[name] = "input_text"
        else:
            inputs[name] = input_tag.get("value", "")

    return inputs


# -----------------------------------------------------------
# Inject payload into URL GET parameters
# -----------------------------------------------------------
def inject_get(url, payload):
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)

        if not qs:
            return None

        # Replace each GET parameter with payload
        new_qs = {k: payload for k in qs.keys()}

        new_url = parsed._replace(query=urlencode(new_qs, doseq=True)).geturl()
        response = requests.get(new_url, verify=False, timeout=6)

        if payload in response.text:
            return {
                "target": url,
                "payload": payload,
                "method": "GET",
                "vulnerable": True,
                "description": "Reflected XSS via URL parameter"
            }
    except Exception:
        return None


# -----------------------------------------------------------
# Main XSS Scanner
# -----------------------------------------------------------
def scan_xss(root_url, payloads=None, max_pages=20):
    if payloads is None:
        payloads = [
            "<script>alert(1)</script>",
            "'\"><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "><svg/onload=alert(1)>",
        ]

    results = []
    visited = set()
    pages_to_visit = [root_url]

    while pages_to_visit and len(visited) < max_pages:
        url = pages_to_visit.pop()

        if url in visited:
            continue

        visited.add(url)

        # -------------------------
        # Test GET parameter XSS
        # -------------------------
        for payload in payloads:
            injected = inject_get(url, payload)
            if injected:
                results.append(injected)

        # -------------------------
        # Scan forms on the page
        # -------------------------
        forms = extract_forms(url)

        for form in forms:
            try:
                method = form.get("method", "get")
                inputs = extract_inputs(form)

                for payload in payloads:
                    response = submit(form, url, method, inputs, payload)
                    if response and payload in response.text:
                        results.append({
                            "target": url,
                            "payload": payload,
                            "method": method,
                            "vulnerable": True,
                            "description": "Reflected XSS found in HTML form"
                        })
            except Exception:
                pass

        # -------------------------
        # Crawl site links
        # -------------------------
        try:
            page = requests.get(url, verify=False, timeout=6)
            soup = BeautifulSoup(page.text, "html.parser")

            for a in soup.find_all("a", href=True):
                next_url = urljoin(root_url, a["href"])
                if urlparse(next_url).netloc == urlparse(root_url).netloc:
                    pages_to_visit.append(next_url)
        except Exception:
            pass

    # -------------------------
    # Deduplicate results
    # -------------------------
    unique = []
    seen = set()

    for r in results:
        key = (r["target"], r["payload"], r["description"])
        if key not in seen:
            seen.add(key)
            unique.append(r)

    return unique