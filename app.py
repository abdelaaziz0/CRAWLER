from flask import Flask, render_template, request, redirect, url_for
import hashlib
import requests
import re
from urllib.parse import urljoin, urlparse

requests.packages.urllib3.disable_warnings()

#####################################
# Module Crawler
#####################################
class Crawler:
    """
    Crawler basique pour découvrir les pages et endpoints d'un site.
    """
    def __init__(self, base_url, max_depth=1, timeout=5):
        self.base_url = base_url
        self.max_depth = max_depth
        self.timeout = timeout
        self.visited = set()
        self.to_visit = [(base_url, 0)]
        self.endpoints = []

    def is_valid_url(self, url):
        parsed = urlparse(url)
        base_domain = urlparse(self.base_url).netloc
        return bool(parsed.netloc) and bool(parsed.scheme) and (base_domain in parsed.netloc)

    def crawl(self):
        while self.to_visit:
            current_url, depth = self.to_visit.pop(0)
            if depth > self.max_depth:
                continue
            if current_url in self.visited:
                continue
            self.visited.add(current_url)
            try:
                r = requests.get(current_url, timeout=self.timeout, verify=False)
                if r.status_code == 200:
                    self.endpoints.append(current_url)
                    for link in self.extract_links(current_url, r.text):
                        if link not in self.visited:
                            self.to_visit.append((link, depth + 1))
            except requests.exceptions.RequestException:
                pass
        return self.endpoints

    def extract_links(self, current_url, html_content):
        links = re.findall(r'href="(.*?)"', html_content, re.IGNORECASE)
        found = []
        for link in links:
            absolute_url = urljoin(current_url, link)
            if self.is_valid_url(absolute_url):
                found.append(absolute_url)
        return found

#####################################
# Module Scanner
#####################################
class VulnerabilityResult:
    def __init__(self, url, vuln_type, payload="", cvss_score=None):
        self.url = url
        self.vuln_type = vuln_type
        self.payload = payload
        self.cvss_score = cvss_score

    def to_dict(self):
        return {
            "url": self.url,
            "vuln_type": self.vuln_type,
            "payload": self.payload,
            "cvss_score": self.cvss_score
        }

class Scanner:
    """
    Scanner pour détecter XSS, SQL Injection et CSRF.
    """
    def __init__(self, endpoints):
        self.endpoints = endpoints
        self.results = []

    def start_scan(self):
        for url in self.endpoints:
            self.detect_xss(url)
            self.detect_sqli(url)
            self.detect_csrf(url)
        return self.results

    def detect_xss(self, url):
        """
        Test de XSS : injecte le payload dans le paramètre 'input' attendu par le site vulnérable.
        """
        xss_payload = "<script>alert('XSS')</script>"
        if "?" not in url:
            test_url = url + "?input=" + xss_payload
        else:
            test_url = url + "&input=" + xss_payload
        try:
            r = requests.get(test_url, timeout=3, verify=False)
            if xss_payload in r.text:
                self.results.append(VulnerabilityResult(url, "XSS", xss_payload))
        except requests.exceptions.RequestException:
            pass

    def detect_sqli(self, url):
        """
        Test de SQL Injection : injecte le payload dans le paramètre 'id' attendu par le site vulnérable.
        """
        sqli_payload = "' OR '1'='1"
        if "?" not in url:
            test_url = url + "?id=" + sqli_payload
        else:
            test_url = url + "&id=" + sqli_payload
        try:
            r = requests.get(test_url, timeout=3, verify=False)
            if "syntax error" in r.text.lower() or "mysql" in r.text.lower():
                self.results.append(VulnerabilityResult(url, "SQL Injection", sqli_payload))
        except requests.exceptions.RequestException:
            pass

    def detect_csrf(self, url):
        """
        Vérifie si la page contient un formulaire dépourvu de token CSRF.
        """
        try:
            r = requests.get(url, timeout=3, verify=False)
            if "<form" in r.text and "csrf" not in r.text.lower():
                self.results.append(VulnerabilityResult(url, "CSRF", "No CSRF token found"))
        except requests.exceptions.RequestException:
            pass

#####################################
# Module CVSS
#####################################
class CVSSCalculator:
    def compute_score(self, vuln_type):
        scores = {"XSS": 5.4, "SQL Injection": 9.0, "CSRF": 6.8}
        return scores.get(vuln_type, 3.0)

#####################################
# Application Flask
#####################################
app = Flask(__name__)
app.config["SECRET_KEY"] = "dev_secret_key"

SCAN_STORAGE = {}

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/start_scan")
def start_scan():
    target_url = request.args.get("url", None)
    if not target_url:
        return "Veuillez préciser une URL. ex: /start_scan?url=https://example.com", 400

    crawler = Crawler(base_url=target_url, max_depth=1)
    endpoints = crawler.crawl()
    scanner = Scanner(endpoints)
    results = scanner.start_scan()
    cvss_calc = CVSSCalculator()
    for r in results:
        r.cvss_score = cvss_calc.compute_score(r.vuln_type)
    scan_id = hashlib.md5(target_url.encode()).hexdigest()[:8]
    SCAN_STORAGE[scan_id] = results

    return redirect(url_for("scan_report", scan_id=scan_id))

@app.route("/scans")
def scans():
    return render_template("scans.html", scans=SCAN_STORAGE)

@app.route("/scan_report/<scan_id>")
def scan_report(scan_id):
    if scan_id not in SCAN_STORAGE:
        return "Scan inconnu", 404
    results = SCAN_STORAGE[scan_id]
    return render_template("scan_report.html", scan_id=scan_id, results=results)

if __name__ == "__main__":
    app.run(debug=True, port=5002)
