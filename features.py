from urllib.parse import urlparse
import re, json
import requests
import socket, ssl
import requests
from bs4 import BeautifulSoup
import whois
from datetime import datetime

def extract_domain(url):
    try:
        parsed_uri = urlparse(url)
        domain = '{uri.netloc}'.format(uri=parsed_uri)
        return domain
    except (ValueError, TypeError) as e:
        return None

def number_of_subdomain(url):
    domain = urlparse(url).netloc
    subdomains = domain.split('.')
    num_subdomains = len(subdomains)
    if num_subdomains > 2:
        return 1
    else:
        return 0

def dns_check(url):
    try:
        ip = socket.gethostbyname(url)
        dns = socket.gethostbyaddr(ip, timeout=5)[0]
        if url == dns:
            return 0  # legitimate
        else:
            return 1  # phishing
    except:
        return 1  # phishing (in case of any error)


# ip instead of domain
def having_ip(url):
    result = urlparse(url).netloc
    try:
        socket.inet_aton(result)
        return 1  # phishing
    except:
        return 0  # legit


# @ sign in url
def have_at_sign(url):
    if "@" in url:
        at = 1  # phishing
    else:
        at = 0
    return at


# url length more than 54
def get_length(url):
    if len(url) < 75:
        length = 0  # legit
    else:
        length = 1
    return length


def http_domain(url):
    domain = urlparse(url).netloc
    if 'https' in domain:
        return 1
    else:
        return 0


def get_depth(url):
    s = urlparse(url).path.split('/')
    depth = 0
    for j in range(len(s)):
        if len(s[j]) != 0:
            depth = depth + 1
    return depth


def redirection(url):
    pos = url.rfind('//')
    if pos > 6:
        if pos > 7:
            return 1
        else:
            return 0
    else:
        return 0


shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"


# 8. Checking for Shortening Services in URL (Tiny_URL)
def tiny_url(url):
    match = re.search(shortening_services, url)
    if match:
        return 1
    else:
        return 0


def prefix_suffix(url):
    if '-' in urlparse(url).netloc:
        return 1  # phishing
    else:
        return 0  # legitimate


def get_features(url):
    features = []
    try:
        # Fetch the HTML content of the webpage
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')

        # Check for the presence of an iframe element
        iframe = soup.find('iframe')
        features.append(1 if iframe is not None else 0)

        # Check for the presence of mouseover event listeners
        mouseover = False
        for tag in soup.find_all():
            if 'onmouseover' in tag.attrs:
                mouseover = True
                break
        features.append(1 if mouseover else 0)

        # Check for the presence of a right-click disabling script
        right_click = False
        for script in soup.find_all('script'):
            if 'event.button==2' in str(script):
                right_click = True
                break
        features.append(1 if right_click else 0)

        # Check for the presence of a forwarding function
        forwarding = False
        for script in soup.find_all('script'):
            if 'window.history.forward' in str(script):
                forwarding = True
                break
        features.append(1 if forwarding else 0)

        # Check for the presence of a login form
        login_form = soup.find('form', {'method': 'post'})
        features.append(1 if login_form is not None else 0)

    except:
        # Return all zeros if there was an error fetching or parsing the webpage
        features = [0, 0, 0, 0, 0]

    return features


def get_ip_address(url):
    try:
        domain_name = url.split("//")[-1].split("/")[0]
        ip_address = socket.gethostbyname(domain_name)
    except socket.gaierror:
        # print(f"Error: Could not resolve URL {url}")
        ip_address = ""

    return ip_address


def is_phishing(url):
    ip_address = get_ip_address(url)
    if ip_address == "":
        return 0  # legitimate URL
    else:
        endpoint_url = f"https://checkurl.phishtank.com/checkurl/?format=json&ip={ip_address}&url={url}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"}
        response = requests.post(endpoint_url, data={"url": url, "format": "json"}, headers=headers)
        data = json.loads(response.text)

        if data["results"]["in_database"] and data["results"]["valid"]:
            return 1  # phishing URL
        else:
            return 0  # legitimate URL


def check_ssl_certificate(url, days_before_expire=30):
    try:
        hostname = url.split('//')[-1].split('/')[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as sslsock:
                cert = sslsock.getpeercert()
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_left = (not_after - datetime.utcnow()).days
        if days_left <= days_before_expire:
            return 1
        else:
            return 0
    except Exception as e:
        # print(f"Error: {e}")
        return 1


def domain_age(domain_name):
    try:
        creation_date = domain_name.creation_date
        expiration_date = domain_name.expiration_date
        if isinstance(creation_date, str) or isinstance(expiration_date, str):
            creation_date = datetime.strptime(str(creation_date), '%Y-%m-%d %H:%M:%S')
            expiration_date = datetime.strptime(str(expiration_date), "%Y-%m-%d %H:%M:%S")
        elif isinstance(creation_date, list) or isinstance(expiration_date, list):
            return 1  # Error in WHOIS data, so treat it as a phishing attempt
        else:
            ageof_domain = abs((expiration_date - creation_date).days)
            if (ageof_domain / 30) < 6:
                return 1  # Phishing attempt
            else:
                return 0  # Legitimate domain
    except:
        return 1  # Error occurred, so treat it as a phishing attempt


def domain_end(url):
    try:
        domain = whois.whois(url).expiration_date
    except whois.parser.PywhoisError:
        return 1

    if isinstance(domain, str):
        try:
            domain = datetime.strptime(domain, "%Y-%m-%d")
        except:
            return 1

    if domain is None:
        return 1
    elif type(domain) is list:
        return 1
    else:
        today = datetime.now()
        end = abs((domain - today).days)
        if (end / 30) < 6:
            end = 0  # legitimate
        else:
            end = 1  # phishing
    return end


def check_unusual_characters(url):
    # Define a regular expression pattern to match unusual characters
    pattern = r"[^a-zA-Z0-9\.\-/:?=&]"

    # Check if the URL contains unusual characters
    if re.search(pattern, url):
        return 1  # Phishing
    else:
        return 0  # Legitimate


def has_javascript(url):
    try:
        response = requests.get(url, timeout=5)
        html = response.text
        if "script" in html:
            return 1
        else:
            return 0
    except:
        return 0


def check_source_code(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')
        scripts = soup.find_all('script')

        for script in scripts:
            if 'redirect' in str(script) or 'capture' in str(script):
                return 1

        return 0

    except Exception as e:
        return 0


def has_privacy_policy(url):
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.content, 'html.parser')
        privacy_policy_links = soup.find_all('a', href=lambda href: href and 'privacy' in href.lower())
        if len(privacy_policy_links) > 0:
            return 1
        else:
            return 0
    except:
        return 0
