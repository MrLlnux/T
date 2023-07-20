import requests
import socket
import ssl
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from termcolor import colored
import tldextract

URL_MAIN = "https://bgp.tools"
URL_ROUTE = "/prefix"
URL = URL_MAIN + URL_ROUTE
TIMEOUT = 3


def send_request(ip):
    ua = UserAgent()
    headers = {
        'User-Agent': ua.random,
    }

    try:
        response = requests.get(URL_MAIN, headers=headers, timeout=TIMEOUT)
        response.raise_for_status()
        if response.status_code == 403:
            print(colored("Your IP is BLOCKED by bgp.tools", "red"))
            return None
    except requests.exceptions.RequestException as e:
        print(colored(f"Error: {e}", "red"))
        return None

    try:
        response = requests.get(f"{URL}/{ip}", headers=headers, timeout=TIMEOUT)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(colored("Cannot connect to bgp.tools\nPlease try again", "red"))
        return None


def cipher_checker(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                ssock_cipher = ssock.cipher()
        return ssock_cipher
    except Exception as e:
        print(colored(f"Error while checking cipher: {e}", "red"))
        return None


def domain_ip_range_checker(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        print(colored(f"Error: Cannot resolve IP address for {domain}", "red"))
        return None


def domain_checker(domain):
    domain = domain.strip()
    domain_s = f"https://{domain}"
    try:
        response = requests.get(domain_s, timeout=TIMEOUT)
        response.raise_for_status()
        if response.status_code == 200:
            ssock_cipher = cipher_checker(domain)
            if not ssock_cipher:
                return

            ssock_version = ssock_cipher[1]
            if ssock_version == "TLSv1.3":
                dns = domain_ip_range_checker(domain)
                if dns:
                    print(colored(f"{domain} => {ssock_cipher} => {dns}", "green"))
            else:
                print(colored(f"{domain} => {ssock_cipher}", "red"))
    except requests.exceptions.RequestException as e:
        print(colored(f"Error while checking domain {domain}: {e}", "red"))


def check_useless_domain(url):
    regex_ip_in_domain = r'(?:[0-9]{1,3}\-){2}[0-9]{1,3}|(?:[0-9]{1,3}\.){2}[0-9]{1,3}'
    regex_subdomain = r'[.-]'
    if not re.findall(regex_ip_in_domain, url):
        ext = tldextract.extract(url)
        if not re.search(regex_subdomain, ext[0]):
            if ext[0] != 'mail':
                return True
    return False


def fdns_html_parser(html):
    domains = []
    soup = BeautifulSoup(html, 'html.parser')
    table = soup.find('table', id='fdnstable')
    if not table:
        print(colored('Forward DNS table not found', "yellow"))
        return domains

    for tr in table.findAll('tr')[1:]:
        _domain = tr.find('td', {'class': 'smallonmobile nowrap'})
        if _domain and _domain.text:
            _domain = _domain.text.strip().split(',')[0]
            domains.append(_domain)

    return domains


def rdns_html_parser(html):
    domains = []
    soup = BeautifulSoup(html, 'html.parser')
    table = soup.find('table', id='rdnstable')
    if not table:
        print(colored("Reverse DNS table not found!", "yellow"))
        return domains

    for tr in table.findAll('tr')[1:]:
        _domain = tr.find('td', {'class': 'smallonmobile nowrap'})
        if _domain and _domain.text:
            _domain = _domain.text.strip()
            if _domain.endswith("."):
                _domain = _domain[:-1]
            domains.append(_domain)

    return domains


def validate_ipv4_address(address):
    ipv4_pattern = r"^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return re.match(ipv4_pattern, address)


if __name__ == '__main__':
    print("Welcome to the Improved IP DNS Checker!")
    input_ip = input(colored("Please enter your server IP: ", "cyan"))

    if validate_ipv4_address(input_ip):
        print("Waiting for getting data from bgp.tools ...")
        html_response = send_request(input_ip)
        if html_response:
            rdns_domains = rdns_html_parser(html_response)
            print("Checking Reversed DNS Domains ...")

            if rdns_domains:
                with alive_bar(len(rdns_domains), force_tty=True) as bar:
                    for rdomain in rdns_domains:
                        if check_useless_domain(rdomain):
                            domain_checker(rdomain)
                        bar.text(rdomain)
                        bar()
            else:
                print(colored("Reverse DNS Domains not found!", "yellow"))

            print("Checking Forward DNS Domains ...")
            fdns_domains = fdns_html_parser(html_response)
            if fdns_domains:
                with alive_bar(len(fdns_domains), force_tty=True) as bar:
                    for fdomain in fdns_domains:
                        if check_useless_domain(fdomain):
                            domain_checker(fdomain)
                        bar.text(fdomain)
                        bar()
            else:
                print(colored("Forward DNS Domains not found!", "yellow"))

            print(colored("Done!", "green"))
    else:
        print(colored("Please enter a valid IPv4 address", "red"))
