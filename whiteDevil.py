import socket
import requests
import dns.resolver
import whois
import ssl
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from urllib.parse import urlparse

console = Console()

# Function to get the website's IP address
def get_ip_address(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return "Invalid domain or unable to resolve IP."

# Function to get HTTP headers
def get_http_headers(url):
    try:
        response = requests.head(url)
        return response.headers
    except requests.RequestException as e:
        return f"Error retrieving headers: {e}"

# Function to get DNS records
def get_dns_records(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')
        return [ip.to_text() for ip in result]
    except Exception as e:
        return f"Error retrieving DNS records: {e}"

# Function to get WHOIS information
def get_whois_info(domain):
    try:
        domain_info = whois.whois(domain)
        return domain_info
    except Exception as e:
        return f"Error retrieving WHOIS info: {e}"

# Function to get SSL certificate details
def get_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        return f"Error retrieving SSL certificate: {e}"

# Function to check open ports
def check_open_ports(domain, ports):
    open_ports = []
    ip_address = get_ip_address(domain)
    if "Invalid domain" in ip_address:
        return "Cannot check ports for an invalid domain."

    for port in ports:
        try:
            with socket.create_connection((ip_address, port), timeout=2):
                open_ports.append(port)
        except (socket.timeout, ConnectionRefusedError):
            pass
    return open_ports if open_ports else "No open ports found."

# Main function to collect all information
def collect_website_info(domain):
    # Check if the URL starts with http/https, add if necessary
    if not domain.startswith("http://") and not domain.startswith("https://"):
        url = "http://" + domain
    else:
        url = domain

    console.print(f"\n--- Collecting Information for: {domain} ---\n", style="bold yellow")

    # 1. Get IP Address
    console.print("1. IP Address:", style="bold cyan")
    ip_address = get_ip_address(domain)
    console.print(ip_address)

    # 2. Get HTTP Headers
    console.print("\n2. HTTP Headers:", style="bold cyan")
    headers = get_http_headers(url)
    console.print(headers)

    # 3. Get DNS Records
    console.print("\n3. DNS Records (A):", style="bold cyan")
    dns_records = get_dns_records(domain)
    console.print(dns_records)

    # 4. Get WHOIS Information
    console.print("\n4. WHOIS Information:", style="bold cyan")
    whois_info = get_whois_info(domain)
    console.print(whois_info)

    # 5. Get SSL Certificate
    console.print("\n5. SSL Certificate:", style="bold cyan")
    ssl_cert = get_ssl_certificate(domain)
    console.print(ssl_cert)

    # 6. Check Open Ports
    console.print("\n6. Open Ports:", style="bold cyan")
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]
    open_ports = check_open_ports(domain, common_ports)
    console.print(open_ports)

# Function to check for SQL Injection
def check_sql_injection(url):
    payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        '" OR "1"="1',
        '" OR "1"="1" --',
        "' AND SLEEP(5) --"  # Time-based injection
    ]

    console.print("\n[+] Checking for SQL Injection...", style="bold yellow")
    vulnerable = False
    for payload in payloads:
        test_url = f"{url}?q={payload}"
        try:
            response = requests.get(test_url, timeout=10)  # Set timeout for time-based SQLi
            if response.status_code == 200:
                if "error" in response.text.lower() or response.elapsed.total_seconds() > 5:
                    console.print(f"[red]Potential SQL Injection vulnerability found with payload: {payload}[/red]")
                    vulnerable = True
        except Exception as e:
            console.print(f"[red]Error during SQL Injection check: {e}[/red]")

    if not vulnerable:
        console.print("[green]No SQL Injection vulnerabilities found![/green]")

# Function to check for XSS
def check_xss(url):
    payloads = ["<script>alert('XSS')</script>", "'\"><script>alert('XSS')</script>"]
    console.print("\n[+] Checking for XSS...", style="bold yellow")
    vulnerable = False
    for payload in payloads:
        test_url = f"{url}?q={payload}"
        try:
            response = requests.get(test_url)
            if response.status_code == 200 and payload in response.text:
                console.print(f"[red]Potential XSS vulnerability found with payload: {payload}[/red]")
                vulnerable = True
        except Exception as e:
            console.print(f"[red]Error during XSS check: {e}[/red]")

    if not vulnerable:
        console.print("[green]No XSS vulnerabilities found![/green]")

# Function to check for Open Redirect
def check_open_redirect(url):
    payloads = [url]
    console.print("\n[+] Checking for Open Redirects...", style="bold yellow")
    vulnerable = False

    for payload in payloads:
        test_url = f"{url}?redirect={payload}"
        try:
            response = requests.get(test_url, allow_redirects=True)
            # Parse the final URL after all redirections
            final_url = response.url
            initial_domain = urlparse(url).netloc
            final_domain = urlparse(final_url).netloc

            # Check if the final redirected domain is different from the initial domain
            if initial_domain != final_domain:
                console.print(f"[red]❗ Potential Open Redirect vulnerability found with payload: {payload}[/red]")
                console.print(f"[red]Redirected to: {final_url}[/red]")
                vulnerable = True
                console.print("[bold red]Open Redirect vulnerability detected![/bold red]")
        except Exception as e:
            console.print(f"[red]Error during Open Redirect check: {e}[/red]")

    if not vulnerable:
        console.print("[green]No Open Redirect vulnerabilities found![/green]")

# Function to check Cookie Security
def check_cookie_security(url):
    console.print("\n[+] Checking Cookie Security...", style="bold yellow")
    try:
        response = requests.get(url)
        cookies = response.cookies
        vulnerable = False
        for cookie in cookies:
            console.print(f"Cookie: {cookie.name}, Secure: {cookie.secure}, HttpOnly: {'HttpOnly' in cookie._rest.keys()}")
            if not cookie.secure:
                console.print(f"[red]Warning: Cookie {cookie.name} is not marked as Secure![/red]")
                vulnerable = True
            if 'HttpOnly' not in cookie._rest.keys():
                console.print(f"[red]Warning: Cookie {cookie.name} is not marked as HttpOnly![/red]")
                vulnerable = True

        if not vulnerable:
            console.print("[green]No issues found with Cookie Security![/green]")

    except Exception as e:
        console.print(f"[red]Error checking cookies: {e}[/red]")

# Main function to perform vulnerability scan
def vulnerability_scan(domain):
    if not domain.startswith("http://") and not domain.startswith("https://"):
        url = "http://" + domain
    else:
        url = domain

    console.print(f"\n--- Performing Vulnerability Scan on: {domain} ---\n", style="bold yellow")

    # Run the vulnerability tests
    check_sql_injection(url)
    check_xss(url)
    check_open_redirect(url)
    check_cookie_security(url)

    console.print("\n[bold green]Vulnerability scan completed![/bold green]")

# Main menu function
def main_menu():
    console.clear()

    # Display the title
    tool_name = "[bold white]WhiteDevil[/bold white]\n[cyan]By Team WhiteDevil[/cyan]"
    description = "[yellow]A Complete Resource Hub For Cyber Security Community[/yellow]"

    # Create a panel with the tool name and description
    panel = Panel.fit(f"{tool_name}\n\n{description}")

    console.print(panel, justify="center")

    # Display menu options
    console.print("\n[green]1) Website Information[/green]")
    console.print("[green]2) Website Vulnerability Scan[/green]")

    # Ask the user for input
    option = Prompt.ask("\nSelect An Option", choices=["1", "2"], default="2")

    return option

# Main script logic
if __name__ == "__main__":
    while True:
        option = main_menu()

        if option == "1":
            domain = Prompt.ask("Enter the domain for information collection")
            collect_website_info(domain)

        elif option == "2":
            domain = Prompt.ask("Enter the domain for vulnerability scan")
            vulnerability_scan(domain)

        # Ask the user if they want to run another option or exit
        again = Prompt.ask("\nDo you want to run another scan? (yes/no)", choices=["yes", "no"], default="no")
        if again.lower() != "yes":
            console.print("\n[bold yellow]Exiting WhiteDevil. Stay secure![/bold yellow]")
            break
