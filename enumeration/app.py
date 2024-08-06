import subprocess
import sqlite3
import json
import requests
from flask import Flask, request, render_template

# Initialize the Flask app
app = Flask(__name__)

# Shodan API key (replace with your own)
SHODAN_API_KEY = 'qeeESxHoeXMyhkYIcUAUUtL4L4XNd6uy'


# Initialize the database
def initialize_db():
    conn = None
    try:
        conn = sqlite3.connect('recon_data.db')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT,
                subdomain TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT,
                email TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS open_ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT,
                ip TEXT,
                port INTEGER,
                service TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT,
                ip TEXT,
                port INTEGER,
                service TEXT,
                version TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT,
                metadata TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS shodan_info (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                info TEXT
            )
        ''')
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()


# Store data in the database
def store_subdomains(domain, subdomains):
    conn = None
    try:
        conn = sqlite3.connect('recon_data.db')
        cursor = conn.cursor()
        for subdomain in subdomains:
            cursor.execute('INSERT INTO subdomains (domain, subdomain) VALUES (?, ?)', (domain, subdomain))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()


def store_emails(domain, emails):
    conn = None
    try:
        conn = sqlite3.connect('recon_data.db')
        cursor = conn.cursor()
        for email in emails:
            cursor.execute('INSERT INTO emails (domain, email) VALUES (?, ?)', (domain, email))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()


def store_open_ports(domain, ip, open_ports):
    conn = None
    try:
        conn = sqlite3.connect('recon_data.db')
        cursor = conn.cursor()
        for port in open_ports:
            cursor.execute('INSERT INTO open_ports (domain, ip, port, service) VALUES (?, ?, ?, ?)',
                           (domain, ip, port['port'], port['service']))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()


def store_services(domain, ip, services):
    conn = None
    try:
        conn = sqlite3.connect('recon_data.db')
        cursor = conn.cursor()
        for service in services:
            cursor.execute('INSERT INTO services (domain, ip, port, service, version) VALUES (?, ?, ?, ?, ?)',
                           (domain, ip, service['port'], service['service'], service['version']))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()


def store_metadata(file_path, metadata):
    conn = None
    try:
        conn = sqlite3.connect('recon_data.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO metadata (file_path, metadata) VALUES (?, ?)', (file_path, json.dumps(metadata)))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()


def store_shodan_info(ip, shodan_info):
    conn = None
    try:
        conn = sqlite3.connect('recon_data.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO shodan_info (ip, info) VALUES (?, ?)', (ip, json.dumps(shodan_info)))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()


# Get data from the database
def get_data_from_db(query):
    conn = sqlite3.connect('recon_data.db')
    cursor = conn.cursor()
    cursor.execute(query)
    data = cursor.fetchall()
    conn.close()
    return data


# Run Sublist3r
def run_sublist3r(domain):
    result = subprocess.run(['sublist3r', '-d', domain], capture_output=True, text=True)
    subdomains = result.stdout.splitlines()
    return subdomains


# Run Amass
def run_amass(domain):
    result = subprocess.run(['amass', 'enum', '-d', domain], capture_output=True, text=True)
    subdomains = result.stdout.splitlines()
    return subdomains


# Run TheHarvester
def run_theharvester(domain):
    result = subprocess.run(['theHarvester', '-d', domain, '-b', 'all'], capture_output=True, text=True)
    emails = [line.split()[0] for line in result.stdout.splitlines() if '@' in line]
    return emails


# Run Nmap for open ports
def run_nmap(target):
    result = subprocess.run(['nmap', '-sS', '-T4', '-p-', '-oX', '-', target], capture_output=True, text=True)
    return result.stdout


# Parse Nmap XML output for open ports
def parse_nmap_xml(nmap_output):
    import xml.etree.ElementTree as ElementTree
    open_ports = []
    try:
        root = ElementTree.fromstring(nmap_output)
        for port in root.findall('.//port'):
            if port.find('state').attrib['state'] == 'open':
                open_ports.append({
                    'port': port.attrib['portid'],
                    'service': port.find('service').attrib['name']
                })
    except ElementTree.ParseError as e:
        print(f"XML Parse error: {e}")
    return open_ports


# Run Nmap for service enumeration
def run_nmap_service_scan(target):
    result = subprocess.run(['nmap', '-sV', '-p-', '-oX', '-', target], capture_output=True, text=True)
    return result.stdout


# Parse Nmap XML output for services
def parse_service_scan(nmap_output):
    import xml.etree.ElementTree as ElementTree
    root = ElementTree.fromstring(nmap_output)
    services = []
    for port in root.findall('.//port'):
        if port.find('state').attrib['state'] == 'open':
            services.append({
                'port': port.attrib['portid'],
                'service': port.find('service').attrib['name'],
                'version': port.find('service').attrib.get('version', 'unknown')
            })
    return services


# Extract metadata using ExifTool
def extract_metadata(file_path):
    result = subprocess.run(['exiftool', file_path], capture_output=True, text=True)
    metadata = {}
    for line in result.stdout.splitlines():
        key, value = line.split(':', 1)
        metadata[key.strip()] = value.strip()
    return metadata


# Get Shodan information
def get_shodan_info(ip):
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        response = requests.get(url)
        response.raise_for_status()  # Raises an HTTPError if the response was an HTTP error
        return response.json()
    except requests.RequestException as e:
        print(f"Shodan API error: {e}")
        return {}


# Flask routes
@app.route('/', methods=['GET', 'POST'])
def index():

    if request.method == 'POST':
        domain = request.form['domain']
        target = request.form['target']
        file_path = request.form['file_path']

        # Run the reconnaissance tasks
        initialize_db()
        print(f"Running reconnaissance on {domain} and {target}...")

        # Subdomain Enumeration
        subdomains = run_sublist3r(domain) + run_amass(domain)
        store_subdomains(domain, subdomains)
        print("\nSubdomain Enumeration Results:")
        for subdomain in subdomains[:5]:  # Show only first 5 results
            print(subdomain)

        # Email Harvesting
        emails = run_theharvester(domain)
        store_emails(domain, emails)
        print("\nEmail Harvesting Results:")
        for email in emails[:5]:  # Show only first 5 results
            print(email)

        # Open Port Scanning
        nmap_output = run_nmap(target)
        open_ports = parse_nmap_xml(nmap_output)
        store_open_ports(domain, target, open_ports)
        print("\nOpen Port Scanning Results:")
        for port in open_ports[:5]:  # Show only first 5 results
            print(f"Port: {port['port']}, Service: {port['service']}")

        # Service Enumeration
        service_scan_output = run_nmap_service_scan(target)
        services = parse_service_scan(service_scan_output)
        store_services(domain, target, services)
        print("\nService Enumeration Results:")
        for service in services[:5]:  # Show only first 5 results
            print(f"Port: {service['port']}, Service: {service['service']}, Version: {service['version']}")

        # Metadata Extraction
        metadata = extract_metadata(file_path)
        store_metadata(file_path, metadata)
        print("\nMetadata Extraction Results:")
        for key, value in list(metadata.items())[:5]:  # Show only first 5 key-value pairs
            print(f"{key}: {value}")

        # Shodan Integration
        shodan_info = get_shodan_info(target)
        store_shodan_info(target, shodan_info)
        print("\nShodan Integration Results:")
        for key, value in list(shodan_info.items())[:5]:  # Show only first 5 key-value pairs
            print(f"{key}: {value}")

    # Fetch data to display

    subdomains = get_data_from_db('SELECT * FROM subdomains LIMIT 5')
    emails = get_data_from_db('SELECT * FROM emails LIMIT 5')
    open_ports = get_data_from_db('SELECT * FROM open_ports LIMIT 5')
    services = get_data_from_db('SELECT * FROM services LIMIT 5')
    shodan_info = get_data_from_db('SELECT * FROM shodan_info LIMIT 5')
    return render_template('index.html', subdomains=subdomains, emails=emails, open_ports=open_ports, services=services,
                           shodan_info=shodan_info)


if __name__ == "__main__":
    app.run(debug=True)
