Libraries and Initialization
Imports:

subprocess for running external commands.
sqlite3 for interacting with the SQLite database.
json for JSON data handling.
requests for making HTTP requests.
Flask, request, and render_template from flask for creating the web application.
Flask App Initialization:

The Flask app is initialized with app = Flask(__name__).
Shodan API Key:

A placeholder for the Shodan API key is provided.
Database Initialization
Function initialize_db():
Connects to an SQLite database named recon_data.db.
Creates tables for storing subdomains, emails, open ports, services, metadata, and Shodan information if they do not already exist.
Uses error handling to catch and print any database errors.
Data Storage Functions
Functions store_subdomains(), store_emails(), store_open_ports(), store_services(), store_metadata(), store_shodan_info():
Each function connects to the database, inserts data into the respective table, commits the transaction, and closes the connection.
Error handling is implemented to catch and print any database errors.
Data Retrieval Function
Function get_data_from_db(query):
Connects to the database, executes the provided query, fetches the results, and closes the connection.
Returns the fetched data.
Reconnaissance Functions
Functions run_sublist3r(), run_amass(), run_theharvester(), run_nmap(), run_nmap_service_scan():

Use subprocess.run() to execute external commands for Sublist3r, Amass, TheHarvester, and Nmap.
Capture and return the command output.
Function parse_nmap_xml(nmap_output):

Parses Nmap XML output to extract open ports using xml.etree.ElementTree.
Function parse_service_scan(nmap_output):

Parses Nmap XML output to extract service information.
Function extract_metadata(file_path):

Uses ExifTool to extract metadata from a file and returns the metadata as a dictionary.
Function get_shodan_info(ip):

Makes an HTTP request to the Shodan API to get information about an IP address.
Handles any request errors.
Flask Routes
Route /:
Handles GET and POST requests.
On POST, performs various reconnaissance tasks (subdomain enumeration, email harvesting, port scanning, service enumeration, metadata extraction, Shodan integration) and stores the results in the database.
Fetches data from the database to display on the web page.
Renders the index.html template with the fetched data.
