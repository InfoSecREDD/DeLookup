import os
import sys
import requests
from dotenv import load_dotenv
from rich import print
from rich.tree import Tree
from rich.console import Console
import argparse
import time
import re
import ipaddress

# ASCII Banner
banner = r"""
[bold red]
     ▗▄▄▖ ▗▄▄▄▖▗▄▄▄  ▗▄▄▄   ▄▄▄              
     ▐▌ ▐▌▐▌   ▐▌  █ ▐▌  █ ▀▄▄               
     ▐▛▀▚▖▐▛▀▀▘▐▌  █ ▐▌  █ ▄▄▄▀              
     ▐▌ ▐▌▐▙▄▄▖▐▙▄▄▀ ▐▙▄▄▀                   
                                             
                                             
                                             
▗▄▄▄  ▗▞▀▚▖    ▗▖ ▄▄▄   ▄▄▄  █  ▄ █  ▐▌▄▄▄▄  
▐▌  █ ▐▛▀▀▘  ▀ ▐▌█   █ █   █ █▄▀  ▀▄▄▞▘█   █ 
▐▌  █ ▝▚▄▄▖    ▐▌▀▄▄▄▀ ▀▄▄▄▀ █ ▀▄      █▄▄▄▀ 
▐▙▄▄▀          ▐▙▄▄▖         █  █      █     
                                       ▀    
                                         
[reset]
[bold yellow]   REDD's DeHashed API Lookup Tool[reset]
            Version [cyan]1.0.0[reset]
"""

# Print the banner
console = Console()
console.print(banner)

# Load environment variables from .env file
load_dotenv()

EMAIL = os.getenv('EMAIL')
API_KEY = os.getenv('API_KEY')

if not EMAIL or not API_KEY:
    print("[bold red]Error:[/bold red] EMAIL and API_KEY must be set in the .env file.")
    sys.exit(1)

BASE_URL = "https://api.dehashed.com"

# Rate limiting constants
MAX_REQUESTS_PER_SECOND = 5
REQUEST_INTERVAL = 1 / MAX_REQUESTS_PER_SECOND
last_request_time = 0

console = Console()

# Mapping of API field names to user-friendly display names
FIELD_NAME_MAPPING = {
    "id": "Entry ID",
    "email": "Email Address",
    "ip_address": "IP Address",
    "username": "Username",
    "password": "Password",
    "hashed_password": "Hashed Password",
    "hash_type": "Hash Type",
    "name": "Real Name",
    "vin": "Vehicle Identification Number (VIN)",
    "address": "Physical Address",
    "phone": "Phone Number",
    "database_name": "Breached Database",
}

# Fields to perform reverse searches on
REVERSE_SEARCH_FIELDS = ["email", "ip_address", "name", "phone", "address", "vin", "username"]

def get_headers():
    return {
        'Accept': 'application/json'
    }

def rate_limited_request(url, headers, params, auth):
    global last_request_time
    current_time = time.time()
    elapsed = current_time - last_request_time
    if elapsed < REQUEST_INTERVAL:
        time_to_wait = REQUEST_INTERVAL - elapsed
        time.sleep(time_to_wait)
    try:
        response = requests.get(url, headers=headers, auth=auth, params=params)
        last_request_time = time.time()
        return response
    except Exception as e:
        console.print(f"[bold red]An error occurred while making the request:[/bold red] {e}")
        sys.exit(1)

def search_data(query, page=1, size=100):
    endpoint = "/search"
    params = {
        'query': query,
        'page': page,
        'size': size
    }
    url = f"{BASE_URL}{endpoint}"
    headers = get_headers()
    auth = (EMAIL.lower(), API_KEY.lower())

    response = rate_limited_request(url, headers, params, auth)

    try:
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 400:
            error_message = response.json().get('Error 400', 'Bad Request')
            console.print(f"[bold red]HTTP 400 Error:[/bold red] {error_message}")
        elif response.status_code == 401:
            console.print("[bold red]HTTP 401 Error:[/bold red] Unauthorized. Check your API credentials.")
        elif response.status_code == 404:
            console.print("[bold red]HTTP 404 Error:[/bold red] Endpoint not found. Check the API URL and method.")
        else:
            console.print(f"[bold red]HTTP error occurred:[/bold red] {http_err} - {response.text}")
        sys.exit(1)
    except ValueError:
        console.print("[bold red]Error:[/bold red] Unable to parse JSON response.")
        sys.exit(1)
    except Exception as err:
        console.print(f"[bold red]An unexpected error occurred:[/bold red] {err}")
        sys.exit(1)

def construct_query(args):
    query_parts = []
    if args.query:
        return args.query

    if args.email:
        query_parts.append(f'email:"{args.email}"')
    if args.ip_address:
        query_parts.append(f'ip_address:"{args.ip_address}"')
    if args.username:
        query_parts.append(f'username:"{args.username}"')
    if args.password:
        query_parts.append(f'password:"{args.password}"')
    if args.hashed_password:
        query_parts.append(f'hashed_password:"{args.hashed_password}"')
    if args.hash_type:
        query_parts.append(f'hash_type:"{args.hash_type}"')
    if args.name:
        query_parts.append(f'name:"{args.name}"')
    if args.vin:
        query_parts.append(f'vin:"{args.vin}"')
    if args.address:
        query_parts.append(f'address:"{args.address}"')
    if args.phone:
        query_parts.append(f'phone:"{args.phone}"')
    if args.database_name:
        query_parts.append(f'database_name:"{args.database_name}"')

    if not query_parts:
        console.print("[bold red]Error:[/bold red] At least one search parameter must be provided.")
        sys.exit(1)

    query = ' AND '.join(query_parts)
    return query

def is_valid_email(email):
    regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(regex, email) is not None

def is_valid_phone(phone):
    regex = r'^\+?[\d\s\-]{7,15}$'
    return re.match(regex, phone) is not None

def is_valid_address(address):
    # Regex for physical addresses with optional directional indicators and city/state formats
    street_regex = r'^\d+\s+(N|S|E|W|NE|NW|SE|SW)?\s*[A-Za-z0-9]+(?:\s+[A-Za-z0-9]+)*,\s*[A-Za-z\s]+,\s*[A-Z]{2},\s*\d{5}$'
    
    # Regex for PO Boxes
    po_box_regex = r'(?i)\b(P\.?\s*O\.?\s*Box|Post Office Box)\s+\d+'

    # Checks if the address matches either regex
    return re.match(street_regex, address) is not None or re.search(po_box_regex, address) is not None


def is_valid_ip_address(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def normalize_name(name):
    return re.sub(r'\s+', ' ', name.strip().lower())

def get_entry_identifier(entry):
    key_fields = ['name', 'address', 'email', 'ip_address', 'username']
    key_values = [entry.get(field, '').strip().lower() for field in key_fields]
    return tuple(key_values)

def filter_unique_values(entries, initial_search_terms, searched_values):
    unique_values = {field: set() for field in REVERSE_SEARCH_FIELDS}

    if not entries:
        return unique_values

    for entry in entries:
        for field in REVERSE_SEARCH_FIELDS:
            value = entry.get(field, None)
            if value:
                value = value.strip()
                if not value:
                    continue
                if field == "email" and is_valid_email(value):
                    if value.lower() not in searched_values['email'] and value.lower() not in initial_search_terms:
                        unique_values[field].add(value.lower())
                elif field == "phone" and is_valid_phone(value):
                    if value not in searched_values['phone'] and value not in initial_search_terms:
                        unique_values[field].add(value)
                elif field == "address" and is_valid_address(value):
                    if value not in searched_values['address'] and value not in initial_search_terms:
                        unique_values[field].add(value)
                elif field == "name":
                    normalized = normalize_name(value)
                    if normalized not in searched_values['name'] and normalized not in initial_search_terms:
                        unique_values[field].add(value)
                elif field == "vin":
                    if value not in searched_values['vin'] and value not in initial_search_terms:
                        unique_values[field].add(value)
                elif field == "username":
                    if value not in searched_values['username'] and value not in initial_search_terms:
                        unique_values[field].add(value)
                elif field == "ip_address" and is_valid_ip_address(value):
                    if value not in searched_values['ip_address'] and value not in initial_search_terms:
                        unique_values[field].add(value)
    return unique_values

def display_results(data, show_id=False, title="[bold green]DeHashed API Search Results[/bold green]", displayed_entries=None):
    if displayed_entries is None:
        displayed_entries = set()

    if not data.get('success', False):
        console.print("[bold red]Search was not successful.[/bold red]")
        return displayed_entries

    entries = data.get('entries', [])
    if not entries:
        console.print("[bold yellow]No results found.[/bold yellow]")
        return displayed_entries

    display_mapping = FIELD_NAME_MAPPING.copy()

    if not show_id:
        display_mapping.pop("id", None)

    tree = Tree(title)
    overall_displayed_entries = set()

    for entry in entries:
        entry_id = get_entry_identifier(entry)
        if entry_id in overall_displayed_entries:
            continue  # Skip duplicate entry
        overall_displayed_entries.add(entry_id)

        entry_tree = tree.add("[bold cyan]Result Found[/bold cyan]")
        for api_field, display_name in display_mapping.items():
            value = entry.get(api_field, None)
            if value is None:
                continue
            if isinstance(value, str) and not value.strip():
                continue
            entry_tree.add(f"[bold blue]{display_name}[/bold blue]: [white]{value}[/white]")

    console.print(tree)
    return overall_displayed_entries  # Return the set of displayed entries for the next calls

def perform_reverse_search(unique_values, page, size, searched_values):
    reverse_results = {field: [] for field in REVERSE_SEARCH_FIELDS}

    for field, values in unique_values.items():
        for value in values:
            if field == "name":
                normalized_value = normalize_name(value)
                query = f'name:"{normalized_value}"'
                searched_values['name'].add(normalized_value)
            else:
                query = f'{field}:"{value}"'
                searched_values[field].add(value)

            console.print(f"[bold blue]Performing reverse search for {field}: {value}[/bold blue]")
            data = search_data(query, page=page, size=size)
            reverse_results[field].append({'query': query, 'data': data})

    return reverse_results

def display_reverse_results(reverse_results, show_id=False, displayed_entries=None, original_displayed_entries=None):
    if displayed_entries is None:
        displayed_entries = {field: set() for field in REVERSE_SEARCH_FIELDS}

    if not any(reverse_results.values()):
        console.print("[bold yellow]No reverse search results to display.[/bold yellow]")
        return

    tree = Tree("[bold green]Reverse Search Results[/bold green]")
    overall_displayed_entries = set(original_displayed_entries)  # Start with the original displayed entries

    for field, searches in reverse_results.items():
        if not searches:
            continue  # Skip fields without searches
        field_tree = tree.add(f"[bold magenta]{field.capitalize()} Reverse Searches[/bold magenta]")
        has_displayed_results = False  # Flag to track if any result is displayed under this category

        for search in searches:
            query = search['query']
            data = search['data']
            if not data.get('success', False):
                field_tree.add(f"[bold red]Failed to retrieve results for query: {query}[/bold red]")
                continue
            
            entries = data.get('entries') or []
            if not entries:
                continue
            
            for entry in entries:
                entry_id = get_entry_identifier(entry)
                if entry_id in overall_displayed_entries or entry_id in displayed_entries[field]:
                    continue  # Skip if entry is already displayed
                overall_displayed_entries.add(entry_id)
                displayed_entries[field].add(entry_id)

                result_tree = field_tree.add("[bold cyan]Result Found[/bold cyan]")
                for api_field, display_name in FIELD_NAME_MAPPING.items():
                    if not show_id and api_field == "id":
                        continue
                    value = entry.get(api_field, None)
                    if value is None:
                        continue
                    if isinstance(value, str) and not value.strip():
                        continue
                    result_tree.add(f"[bold blue]{display_name}[/bold blue]: [white]{value}[/white]")
                
                has_displayed_results = True  # Mark that we have displayed at least one result

        # If no results were displayed for this field, remove it from the tree
        if not has_displayed_results:
            tree.children.remove(field_tree)

    if tree.children:
        console.print(tree)
    else:
        console.print("[bold yellow]No unique reverse search results to display.[/bold yellow]")

def export_to_csv(primary_data, reverse_data, filename='results.csv'):
    import csv

    entries = primary_data.get('entries', [])
    if not entries:
        console.print("[bold yellow]No data to export.[/bold yellow]")
        return

    all_fields = set()
    for entry in entries:
        all_fields.update(entry.keys())
    all_fields = sorted(all_fields)

    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=all_fields)
            writer.writeheader()
            for entry in entries:
                sanitized_entry = {k: (v if v is not None and v != '' else 'N/A') for k, v in entry.items()}
                writer.writerow(sanitized_entry)
        console.print(f"[bold green]Primary results exported to {filename}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Error exporting primary results to CSV:[/bold red] {e}")

    if reverse_data:
        reverse_filename = f"reverse_{filename}"
        try:
            with open(reverse_filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['Field', 'Value']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for field, values in reverse_data.items():
                    for value in values:
                        writer.writerow({'Field': field, 'Value': value})
            console.print(f"[bold green]Reverse search results exported to {reverse_filename}[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Error exporting reverse search results to CSV:[/bold red] {e}")

def main():
    try:
        parser = argparse.ArgumentParser(description="Search Dehashed API for various fields.")

        # Search parameters
        parser.add_argument('--email', type=str, help='Email address to search for.')
        parser.add_argument('--ip_address', type=str, help='IP address to search for.')
        parser.add_argument('--username', type=str, help='Username to search for.')
        parser.add_argument('--password', type=str, help='Password to search for.')
        parser.add_argument('--hashed_password', type=str, help='Hashed password to search for.')
        parser.add_argument('--hash_type', type=str, help='Type of hash (e.g., MD5, SHA1) to search for.')
        parser.add_argument('--name', type=str, help='Real name to search for.')
        parser.add_argument('--vin', type=str, help='Vehicle Identification Number (VIN) to search for.')
        parser.add_argument('--address', type=str, help='Physical address to search for.')
        parser.add_argument('--phone', type=str, help='Phone number to search for.')
        parser.add_argument('--database_name', type=str, help='Breached database name to search within.')

        # Advanced query options
        parser.add_argument('--query', type=str, help='Raw query string for advanced searches.')

        # Pagination & Sizing
        parser.add_argument('--size', type=int, default=100, help='Number of results per call (max 10000). Default is 100.')
        parser.add_argument('--page', type=int, default=1, help='Page number for pagination. Default is 1.')

        # Export option
        parser.add_argument('--export', type=str, help='Filename to export results as CSV.')

        # New ID display option
        parser.add_argument('--ID', action='store_true', help='Include Entry ID in the display.')

        # Reverse option
        parser.add_argument('--reverse', action='store_true', help='Enable reverse searches on unique results.')

        # Reverse stop option
        parser.add_argument('--revstop', type=int, default=4, help='Maximum depth of reverse search iterations. Default is 4.')

        args = parser.parse_args()

        if args.size < 1 or args.size > 10000:
            console.print("[bold red]Error:[/bold red] 'size' must be between 1 and 10000.")
            sys.exit(1)

        query = construct_query(args)
        console.print(f"[bold blue]Constructed Query:[/bold blue] {query}")
        console.print(f"[bold blue]Fetching results[/bold blue] (Page: {args.page}, Size: {args.size})...\n")

        displayed_entries_primary = set()
        primary_data = search_data(query, page=args.page, size=args.size)

        show_id = args.ID if not args.reverse else False

        # Display primary results and get unique entries displayed
        displayed_entries_primary = display_results(primary_data, show_id=show_id, displayed_entries=displayed_entries_primary)

        reverse_search_data = {}
        if args.reverse:
            entries = primary_data.get('entries', [])
            if entries is None:
                entries = []
            searched_values = {field: set() for field in REVERSE_SEARCH_FIELDS}

            initial_search_terms = set()
            if args.email:
                initial_search_terms.add(args.email.lower())
            if args.ip_address:
                initial_search_terms.add(args.ip_address)
            if args.username:
                initial_search_terms.add(args.username)
            if args.name:
                normalized_name = normalize_name(args.name)
                initial_search_terms.add(normalized_name)
            if args.phone:
                initial_search_terms.add(args.phone)
            if args.address:
                initial_search_terms.add(args.address)
            if args.vin:
                initial_search_terms.add(args.vin)

            unique_values = filter_unique_values(entries, initial_search_terms, searched_values)
            unique_values = {k: v for k, v in unique_values.items() if v}
            if unique_values:
                all_reverse_searches = {field: [] for field in REVERSE_SEARCH_FIELDS}
                current_unique_values = unique_values
                depth = 0
                max_depth = args.revstop
                displayed_entries_reverse = {field: set() for field in REVERSE_SEARCH_FIELDS}

                while depth < max_depth and any(current_unique_values.values()):
                    depth += 1
                    console.print(f"[bold yellow]Reverse Searching Layer {depth}[/bold yellow]")
                    reverse_results = perform_reverse_search(current_unique_values, page=args.page, size=args.size, searched_values=searched_values)

                    for field in REVERSE_SEARCH_FIELDS:
                        all_reverse_searches[field].extend(reverse_results[field])

                    new_unique_values = {field: set() for field in REVERSE_SEARCH_FIELDS}
                    for field, searches in reverse_results.items():
                        for search in searches:
                            data = search['data']
                            if not data.get('success', False):
                                continue
                            entries = data.get('entries') or []
                            for entry in entries:
                                for rev_field in REVERSE_SEARCH_FIELDS:
                                    rev_value = entry.get(rev_field, None)
                                    if rev_value:
                                        rev_value = rev_value.strip()
                                        if not rev_value:
                                            continue
                                        if rev_field == "name":
                                            normalized = normalize_name(rev_value)
                                            if normalized not in searched_values['name'] and normalized not in initial_search_terms:
                                                new_unique_values[rev_field].add(rev_value)
                                        elif rev_field == "email" and is_valid_email(rev_value):
                                            if rev_value.lower() not in searched_values['email'] and rev_value.lower() not in initial_search_terms:
                                                new_unique_values[rev_field].add(rev_value.lower())
                                        elif rev_field == "phone" and is_valid_phone(rev_value):
                                            if rev_value not in searched_values['phone'] and rev_value not in initial_search_terms:
                                                new_unique_values[rev_field].add(rev_value)
                                        elif rev_field == "address" and is_valid_address(rev_value):
                                            if rev_value not in searched_values['address'] and rev_value not in initial_search_terms:
                                                new_unique_values[rev_field].add(rev_value)
                                        elif rev_field == "vin":
                                            if rev_value not in searched_values['vin'] and rev_value not in initial_search_terms:
                                                new_unique_values[rev_field].add(rev_value)
                                        elif rev_field == "username":
                                            if rev_value not in searched_values['username'] and rev_value not in initial_search_terms:
                                                new_unique_values[rev_field].add(rev_value)
                                        elif rev_field == "ip_address" and is_valid_ip_address(rev_value):
                                            if rev_value not in searched_values['ip_address'] and rev_value not in initial_search_terms:
                                                new_unique_values[rev_field].add(rev_value)

                    current_unique_values = {k: v for k, v in new_unique_values.items() if v}

                # Display all reverse search results
                display_reverse_results(all_reverse_searches, show_id=False, displayed_entries=displayed_entries_reverse, original_displayed_entries=displayed_entries_primary)

                reverse_search_data = {field: set() for field in REVERSE_SEARCH_FIELDS}
                for field, searches in all_reverse_searches.items():
                    for search in searches:
                        data = search['data']
                        entries = data.get('entries') or []
                        for entry in entries:
                            for rev_field in REVERSE_SEARCH_FIELDS:
                                value = entry.get(rev_field, None)
                                if value:
                                    value = value.strip()
                                    if not value:
                                        continue
                                    reverse_search_data[rev_field].add(value)

            else:
                console.print("[bold yellow]No valid unique values found for reverse searching.[/bold yellow]")

        if args.export:
            export_to_csv(primary_data, reverse_search_data, filename=args.export)
    except KeyboardInterrupt:
        console.print("\n[bold red]Process interrupted by user. Exiting...[/bold red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred:[/bold red] {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()