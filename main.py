import os
import requests
import urllib.parse
from dotenv import load_dotenv, set_key
import argparse
import time
import logging
from datetime import datetime, timedelta, timezone
from dateutil.parser import isoparse
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich import box
from rich.pretty import pprint
import random
import json
import sys
from rich.logging import RichHandler

logging.basicConfig(
    level=logging.DEBUG,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[
        RichHandler(rich_tracebacks=True),
        logging.FileHandler("ninjaone_client.log"),
    ],
)
logger = logging.getLogger("ninjaone_client")

# Initialize Rich Console, this lets us print with formatting
console = Console(highlight=False)

# Define the path for the .env file; in this case it's in the same directory as the script
env_file_path = '.env'

# Check and load .env file if it exists, if not, create it.
# The .env file is used to store environment variables that can be used by the script
if not os.path.exists(env_file_path):
    console.print(".env file not found. Creating a new one.", style="yellow")
    with open(env_file_path, 'w') as env_file:
        env_file.write("CLIENT_ID=\n")
        env_file.write("CLIENT_SECRET=\n")
        env_file.write("SCOPES=\n")
        env_file.write("INSTANCE=app\n")
        env_file.write("ACCESS_TOKEN=\n")  # Fixed initial value
        env_file.write("ACCESS_TOKEN_EXPIRES_AT=\n")  # Fixed initial value
    console.print("[blue].env file created[/blue]")
else:  # Load environment variables from a .env file
    console.print("[green].env file found[/green]")
    load_dotenv()


class NinjaOneClient(requests.Session):
    def __init__(self, client_id, client_secret, scopes, instance):
        """
        Initialize the NinjaOne Client with client credentials and instance details.
        """
        super().__init__()
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = scopes
        self.instance = instance
        self.baseurl = f"https://{self.instance}.ninjarmm.com/v2/"
        self.access_token = os.getenv('ACCESS_TOKEN')
        self.access_token_expires_at = self._get_token_expiry('ACCESS_TOKEN_EXPIRES_AT')

        logger.debug(f"Initialized NinjaOneClient with instance: {self.instance}")
        logger.debug(f"Access Token Expires At: {self.access_token_expires_at}")

        # Update headers if access token is available and not expired
        if self.access_token and not self._is_token_expired('access'):
            self.headers.update({
                "Authorization": f"Bearer {self.access_token}",
                "Accept": "application/json",
                'User-agent': 'myscript'
            })
            logger.debug("Access token is valid and headers are updated.")
        else:
            logger.debug("Access token is missing or expired. Clearing tokens.")
            self.access_token = None
            self.authenticate()

        # Attach rate limiting handler
        self.hooks["response"].append(self.rate_limit_handler)

    def _get_full_url(self, endpoint):
        """
        Construct the full URL for API requests.
        """
        return urllib.parse.urljoin(self.baseurl, endpoint)

    def _get_token_expiry(self, token_type):
        """
        Retrieve token expiry time from environment variables.
        """
        expiry_str = os.getenv(token_type)
        if expiry_str:
            try:
                # Use isoparse for robust ISO 8601 parsing
                dt = isoparse(expiry_str)
                if dt.tzinfo is None:
                    # Assume UTC if no timezone info is present
                    dt = dt.replace(tzinfo=timezone.utc)
                logger.debug(f"Parsed {token_type}: {dt.isoformat()}")
                return dt
            except (ValueError, TypeError) as e:
                logger.error(f"Invalid date format for {token_type} in .env: {e}")
                return None
        return None

    def _is_token_expired(self, token_type):
        """
        Check if the specified token is expired.
        """
        now = datetime.now(timezone.utc)
        if token_type == 'access':
            if self.access_token_expires_at:
                logger.debug(f"Checking access token expiry: now={now.isoformat()} >= expires_at={self.access_token_expires_at.isoformat()}")
                return now >= self.access_token_expires_at
            return True  # If expiry not set, assume expired
        return True

    def rate_limit_handler(self, response, *args, **kwargs):
        """
        Handle rate limiting by checking for HTTP 429 status code.
        """
        if response.status_code == 429:
            retry_count = kwargs.get('retry_count', 0)
            if 'Retry-After' in response.headers:
                retry_after = int(response.headers.get("Retry-After"))
            else:
                retry_after = round((60 * (2 ** retry_count) + random.uniform(0, 1)), 2)
            console.print(f"[yellow]Rate limit reached. Retrying after {retry_after} seconds...[/yellow]")
            logger.warning(f"Rate limit reached. Retrying after {retry_after} seconds.")
            time.sleep(retry_after)
            # Retry the request after waiting
            method = response.request.method
            url = response.request.url
            headers = response.request.headers.copy()
            data = response.request.body
            params = response.request.params

            # Avoid infinite retry loops by limiting retries
            if retry_count < 3:
                kwargs['retry_count'] = retry_count + 1
                return self.request(method, url, headers=headers, data=data, params=params, **kwargs)
            else:
                console.print("[red]Max retry attempts reached. Aborting request.[/red]")
                logger.error("Max retry attempts for rate limiting reached.")
                return response
        return response

    def authenticate(self):
        """
        Handle the client_credentials authentication flow to obtain access tokens.
        """
        # Wait for user to complete authentication
        console.print("Waiting for authentication...", style="cyan")

        # Exchange authorization code for access token
        token_response = requests.post(
            f"https://{self.instance}.ninjarmm.com/ws/oauth/token",
            data={
                'grant_type': 'client_credentials',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'scope': self.scopes
            },
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-agent': 'myscript'
            }
        )

        logger.debug(f"Authentication response status: {token_response.status_code}")

        if token_response.status_code == 200:
            token_json = token_response.json()
            self.access_token = token_json.get('access_token')
            expires_in = token_json.get('expires_in', 3600)  # Default to 1 hour if not provided

            if self.access_token:
                self.access_token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

                # Update session headers
                self.headers.update({
                    "Authorization": f"Bearer {self.access_token}",
                    "Accept": "application/json",
                    'User-agent': 'myscript'
                })

                # Save tokens and expiry times to .env
                self.save_tokens_to_env()
                console.print("[green]Authentication successful. Tokens have been saved to the .env file.[/green]")
                logger.info("Authentication successful. Tokens saved.")
            else:
                console.print("[red]Error: Tokens not found in the response.[/red]")
                logger.error("Tokens not found in the authentication response.")
        else:
            console.print(f"[red]Error: Failed to retrieve tokens. Status Code: {token_response.status_code}[/red]")
            try:
                response_json = token_response.json()
                pprint(response_json)
                logger.error(token_response.json())
            except ValueError:
                logger.error(token_response.text)

    def save_tokens_to_env(self):
        """
        Save access and refresh tokens along with their expiry times to the .env file.
        """
        set_key('.env', 'ACCESS_TOKEN', self.access_token)
        set_key('.env', 'ACCESS_TOKEN_EXPIRES_AT', self.access_token_expires_at.isoformat())
        logger.debug("Tokens and expiry times saved to .env file.")

    def _ensure_valid_token(self):
        """
        Ensure that the access token is valid. Refresh if expired.
        """
        if not self.access_token or self._is_token_expired('access'):
            console.print("[red]Access token is missing or expired. Please authenticate again.[/red]")
            logger.info("Access token is missing or expired. Attempting to refresh.")
            self.authenticate()

    def request(self, method, url, **kwargs):
        """
        Override the request method to include token validation, refreshing logic,
        and automatic URL prefixing.
        """
        retry_count = kwargs.pop('retry_count', 0)

        # Prefix the URL with baseurl if it's relative
        if not url.startswith("http"):
            url = self._get_full_url(url)
            logger.debug(f"Prefixed URL: {url}")

        self._ensure_valid_token()

        response = super().request(method, url, **kwargs)
        logger.debug(f"Request URL: {url}, Method: {method}, Status Code: {response.status_code}")

        if response.status_code == 401 and retry_count == 0:
            console.print("[yellow]Access token expired or invalid. Attempting to refresh...[/yellow]")
            logger.warning("Access token expired or invalid. Attempting to refresh.")
            self.authenticate()
            # Retry the request with the new token
            kwargs['retry_count'] = retry_count + 1
            response = super().request(method, url, **kwargs)
            logger.debug(f"Retry Request URL: {url}, Method: {method}, Status Code: {response.status_code}")

        return response


def list_devices(client, device_ids=None, organization_ids=None, page_size=100):
    """
    List devices in a table format with pagination and optional filtering.

    :param client: Instance of NinjaOneClient.
    :param device_ids: Comma-separated string of device IDs to filter by.
    :param organization_ids: Comma-separated string of organization IDs to filter by.
    :param page_size: Number of devices to retrieve per page.
    """
    try:
        endpoint = "devices-detailed"
        all_devices = []
        after = None  # Cursor for pagination
        filters = []

        # Construct filters based on provided arguments
        if device_ids:
            ids = [id.strip() for id in device_ids.split(',') if id.strip().isdigit()]
            if ids:
                filter_str = f"id in ({','.join(ids)})"
                filters.append(filter_str)
        
        if organization_ids:
            org_ids = [id.strip() for id in organization_ids.split(',') if id.strip().isdigit()]
            if org_ids:
                filter_str = f"organization in ({','.join(org_ids)})"
                filters.append(filter_str)
        
        # Combine filters using AND logic (you can adjust as needed)
        df = " AND ".join(filters) if filters else None

        while True:
            params = {
                "pageSize": page_size
            }
            if after:
                params["after"] = after
            if df:
                params["df"] = df

            logger.debug(f"Fetching devices with params: {params}")
            response = client.get(endpoint, params=params)
            response.raise_for_status()  # Raises HTTPError for bad responses

            data = response.json()
            logger.info(f"Fetched {len(data)} devices.")
            all_devices.extend(data)

            # Check for pagination
            if len((data))<page_size:
                logger.info(f"Running total: Fetched {len(all_devices)} devices.")
                break

            after = data[-1]['id']

            # Optional: Display progress or intermediate results
            console.print(f"[cyan]Fetching next page with cursor: {after}[/cyan]")

        if all_devices:
            display_table(all_devices, sort_key='id', second_column_key='name', title="Devices List")
            logger.info(f"Total devices fetched: {len(all_devices)}")
        else:
            console.print("[yellow]No devices found with the specified criteria.[/yellow]")
            logger.info("No devices found with the specified criteria.")
    
    except requests.exceptions.HTTPError as http_err:
        console.print(f"[red]HTTP error occurred: {http_err}[/red]")
        logger.error(f"HTTP error: {http_err}")
        if response.content:
            try:
                logger.error(response.json())
            except ValueError:
                logger.error(response.text)
    except Exception as err:
        console.print(f"[red]An error occurred: {err}[/red]")
        logger.error(f"Unexpected error: {err}")


def display_table(data, sort_key='id', second_column_key='name', ascending=True, title=None):
    """
    Function to display a sorted table using the rich library.

    :param data: List of dictionaries containing data to display.
    :param sort_key: The key to sort the data by. Default is 'id'.
    :param second_column_key: The key for the second column. Default is 'name'.
    :param ascending: Boolean flag to determine if sorting is ascending (True) or descending (False). Default is True (ascending).
    :param title: Optional title for the table.
    """
    if not data:
        console.print("[yellow]No data to display.[/yellow]")
        return

    # Ensure each item is a dictionary
    valid_data = [item for item in data if isinstance(item, dict) and isinstance(item.get(sort_key, None), (int, float, str))]

    if not valid_data:
        console.print(f"[red]No valid data found to sort by '{sort_key}'.[/red]")
        return

    # Sort the list by the given sort_key based on the ascending flag
    sorted_data = sorted(valid_data, key=lambda x: x.get(sort_key, ''), reverse=not ascending)

    # Create a table with Rich
    table_title = title if title else f"Data Sorted by {sort_key.capitalize()} ({'Ascending' if ascending else 'Descending'})"
    table = Table(title=table_title, box=box.MINIMAL_DOUBLE_HEAD, expand=True)

    # Define the first two columns with appropriate overflow settings
    table.add_column(sort_key.capitalize(), justify="right", style="cyan", overflow="fold")
    table.add_column(second_column_key.capitalize(), justify="left", style="magenta", overflow="fold")

    # Add remaining columns dynamically
    if len(sorted_data) > 0:
        extra_keys = [key for key in sorted_data[0].keys() if key not in [sort_key, second_column_key]]
        for key in extra_keys:
            table.add_column(key.capitalize(), justify="left", style="green", overflow="fold")

        # Add rows to the table
        for item in sorted_data:
            row_data = [str(item.get(sort_key, '')), str(item.get(second_column_key, ''))]

            # Add extra columns and handle nested or missing data
            for key in extra_keys:
                value = item.get(key, 'N/A')
                if isinstance(value, (dict, list)):
                    # Convert nested structures to pretty JSON strings
                    value = json.dumps(value, indent=2)
                else:
                    value = str(value)
                row_data.append(value)

            table.add_row(*row_data)

    # Display the table
    console.print(table)


def parse_arguments():
    """
    Set up and parse command-line arguments.
    """
    parser = argparse.ArgumentParser(description="NinjaOne OAuth Script with Multiple Functionalities")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Subparser for listing devices
    devices_parser = subparsers.add_parser('list-devices', help='List devices with optional pagination and filtering')
    devices_parser.add_argument("--device_ids", type=str, help="Comma-separated list of device IDs to filter by (e.g., '1,2,3')")
    devices_parser.add_argument("--organization_ids", type=str, help="Comma-separated list of organization IDs to filter by (e.g., '1,2')")
    devices_parser.add_argument("--page_size", type=int, default=100, help="Number of devices to return per page (default: 100)")

    # Global arguments
    parser.add_argument("--client_id", type=str, help="Client ID")
    parser.add_argument("--client_secret", type=str, help="Client Secret")
    parser.add_argument("--scopes", type=str, help="Scopes (e.g., 'management monitoring')")
    parser.add_argument("--instance", type=str, help="Instance (e.g., app, ca, eu)")

    return parser.parse_args()


def get_client_from_somewhere(args):
    client_id = args.client_id or os.getenv('CLIENT_ID') or Prompt.ask("Enter CLIENT_ID")
    client_secret = args.client_secret or os.getenv('CLIENT_SECRET') or Prompt.ask("Enter CLIENT_SECRET", password=True)
    scopes = args.scopes or os.getenv('SCOPES', 'management') or Prompt.ask("Enter SCOPES", default='management')
    instance = args.instance or os.getenv('INSTANCE', 'app') or Prompt.ask("Enter INSTANCE (e.g., ca, us)", default='app')

    # Validate inputs
    required_vars = {
        'CLIENT_ID': client_id,
        'CLIENT_SECRET': client_secret,
        'SCOPES': scopes,
        'INSTANCE': instance
    }
    missing_vars = [var for var, value in required_vars.items() if not value]
    if missing_vars:
        console.print(f"[red]Missing required variables: {', '.join(missing_vars)}[/red]")
        logger.error(f"Missing required variables: {missing_vars}")
        sys.exit(1)

    client = NinjaOneClient(
        client_id=client_id,
        client_secret=client_secret,
        scopes=scopes,
        instance=instance
    )

    return client


def main():
    args = parse_arguments()
    client = get_client_from_somewhere(args)

    if args.command == 'list-devices':
        device_ids = args.device_ids
        organization_ids = args.organization_ids
        page_size = args.page_size

        list_devices(client, device_ids=device_ids, organization_ids=organization_ids, page_size=page_size)
    else:
        # If no command is provided, show help
        console.print("[bold red]No command provided.[/bold red]")
        console.print("Available commands: list-devices")
        logger.warning("No command provided by the user.")
        return


if __name__ == "__main__":
    main()
