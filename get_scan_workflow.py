import sys
import requests
import argparse
import time
import json

import csv

# Standard global variables
base_url = None
tenant_name = None
auth_url = None
iam_base_url = None
api_key = None
auth_token = None
token_expiration = 0 # initialize so we have to authenticate
debug = False

def generate_auth_url():
    global iam_base_url
        
    try:
        if debug:
            print("Generating authentication URL...")
        
        if iam_base_url is None:
            iam_base_url = base_url.replace("ast.checkmarx.net", "iam.checkmarx.net")
            if debug:
                print(f"Generated IAM base URL: {iam_base_url}")
        
        temp_auth_url = f"{iam_base_url}/auth/realms/{tenant_name}/protocol/openid-connect/token"
        
        if debug:
            print(f"Generated authentication URL: {temp_auth_url}")
        
        return temp_auth_url
    except AttributeError:
        print("Error: Invalid base_url provided")
        sys.exit(1)

def authenticate():
    global auth_token, token_expiration

    # if the token hasn't expired then we don't need to authenticate
    if time.time() < token_expiration - 60:
        if debug:
            print("Token still valid.")
        return
    
    if debug:
        print("Authenticating with API key...")
        
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    data = {
        'grant_type': 'refresh_token',
        'client_id': 'ast-app',
        'refresh_token': api_key
    }
    
    try:
        response = requests.post(auth_url, headers=headers, data=data)
        response.raise_for_status()
        
        json_response = response.json()
        auth_token = json_response.get('access_token')
        if not auth_token:
            print("Error: Access token not found in the response.")
            sys.exit(1)
        
        expires_in = json_response.get('expires_in')
        
        if not expires_in:
            expires_in = 600

        token_expiration = time.time() + expires_in

        if debug:
            print("Authenticated successfully.")
      
    except requests.exceptions.RequestException as e:
        print(f"An error occurred during authentication: {e}")
        sys.exit(1)

def get_scan_workflow(scan_id):
    if debug:
        print(f"Retrieving workflow for scan ID: {scan_id}")
    authenticate()

    workflow_url = f"{base_url}/api/scans/{scan_id}/workflow"
    headers = {
        'Accept': 'application/json; version=1.0',
        'Authorization': f'Bearer {auth_token}'
    }

    try:
        response = requests.get(workflow_url, headers=headers)
        response.raise_for_status()

        if debug:
            print("Workflow data retrieved successfully")

        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while retrieving the workflow: {e}")
        return None

def write_workflow_to_csv(workflow_data, output_file):
    if not workflow_data:
        print("Error: No workflow data to write.")
        return

    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=['Timestamp', 'Source', 'Info'])
            writer.writeheader()
            for event in workflow_data:
                writer.writerow(event)

    except IOError as e:
        print(f"An error occurred while writing to the file: {e}")

def read_scan_ids_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except IOError as e:
        print(f"An error occurred while reading the file: {e}")
        sys.exit(1)

def main():
    global base_url
    global tenant_name
    global debug
    global auth_url
    global auth_token
    global iam_base_url
    global api_key

    # Parse and handle various CLI flags
    parser = argparse.ArgumentParser(description='Export a CxOne scan workflow as a CSV file')
    parser.add_argument('--base_url', required=True, help='Region Base URL')
    parser.add_argument('--iam_base_url', required=False, help='Region IAM Base URL')
    parser.add_argument('--tenant_name', required=True, help='Tenant name')
    parser.add_argument('--api_key', required=True, help='API key for authentication')
    parser.add_argument('--scan_id', required=False, help='ID of the scan to retrieve')
    parser.add_argument('--scan_id_file', required=False, help='File containing list of scan IDs')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')

    args = parser.parse_args()
    
    # Ensure either scan_id or scan_id_file is provided, but not both
    if bool(args.scan_id) == bool(args.scan_id_file):
        parser.error("Either --scan_id or --scan_id_file must be provided, but not both.")
    
    base_url = args.base_url
    tenant_name = args.tenant_name
    debug = args.debug
    if args.iam_base_url:
        iam_base_url = args.iam_base_url
    api_key = args.api_key
    auth_url = generate_auth_url()
    
    scan_ids = [args.scan_id] if args.scan_id else read_scan_ids_from_file(args.scan_id_file)

    for scan_id in scan_ids:
        workflow_data = get_scan_workflow(scan_id)
        if workflow_data is None:
            print(f"Failed to retrieve workflow data for scan ID {scan_id}.")
            continue

        # Write each workflow to a separate file named '<scan_id>.csv'
        write_workflow_to_csv(workflow_data, f"{scan_id}.csv")

    print(f"Workflow data written to {scan_id}.csv")

if __name__ == "__main__":
    main()