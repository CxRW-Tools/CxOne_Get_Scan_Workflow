import sys
import json
import requests
import argparse
import csv

# Global variables
base_url = None
tenant_name = None
auth_url = None
iam_base_url = None
auth_token = None
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

def authenticate(api_key):
    if auth_url is None:
        return None
    
    if debug:
        print("Authenticating with API...")
        
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f'Bearer {api_key}'
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
        access_token = json_response.get('access_token')
        
        if not access_token:
            print("Error: Access token not found in the response.")
            return None
        
        if debug:
            print("Successfully authenticated")
        
        return access_token
    except requests.exceptions.RequestException as e:
        print(f"An error occurred during authentication: {e}")
        sys.exit(1)

def get_scan_workflow(scan_id):
    workflow_url = f"{base_url}/api/scans/{scan_id}/workflow"
    headers = {
        'Accept': 'application/json; version=1.0',
        'Authorization': f'Bearer {auth_token}'
    }

    if debug:
        print(f"Retrieving workflow for scan ID: {scan_id}")
        print(f"GET Request URL: {workflow_url}")

    try:
        response = requests.get(workflow_url, headers=headers)
        response.raise_for_status()

        if debug:
            print("Workflow data retrieved successfully.")

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

def main():
    global base_url
    global tenant_name
    global debug
    global auth_url
    global auth_token
    global iam_base_url

    # Parse and handle various CLI flags
    parser = argparse.ArgumentParser(description='Export a CxOne scan workflow as a CSV file')
    parser.add_argument('--base_url', required=True, help='Region Base URL')
    parser.add_argument('--iam_base_url', required=False, help='Region IAM Base URL')
    parser.add_argument('--tenant_name', required=True, help='Tenant name')
    parser.add_argument('--api_key', required=True, help='API key for authentication')
    parser.add_argument('--scan_id', required=True, help='ID of the scan to retrieve')
    parser.add_argument('--output_file', required=True, help='Name of the output CSV file')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')

    args = parser.parse_args()
    base_url = args.base_url
    tenant_name = args.tenant_name
    scan_id = args.scan_id
    output_file = args.output_file
    debug = args.debug
            
    # Authenticate to CxOne
    if args.iam_base_url:
        iam_base_url = args.iam_base_url
    
    auth_url = generate_auth_url()
    auth_token = authenticate(args.api_key)
    
    if auth_token is None:
        return
    
    workflow_data = get_scan_workflow(scan_id)
    if workflow_data is None:
        print("Failed to retrieve workflow data.")
        return

    write_workflow_to_csv(workflow_data, output_file)

    print(f"Workflow data successfully written to {output_file}")
  
if __name__ == "__main__":
    main()