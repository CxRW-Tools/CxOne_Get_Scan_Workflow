# CxOne Get Scan Workflow Tool Usage Guide

## Summary

This tool designed to retrieve scan workflow logs from Checkmarx One and save them as CSV files. This utility simplifies the process of extracting detailed workflow information, allowing for easy analysis and record-keeping of scan activities.

## Syntax and Arguments

Execute the script using the following command line:

```
python get_scan_workflow.py --base_url BASE_URL --tenant_name TENANT_NAME --api_key API_KEY --scan_id SCAN_ID [OPTIONS]
```

Or, to process multiple scans from a file:

```
python get_scan_workflow.py --base_url BASE_URL --tenant_name TENANT_NAME --api_key API_KEY --scan_id_file SCAN_ID_FILE [OPTIONS]
```

### Required Arguments

- `--base_url`: The base URL of the Checkmarx One region.
- `--tenant_name`: Your tenant name in Checkmarx One.
- `--api_key`: Your API key for authenticating with the Checkmarx One APIs.
- `--scan_id` (optional if `--scan_id_file` is used): The ID of the scan for which you want to retrieve the workflow.
- `--scan_id_file` (optional if `--scan_id` is used): Path to a text file containing a list of scan IDs, one per line.

### Optional Arguments

- `--iam_base_url`: Optional IAM base URL. Defaults to the same as `base_url` if not provided.
- `--debug`: Enable debug output. (Flag, no value required)

## Usage Examples

Retrieving and saving a single scan workflow log:

```
python get_scan_workflow.py --base_url https://cxone.example.com --tenant_name mytenant --api_key 12345 --scan_id_file scan_ids.txt
```

Retrieving and saving multiple scan workflows from a file:

```
python get_scan_workflow.py --base_url https://cxone.example.com --tenant_name mytenant --api_key 12345 --scan_id 67890
```

Retrieving and saving a scan workflow log with debug output:

```
python get_scan_workflow.py --base_url https://cxone.example.com --tenant_name mytenant --api_key 12345 --scan_id 67890 --debug
```

## Output

For each scan ID, the tool generates a separate CSV file named `<scan_id>.csv` containing the workflow data. The tool provides console output indicating the steps being performed, such as authentication, retrieval of the workflow, and writing the data to the CSV files. If the `--debug` flag is used, additional diagnostic information will be displayed to assist in troubleshooting and verifying the process.
