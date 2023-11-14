# CxOne Get Scan Workflow Tool Usage Guide

## Summary

This tool designed to retrieve the workflow log from a specific scan in Checkmarx One and save it as a CSV file. This utility simplifies the process of extracting detailed workflow information, allowing for easy analysis and record-keeping of scan activities.

## Syntax and Arguments

Execute the script using the following command line:

```
python get_scan_workflow.py --base_url BASE_URL --tenant_name TENANT_NAME --api_key API_KEY --scan_id SCAN_ID --output_file OUTPUT_FILE [OPTIONS]
```

### Required Arguments

- `--base_url`: The base URL of the Checkmarx One region.
- `--tenant_name`: Your tenant name in Checkmarx One.
- `--api_key`: Your API key for authenticating with the Checkmarx One APIs.
- `--scan_id`: The ID of the scan for which you want to retrieve the workflow.
- `--output_file`: The name of the CSV file where the workflow data will be saved.

### Optional Arguments

- `--iam_base_url`: Optional IAM base URL. Defaults to the same as `base_url` if not provided.
- `--debug`: Enable debug output. (Flag, no value required)

## Usage Examples

Retrieving and saving a scan workflow log:

```
python get_scan_workflow.py --base_url https://cxone.example.com --tenant_name mytenant --api_key 12345 --scan_id 67890 --output_file scan_workflow.csv
```

Retrieving and saving a scan workflow log with debug output:

```
python get_scan_workflow.py --base_url https://cxone.example.com --tenant_name mytenant --api_key 12345 --scan_id 67890 --output_file scan_workflow.csv --debug
```

## Output

The CxOne Scan Workflow Exporter will provide console output indicating the steps being performed, such as authentication, retrieval of the workflow, and writing the data to the CSV file. If the `--debug` flag is used, additional diagnostic information will be displayed to assist in troubleshooting and verifying the process.
