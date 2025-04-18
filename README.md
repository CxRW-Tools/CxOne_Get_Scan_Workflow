# CxOne Get Scan Workflow Tool Usage Guide

## Summary

This tool designed to retrieve scan workflow logs from Checkmarx One and save them as CSV files. This utility simplifies the process of extracting detailed workflow information, allowing for easy analysis and record-keeping of scan activities.

## Syntax and Arguments

Execute the script using the following command line:

```
python get_scan_workflow.py --base_url BASE_URL --tenant_name TENANT_NAME --api_key API_KEY [--scan_id SCAN_ID | --scan_id_file SCAN_ID_FILE] [--debug]
```

### Required Arguments

- `--base_url`: The base URL of the Checkmarx One region.
- `--tenant_name`: Your tenant name in Checkmarx One.
- `--api_key`: Your API key for authenticating with the Checkmarx One APIs.
- `--scan_id` (optional): The ID of the scan for which you want to retrieve the workflow.
- `--scan_id_file` (optional): Path to a text file containing a list of scan IDs, one per line.

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

## License

MIT License

Copyright (c) 2024

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
