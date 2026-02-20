# cli-report

Code to build a report on Wiz CLI usage. This tool queries the Wiz API for CI/CD scan events from the Wiz CLI and exports the data to a CSV file.

## Prerequisites

- Python 3.x
- Required Python packages (install via `pip install -r requirements.txt`):
  - `requests`
  - `python-dotenv`

## Environment Variables

The following environment variables must be set before running the tool:

- `API_KEY` - Your Wiz service account client ID
- `SECRET_KEY` - Your Wiz service account client secret

You can set these in a `.env` file in the project root:

```
API_KEY=your_client_id_here
SECRET_KEY=your_client_secret_here
```

## Usage

```bash
python main.py [OPTIONS]
```

### Command-Line Options

| Option | Long Form | Type | Default | Description |
|--------|-----------|------|---------|-------------|
| `-d` | `--days` | int | 30 | Number of days to look back for data (max: 60) |
| `-u` | `--url` | string | `https://api.us1.app.wiz.io/graphql` | Wiz API endpoint URL.  Available in Wiz tenant information. |
| `-f` | `--filepath` | string | `.` | Output directory path for the CSV file |

### Examples

**Basic usage with defaults:**
```bash
python main.py
```
This will fetch the last 30 days of CLI usage data and save the CSV to the current directory.

**Fetch data for the last 7 days:**
```bash
python main.py -d 7
```

**Specify a different Wiz API region:**
```bash
python main.py -u https://api.us20.app.wiz.io/graphql
```

**Save output to a specific directory:**
```bash
python main.py -f /path/to/output
```

**Combine multiple options:**
```bash
python main.py -d 14 -f ./reports
```

## Output

The tool generates a timestamped CSV file with the following format:

`YYYYMMDD_HHMMSS_cli_report.csv`

### CSV Columns

- `timestamp` - When the scan occurred
- `actor_type` - Type of actor (e.g., USER, SERVICE_ACCOUNT)
- `actor_name` - Name/email of the actor
- `resource_name` - Name of the scanned resource
- `scan_origin_resource_type` - Type of resource scanned
- `client_version` - Version of the Wiz CLI used
- `repository` - Repository name (if applicable)
- `commit_hash` - Git commit hash (if applicable)
- `committed_by` - User who made the commit (if applicable)

## Security

The tool includes the following security features:

- **URL validation** - Only allows connections to official Wiz API domains
- **HTTPS enforcement** - Requires secure HTTPS connections
- **Path validation** - Prevents path traversal attacks on output directory
- **Input validation** - Validates all command-line inputs

## License

MIT License - Copyright (c) 2026
