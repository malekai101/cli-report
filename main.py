#!/usr/bin/env python3
"""
CLI Report Tool - GraphQL to CSV converter
"""
import argparse
import csv
import json
import os
import sys
from dotenv import load_dotenv
from urllib.parse import urlparse
import requests
import pprint
import datetime

def authenticate_to_wiz(client_id: str, client_secret: str) -> dict:
    """
    Authenticate to Wiz using OAuth2 client credentials flow.

    Args:
        client_id: The Wiz service account client ID
        client_secret: The Wiz service account client secret

    Returns:
        dict: Authentication response containing access_token, refresh_token,
              expires_in, and token_type

    Raises:
        requests.exceptions.RequestException: If the authentication request fails
    """
    auth_url = 'https://auth.app.wiz.io/oauth/token'

    payload = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'audience': 'wiz-api'
    }

    headers = {
        'content-type': 'application/x-www-form-urlencoded'
    }

    response = requests.post(auth_url, data=payload, headers=headers)
    response.raise_for_status()

    return response.json()


def run_graphql_query(url: str, token: str, query: str = "", variables: str = "") -> dict:
    """
    Run a GraphQL query against the Wiz API.

    Args:
        token: The bearer token for authentication
        query: The GraphQL query string (optional, defaults to empty string)

    Returns:
        dict: The JSON response from the GraphQL API

    Raises:
        requests.exceptions.RequestException: If the GraphQL request fails
    """
    api_url = url

    headers = {
        'Authorization': f'bearer {token}',
        'content-type': 'application/json'
    }

    if variables == "":
        payload = {
            'query': query
        }
    else:
        payload = {
            'query': query,
            'variables': json.loads(variables)
        }

    response = requests.post(api_url, json=payload, headers=headers)
    response.raise_for_status()

    return response.json()


def run_graphql_query_with_pagination(url: str, token: str, query: str, variables: str) -> dict:
    """
    Run a GraphQL query with cursor-based pagination and combine all results.

    Args:
        url: The API endpoint URL
        token: The bearer token for authentication
        query: The GraphQL query string
        variables: The GraphQL variables as a JSON string

    Returns:
        dict: Combined response with all nodes from all pages

    Raises:
        requests.exceptions.RequestException: If any GraphQL request fails
    """
    all_nodes = []
    has_next_page = True
    cursor = None

    # Parse variables once
    vars_dict = json.loads(variables)

    while has_next_page:
        # Update the 'after' cursor for pagination
        if cursor:
            vars_dict['after'] = cursor

        # Convert back to JSON string for run_graphql_query
        current_variables = json.dumps(vars_dict)

        # Fetch current page
        response = run_graphql_query(url, token, query, current_variables)

        # Extract pagination info and nodes
        cloud_events = response.get('data', {}).get('cloudEvents', {})
        nodes = cloud_events.get('nodes', [])
        page_info = cloud_events.get('pageInfo', {})

        # Accumulate nodes
        all_nodes.extend(nodes)

        # Check if there are more pages
        has_next_page = page_info.get('hasNextPage', False)
        cursor = page_info.get('endCursor')

    # Return combined result with all nodes
    return {
        'data': {
            'cloudEvents': {
                'nodes': all_nodes,
                'totalCount': len(all_nodes)
            }
        }
    }


def verify_environment_variables():
    """Verify that required environment variables are set."""
    # Load environment variables from .env file if it exists
    load_dotenv()

    required_vars = ['API_KEY', 'SECRET_KEY']
    missing_vars = []

    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)

    if missing_vars:
        print("Error: Missing required environment variables:", file=sys.stderr)
        for var in missing_vars:
            print(f"  - {var}", file=sys.stderr)
        print("\nPlease set these variables in your environment or create a .env file.", file=sys.stderr)
        sys.exit(1)

    print("✓ Environment variables verified")


def validate_days(value: str) -> int:
    """
    Validate that the days parameter is within acceptable range.

    Args:
        value: The days value as a string

    Returns:
        int: The validated days value

    Raises:
        argparse.ArgumentTypeError: If days is not within valid range
    """
    try:
        days = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Days must be an integer. Got: {value}")

    if days < 1:
        raise argparse.ArgumentTypeError(f"Days must be at least 1. Got: {days}")

    if days > 60:
        raise argparse.ArgumentTypeError(f"Days must not exceed 60. Got: {days}")

    return days


def validate_url(url: str) -> str:
    """
    Validate that the URL is from an allowed Wiz API domain.

    Args:
        url: The URL to validate

    Returns:
        str: The validated URL

    Raises:
        argparse.ArgumentTypeError: If URL is not from an allowed domain
    """
    allowed_domains = [
        'api.us1.app.wiz.io',
        'api.us20.app.wiz.io'
    ]

    try:
        parsed = urlparse(url)
        if parsed.hostname not in allowed_domains:
            raise argparse.ArgumentTypeError(
                f"URL must be from allowed Wiz API domains. Got: {parsed.hostname}"
            )
        if parsed.scheme not in ['https']:
            raise argparse.ArgumentTypeError(
                f"URL must use HTTPS protocol. Got: {parsed.scheme}"
            )
        return url
    except Exception as e:
        raise argparse.ArgumentTypeError(f"Invalid URL: {e}")


def validate_filepath(filepath: str) -> str:
    """
    Validate and sanitize the output filepath.

    Args:
        filepath: The filepath to validate

    Returns:
        str: The validated absolute filepath

    Raises:
        argparse.ArgumentTypeError: If filepath is invalid or unsafe
    """
    # Resolve to absolute path
    abs_path = os.path.abspath(filepath)

    # Check if path exists
    if not os.path.exists(abs_path):
        raise argparse.ArgumentTypeError(f"Path does not exist: {filepath}")

    # Check if it's a directory
    if not os.path.isdir(abs_path):
        raise argparse.ArgumentTypeError(f"Path is not a directory: {filepath}")

    # Check if we have write permissions
    if not os.access(abs_path, os.W_OK):
        raise argparse.ArgumentTypeError(f"No write permission for path: {filepath}")

    return abs_path


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='CLI Report Tool - GraphQL to CSV converter for Wiz CLI usage'
    )
    parser.add_argument(
        '-d', '--days',
        type=validate_days,
        default=30,
        help='Number of days to look back for data (default: 30, max: 60)'
    )
    parser.add_argument(
        '-u', '--url',
        type=validate_url,
        default='https://api.us1.app.wiz.io/graphql',
        help='URL for the API endpoint (default: https://api.us1.app.wiz.io/graphql)'
    )
    parser.add_argument(
        '-f', '--filepath',
        type=validate_filepath,
        default='.',
        help='File path for output (default: .)'
    )
    return parser.parse_args()

def get_unsupported_cli_calls(url: str, auth_token: str, days: int) -> dict:
    query = """query CodeCICDScansTable($after: String, $first: Int, $filterBy: CloudEventFilters, $groupBy: CloudEventGroupBy, $orderDirection: OrderDirection, $projectId: [String!], $includeCount: Boolean!) {
  cloudEvents(
    filterBy: $filterBy
    first: $first
    after: $after
    groupBy: $groupBy
    orderDirection: $orderDirection
    projectId: $projectId
  ) {
    nodes {
      ... on CloudEventGroupByResult {
        values
        count: countV2 @include(if: $includeCount)
        cloudEvents {
          id
          timestamp
          cloudPlatform
          category
          hash
          kind
          externalName
          origin
          path
          actor {
            email
            type
            name
            id
            userAgent
            providerUniqueId
          }
          subjectResource {
            id
            type
            externalId
            name
            nativeType
            region
            cloudAccount {
              cloudProvider
              id
              externalId
            }
            kubernetesCluster {
              id
              name
              type
            }
            vcsRepository {
              type
              providerUniqueId
              id
              name
            }
            openToAllInternet
          }
          matchedRules {
            rule {
              builtInId
              name
              id
            }
          }
          extraDetails {
            ...CloudEventCICDScanDetailsExtraDetails
          }
        }
      }
      ... on CloudEvent {
        id
        timestamp
        kind
        origin
        cloudPlatform
        subjectResource {
          id
          name
          type
          vcsRepository {
            type
            providerUniqueId
            id
            name
          }
        }
        actor {
          email
          type
          name
          id
          userAgent
          providerUniqueId
        }
        extraDetails {
          ... on CloudEventCICDScanDetails {
            ...CloudEventCICDScanDetailsExtraDetails
          }
        }
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
    totalCount @include(if: $includeCount)
    maxCountReached
  }
}

    fragment CloudEventCICDScanDetailsExtraDetails on CloudEventCICDScanDetails {
  trigger
  tags {
    key
    value
  }
  policies {
    __typename
    id
    name
    params {
      __typename
    }
  }
  createdBy {
    serviceAccount {
      id
      name
    }
  }
  cliDetails {
    scanOriginResourceType
    clientVersion
    buildParams {
      committedBy
      repository
      commitHash
    }
  }
  executionDetails {
    isDifferential
    isForcedPass
  }
  malwareDetails {
    analytics {
      infoCount
      lowCount
      mediumCount
      highCount
      criticalCount
      totalCount
    }
  }
  analytics {
    vulnerabilityScanResultAnalytics {
      infoCount
      lowCount
      mediumCount
      highCount
      criticalCount
    }
    dataScanResultAnalytics {
      infoCount
      lowCount
      mediumCount
      highCount
      criticalCount
    }
    iacScanResultAnalytics {
      infoCount: infoMatches
      lowCount: lowMatches
      mediumCount: mediumMatches
      highCount: highMatches
      criticalCount: criticalMatches
    }
    secretScanResultAnalytics {
      cloudKeyCount
      dbConnectionStringCount
      gitCredentialCount
      passwordCount
      privateKeyCount
      saasAPIKeyCount
      infoCount
      lowCount
      mediumCount
      highCount
      criticalCount
      totalCount
      infoCount
      lowCount
      mediumCount
      highCount
      criticalCount
    }
    sastScanResultAnalytics {
      infoCount
      lowCount
      mediumCount
      highCount
      criticalCount
    }
  }
  status {
    details
    state
    verdict
  }
  codeAnalyzerDetails {
    pullRequest {
      id
      infoURL
      title
    }
  }
  infoMatches
  lowMatches
  mediumMatches
  highMatches
  criticalMatches
  hasTriggerableRemediation
}
"""

    variables = f'{{"filterBy":{{"and":[{{"timestamp":{{"inLast":{{"amount":{days},"unit":"DurationFilterValueUnitDays"}}}},"origin":{{"equals":["WIZ_CODE_ANALYZER","WIZ_CLI"]}},"kind":{{"equals":["CI_CD_SCAN"]}},"cicdScan":{{"trigger":{{"equals":["USER_INITIATED"]}}}}}},{{"or":[{{"resource":{{}}}},{{"resource":{{}}}}]}},{{"or":[{{"cicdScan":{{"vulnerabilityFindingCount":{{}}}}}},{{"cicdScan":{{"iacFindingCount":{{}}}}}},{{"cicdScan":{{"secretFindingCount":{{}}}}}},{{"cicdScan":{{"dataFindingCount":{{}}}}}},{{"cicdScan":{{"hostConfigurationFindingCount":{{}}}}}},{{"cicdScan":{{"malwareFindingCount":{{}}}}}},{{"cicdScan":{{"softwareSupplyChainFindingCount":{{}}}}}},{{"cicdScan":{{"sastFindingCount":{{}}}}}}]}},{{"cicdScan":{{"resourceType":{{}},"verdict":{{}},"type":{{}},"state":{{}},"severities":{{}},"hasTriggerableRemediation":{{}},"hasFindingsIgnoredByCommentException":{{}},"repositoryVisibility":{{}}}}}},{{}},{{"rawAuditLogRecordPath":{{"path":"cliDetails.clientVersion","startsWith":["0."]}}}}]}},"includeCount":false}}'

    return run_graphql_query_with_pagination(url, auth_token, query, variables)

def clean_cli_data(raw_data: dict) -> list:
    """
    Extract relevant CLI data from raw GraphQL response.

    Args:
        raw_data: Raw GraphQL response containing cloudEvents nodes

    Returns:
        list: List of dictionaries with cleaned data for each node
    """
    cleaned_records = []

    # Extract nodes from the response
    nodes = raw_data.get('data', {}).get('cloudEvents', {}).get('nodes', [])

    for node in nodes:
        # Handle both CloudEventGroupByResult and CloudEvent types
        # If it's a CloudEventGroupByResult, we need to iterate through cloudEvents
        if 'cloudEvents' in node:
            # This is a CloudEventGroupByResult
            cloud_events = node.get('cloudEvents', [])
        else:
            # This is a direct CloudEvent
            cloud_events = [node]

        for event in cloud_events:
            # Extract actor information
            actor = event.get('actor', {})
            actor_type = actor.get('type', '')
            actor_name = actor.get('name', '')

            # Extract subjectResource information
            subject_resource = event.get('subjectResource', {})
            resource_name = subject_resource.get('name', '')

            # Extract extraDetails and cliDetails
            extra_details = event.get('extraDetails', {})
            cli_details = extra_details.get('cliDetails', {})
            build_params = cli_details.get('buildParams', {})

            # Build the cleaned record
            record = {
                'timestamp': event.get('timestamp', ''),
                'actor_type': actor_type,
                'actor_name': actor_name,
                'resource_name': resource_name,
                'scan_origin_resource_type': cli_details.get('scanOriginResourceType', ''),
                'client_version': cli_details.get('clientVersion', ''),
                'repository': build_params.get('repository', ''),
                'commit_hash': build_params.get('commitHash', ''),
                'committed_by': build_params.get('committedBy', '')
            }

            cleaned_records.append(record)

    return cleaned_records

def write_csv(data: list, filepath: str):
    """
    Write cleaned CLI data to a CSV file.

    Args:
        data: List of dictionaries containing cleaned CLI data
        filepath: Directory path where the CSV file should be saved
    """
    if not data:
        print("No data to write to CSV")
        return

    # Generate filename with timestamp
    filename = f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_cli_report.csv"
    full_path = os.path.join(filepath, filename)

    # Get field names from the first record
    fieldnames = data[0].keys()

    # Write to CSV
    with open(full_path, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

    print(f"✓ CSV file written to: {full_path}")


def main():
    """Main entry point for the application."""
    args = parse_arguments()
    days = args.days
    url = args.url
    filepath = args.filepath
    verify_environment_variables()

    # Authenticate to Wiz
    auth_response = authenticate_to_wiz(os.getenv('API_KEY'), os.getenv('SECRET_KEY'))
    auth_token = auth_response.get('access_token')

    print(f"Fetching data for the last {days} days...")

    # TODO: Add GraphQL query logic
    raw_cli_data = get_unsupported_cli_calls(url, auth_token, days)
    # TODO: Parse JSON response
    clean_data = clean_cli_data(raw_cli_data)
    # TODO: Write CSV file
    write_csv(clean_data, filepath)
    print(f"Report written to: {filepath}")
    print("Application finished successfully")


if __name__ == "__main__":
    main()
