#!/usr/bin/env python3
"""
CLI Report Tool - GraphQL to CSV converter
"""
import os
import sys
from dotenv import load_dotenv


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


def main():
    """Main entry point for the application."""
    verify_environment_variables()

    # TODO: Add GraphQL query logic
    # TODO: Parse JSON response
    # TODO: Write CSV file
    print("Application started successfully")


if __name__ == "__main__":
    main()
