import os

import shodan
from dotenv import load_dotenv


def test_shodan():
    # Load environment variables
    load_dotenv()

    # Read API key
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        print("Error: SHODAN_API_KEY is not set in the environment.")
        return

    print("Testing Shodan API connection...")

    try:
        # Initialize Shodan API
        api = shodan.Shodan(api_key)

        # Run a simple account info request
        info = api.info()
        print("Success! Shodan API key is valid.")
        print(f"Account plan: {info.get('plan')}")
        print(f"Scan credits remaining: {info.get('scan_credits')}")
        print(f"Query credits remaining: {info.get('query_credits')}")

    except shodan.APIError as e:
        print(f"Error: Invalid Shodan API key or connection failed. Details: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")


if __name__ == "__main__":
    test_shodan()
