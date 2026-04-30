import os
import sentry_sdk
from dotenv import load_dotenv

def test_sentry():
    load_dotenv()
    sentry_dsn = os.getenv("SENTRY_DSN")
    if not sentry_dsn:
        print("Error: SENTRY_DSN is not set in the environment.")
        return
        
    print("Testing Sentry initialization...")
    try:
        sentry_sdk.init(
            dsn=sentry_dsn,
            traces_sample_rate=1.0,
        )
        print("Sentry initialized successfully! Sending test exception...")
        
        try:
            1 / 0
        except ZeroDivisionError as e:
            sentry_sdk.capture_exception(e)
            
        # Give sentry time to flush
        sentry_sdk.flush()
        print("Success! Test exception sent to Sentry.")
    except Exception as e:
        print(f"Error initializing or sending to Sentry: {e}")

if __name__ == "__main__":
    test_sentry()
