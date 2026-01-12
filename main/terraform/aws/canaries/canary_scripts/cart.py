from aws_synthetics.selenium import synthetics_webdriver as syn_webdriver
from aws_synthetics.common import synthetics_logger as logger
import os
import uuid

def handler(event, context):
    logger.info("Handler started for CART canary")
    driver = None
    try:
        url = os.environ.get("URL")
        if not url:
            raise ValueError("URL environment variable is not set")

        driver = syn_webdriver.Chrome()

        logger.info("Navigating to URL: %s" % url)
        driver.get(url)

        # Optional: log title for extra visibility in logs
        try:
            logger.info("Page title: %s" % driver.title)
        except:
            pass

        # Positive check: basic indicator that we're on the cart page
        page_source_lower = driver.page_source.lower()
        if "cart" not in page_source_lower and "shopping cart" not in page_source_lower:
            raise Exception("Cart page did not load correctly - missing expected cart indicators")

        # Negative check: detect known error page content (from the failure screenshot)
        if ("Uh, oh!" in driver.page_source or
            "Something has failed" in driver.page_source or
            "could not retrieve cart" in page_source_lower or
            "rpc error" in page_source_lower or
            "HTTP Status: 500" in driver.page_source):
            raise Exception("Cart service failure detected - error page shown (likely backend unavailable)")

        logger.info("Cart page loaded successfully with no errors")
        return {
            "statusCode": 200,
            "statusText": "OK"
        }
    except Exception as e:
        logger.error("Canary failed: %s" % str(e))

        # Take screenshot ONLY on failure
        try:
            if driver:
                failure_screenshot_name = f"cart_canary_failure_{str(uuid.uuid4())[:8]}"
                driver.save_screenshot(failure_screenshot_name)
                logger.info(f"Failure screenshot taken: {failure_screenshot_name}.png")
        except Exception as se:
            logger.error("Failed to take failure screenshot: %s" % str(se))

        raise e  # Re-raise to mark canary as failed
    finally:
        if driver:
            try:
                driver.quit()
                logger.info("Driver quit successfully")
            except Exception as qe:
                logger.error("Error quitting driver: %s" % str(qe))
