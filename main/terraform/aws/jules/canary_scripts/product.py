from aws_synthetics.selenium import synthetics_webdriver as syn_webdriver
from aws_synthetics.common import synthetics_logger as logger
from selenium.webdriver.common.by import By
import os
import uuid

def handler(event, context):
    logger.info("Handler started for PRODUCT canary")
    driver = None
    try:
        url = os.environ.get("URL")
        if not url:
            raise ValueError("URL environment variable is not set")

        driver = syn_webdriver.Chrome()

        logger.info("Navigating to URL: %s" % url)
        driver.get(url)

        # Optional: Try to extract and log the product name from h2 (for better observability)
        try:
            product_name_element = driver.find_element(By.TAG_NAME, "h2")
            product_name = product_name_element.text.strip()
            logger.info("Found product name in h2: %s" % product_name)
        except Exception as e:
            logger.warning("Could not find or read h2 tag for product name: %s" % str(e))

        # Main check for expected product content
        if "Sunglasses" not in driver.page_source and "Vintage Typewriter" not in driver.page_source:
            raise Exception("Expected product content not found on page")

        logger.info("Page loaded successfully with expected product content")
        return {
            "statusCode": 200,
            "statusText": "OK"
        }
    except Exception as e:
        logger.error("Canary failed: %s" % str(e))

        # Take screenshot ONLY on failure
        try:
            if driver:
                failure_screenshot_name = f"product_canary_failure_{str(uuid.uuid4())[:8]}"
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
