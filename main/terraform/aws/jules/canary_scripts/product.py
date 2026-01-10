from aws_synthetics.selenium import synthetics_webdriver as syn_webdriver
from aws_synthetics.common import synthetics_logger as logger
from selenium.webdriver.common.by import By
import os

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

        # Check for specific product name
        try:
            # Wait/Check for h2 tag
            product_name = driver.find_element(By.TAG_NAME, "h2").text
            logger.info("Found product: %s" % product_name)
        except Exception as e:
            logger.warning("Could not find H2 tag, checking page source")

        if "Sunglasses" not in driver.page_source and "Vintage Typewriter" not in driver.page_source:
             # Synthetics automatically captures screenshots on failure
             raise Exception("Expected product content not found on page")

        # Removed manual screenshot

        logger.info("Page loaded successfully")
        return {
            "statusCode": 200,
            "statusText": "OK"
        }
    except Exception as e:
        logger.error("Canary failed: %s" % str(e))
        try:
            if driver:
                driver.save_screenshot("/tmp/failed.png")
                logger.info("Screenshot saved to /tmp/failed.png")
        except Exception as se:
            logger.error("Failed to take screenshot: %s" % str(se))
        raise e
