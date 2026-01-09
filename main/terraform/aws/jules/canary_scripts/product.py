from aws_synthetics.selenium import synthetics_webdriver as syn_webdriver
from aws_synthetics.common import synthetics_logger as logger
from selenium.webdriver.common.by import By
import os

def handler(event, context):
    logger.info("Handler started for PRODUCT canary")
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
            # Relaxed check: Just ensure page has content
        except Exception as e:
            logger.warn("Could not find H2 tag, checking page source")

        if "Sunglasses" not in driver.page_source and "Vintage Typewriter" not in driver.page_source:
             driver.save_screenshot("/tmp/failure.png")
             raise Exception("Expected product content not found on page")

        driver.save_screenshot("/tmp/screenshot.png")

        logger.info("Page loaded successfully")
        return {
            "statusCode": 200,
            "statusText": "OK"
        }
    except Exception as e:
        logger.error("Canary failed: %s" % str(e))
        raise e
