from aws_synthetics.selenium import synthetics_webdriver as syn_webdriver
from aws_synthetics.common import synthetics_logger as logger
from selenium.webdriver.common.by import By
import os

def handler(event, context):
    logger.info("Handler started for CART canary")
    try:
        url = os.environ.get("URL")
        if not url:
            raise ValueError("URL environment variable is not set")

        driver = syn_webdriver.Chrome()

        logger.info("Navigating to URL: %s" % url)
        driver.get(url)

        # Check for Cart text
        if "Cart" not in driver.page_source and "Shopping Cart" not in driver.page_source:
             driver.save_screenshot("/tmp/failure.png")
             raise Exception("Cart page did not load correctly")

        driver.save_screenshot("/tmp/screenshot.png")

        logger.info("Page loaded successfully")
        return {
            "statusCode": 200,
            "statusText": "OK"
        }
    except Exception as e:
        logger.error("Canary failed: %s" % str(e))
        raise e
