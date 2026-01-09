from aws_synthetics.selenium import synthetics_webdriver as syn_webdriver
from aws_synthetics.common import synthetics_logger as logger
from selenium.webdriver.common.by import By
import os

def handler(event, context):
    logger.info("Handler started for HOME canary")
    driver = None
    try:
        url = os.environ.get("URL")
        if not url:
            raise ValueError("URL environment variable is not set")

        driver = syn_webdriver.Chrome()

        logger.info("Navigating to URL: %s" % url)
        driver.get(url)

        # Assert title to ensure page loaded correctly
        title = driver.title
        logger.info("Page title: %s" % title)
        if "Online Boutique" not in title:
             # Synthetics automatically captures screenshots on failure
             raise Exception("Page title does not match. Expected 'Online Boutique', got: %s" % title)

        # Removed manual screenshot to avoid runtime bug in syn-python-selenium-8.0

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
