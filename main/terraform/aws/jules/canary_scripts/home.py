from aws_synthetics.selenium import synthetics_webdriver as syn_webdriver
from aws_synthetics.common import synthetics_logger as logger
from selenium.webdriver.common.by import By
import os

def handler(event, context):
    url = os.environ.get("URL")
    if not url:
        raise ValueError("URL environment variable is not set")

    driver = syn_webdriver.Chrome()

    logger.info("Navigating to URL: %s" % url)
    driver.get(url)

    # Assert title to ensure page loaded correctly
    title = driver.title
    if "Online Boutique" not in title:
         driver.save_screenshot("/tmp/failure.png")
         raise Exception("Page title does not match. Expected 'Online Boutique', got: %s" % title)

    driver.save_screenshot("/tmp/screenshot.png")

    logger.info("Page loaded successfully")
    return {
        "statusCode": 200,
        "statusText": "OK"
    }
