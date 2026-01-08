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

    # Check for specific product name
    try:
        product_name = driver.find_element(By.TAG_NAME, "h2").text
        # Or check body text if H2 is not guaranteed, but Sunglasses should be prominent
        if "Sunglasses" not in driver.page_source:
             raise Exception("Product 'Sunglasses' not found on page")
    except Exception as e:
        driver.save_screenshot("/tmp/failure.png")
        raise e

    driver.save_screenshot("/tmp/screenshot.png")

    logger.info("Page loaded successfully")
    return {
        "statusCode": 200,
        "statusText": "OK"
    }
