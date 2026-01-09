from aws_synthetics.selenium import synthetics_webdriver as syn_webdriver
from aws_synthetics.common import synthetics_logger as logger
from selenium.webdriver.common.by import By
import os

def handler(event, context):
    logger.info("Handler started for HEALTH canary")
    try:
        url = os.environ.get("URL")
        if not url:
            raise ValueError("URL environment variable is not set")

        driver = syn_webdriver.Chrome()

        logger.info("Navigating to URL: %s" % url)
        driver.get(url)

        body_text = driver.find_element(By.TAG_NAME, "body").text
        if "ok" not in body_text:
            raise Exception("Health check failed: 'ok' not found in body")

        logger.info("Health check passed")
        return {
            "statusCode": 200,
            "statusText": "OK"
        }
    except Exception as e:
        logger.error("Canary failed: %s" % str(e))
        raise e
