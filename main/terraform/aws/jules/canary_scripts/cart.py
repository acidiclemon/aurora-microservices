from aws_synthetics.selenium import synthetics_webdriver as syn_webdriver
from aws_synthetics.common import synthetics_logger as logger
from selenium.webdriver.common.by import By
import os
import boto3
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

        # Check for Cart text
        if "Cart" not in driver.page_source and "Shopping Cart" not in driver.page_source:
             # Synthetics automatically captures screenshots on failure
             raise Exception("Cart page did not load correctly")

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
                screenshot_path = "/tmp/failed.png"
                driver.save_screenshot(screenshot_path)
                logger.info("Screenshot saved to %s" % screenshot_path)

                # Manual upload to S3 to ensure visibility
                bucket = os.environ.get("ARTIFACT_S3_BUCKET")
                canary_name = os.environ.get("CANARY_NAME")

                logger.info("Env Check: BUCKET=%s, CANARY_NAME=%s" % (bucket, canary_name))

                if bucket and canary_name:
                    s3 = boto3.client('s3')
                    key = "FAILED_SCREENSHOT_%s_%s.png" % (canary_name, str(uuid.uuid4()))
                    logger.info("Attempting upload to s3://%s/%s" % (bucket, key))
                    s3.upload_file(screenshot_path, bucket, key)
                    logger.info("Upload successful")
                else:
                    logger.error("Missing environment variables for S3 upload")
        except Exception as se:
            logger.error("Failed to take/upload screenshot: %s" % str(se))
        raise e
