from aws_synthetics.selenium import synthetics_webdriver as syn_webdriver
from aws_synthetics.common import synthetics_logger as logger
import os
import uuid

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
            raise Exception("Page title does not match. Expected 'Online Boutique', got: %s" % title)

        logger.info("Page loaded successfully")
        return {
            "statusCode": 200,
            "statusText": "OK"
        }
    except Exception as e:
        logger.error("Canary failed: %s" % str(e))

        # Take screenshot ONLY on failure
        try:
            if driver:
                failure_screenshot_name = f"home_canary_failure_{str(uuid.uuid4())[:8]}"
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
