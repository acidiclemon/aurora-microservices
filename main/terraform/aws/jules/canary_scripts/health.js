var synthetics = require('Synthetics');
const log = require('SyntheticsLogger');

const pageLoadBlueprint = async function () {
    const url = process.env.URL;
    if (!url) {
        throw "URL environment variable is not set";
    }

    let page = await synthetics.getPage();
    const response = await page.goto(url, {waitUntil: 'networkidle0', timeout: 30000});
    if (!response || response.status() !== 200) {
        throw "Failed to load page: " + response.status() + " " + response.statusText();
    }
    const text = await page.evaluate(() => document.body.textContent);
    if (!text.includes('ok')) {
         throw "Health check failed: " + text;
    }
};

exports.handler = async () => {
    return await pageLoadBlueprint();
};
