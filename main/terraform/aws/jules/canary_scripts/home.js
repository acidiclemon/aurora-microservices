var synthetics = require('Synthetics');
const log = require('SyntheticsLogger');

const pageLoadBlueprint = async function () {
    const url = process.env.URL;
    if (!url) {
        throw "URL environment variable is not set";
    }

    let page = await synthetics.getPage();
    const response = await page.goto(url, {waitUntil: 'domcontentloaded', timeout: 30000});
    if (!response || response.status() !== 200) {
        throw "Failed to load page: " + response.status() + " " + response.statusText();
    }
    await page.screenshot({ path: '/tmp/screenshot.png' });
};

exports.handler = async () => {
    return await pageLoadBlueprint();
};
