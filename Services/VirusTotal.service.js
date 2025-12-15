const axios = require("axios");

async function VirusTotalScan(url) {
  const normalized = url.trim().toLowerCase();

  // Submit URL for analysis
  const submit = await axios.post(
    "https://www.virustotal.com/api/v3/urls",
    new URLSearchParams({ url: normalized }),
    {
      headers: {
        "x-apikey": process.env.VT_API_KEY,
        "Content-Type": "application/x-www-form-urlencoded",
      },
    }
  );

  const analysisId = submit.data.data.id;

  // Poll for results
  let report;
  const maxTries = 10;
  let tries = 0;
  const delay = ms => new Promise(res => setTimeout(res, ms));

  while (tries < maxTries) {
    const response = await axios.get(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      { headers: { "x-apikey": process.env.VT_API_KEY } }
    );

    report = response.data;

    // Check if stats are ready
    if (report?.data?.attributes?.stats) break;

    tries++;
    await delay(2000); // wait 2 seconds before next check
  }

  if (!report?.data?.attributes?.stats) {
    throw new Error("VirusTotal report not ready after multiple attempts");
  }

  return { analysisId, report };
}

module.exports = { VirusTotalScan };
