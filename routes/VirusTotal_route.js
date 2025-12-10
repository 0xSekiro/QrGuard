const express = require("express");
const axios = require("axios");

const router = express.Router();

router.post("/scan", async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: "URL is required" });

    const normalized = url.trim().toLowerCase();

    // Submit URL
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

    // Get report
    const report = await axios.get(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      { headers: { "x-apikey": process.env.VT_API_KEY } }
    );

    const stats = report.data.data.attributes.stats;
    const total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;
    const score = total > 0 ? Math.round(((stats.malicious + stats.suspicious / 2) / total) * 100) : 0;

    // Verdict & color
    let verdict, color;
    if (score === 0) { verdict = "clean"; color = "green"; }
    else if (score <= 20) { verdict = "safe"; color = "lightgreen"; }
    else if (score <= 50) { verdict = "suspicious"; color = "yellow"; }
    else { verdict = "malicious"; color = "red"; }

    // Send response
    res.json({
      url: normalized,
      stats,
      score,
      verdict,
      color,
      report: report.data
    });

  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).json({
      error: "VirusTotal scan failed",
      details: err.response?.data || err.message
    });
  }
});

module.exports = router;
