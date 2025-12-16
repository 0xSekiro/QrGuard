const { scanURL } = require("../Services/urlChecker.service.js");
const { VirusTotalScan } = require("../Services/VirusTotal.service.js");
// const { generateAIReport } = require("../Services/Aireport.service");
const LinkScan = require("../models/linkModel.js");


async function check_url(req, res) {
  try {
    const { url } = req.body;

    if (!url || typeof url !== "string") {
      return res.status(400).json({ error: "URL must be a string" });
    }

    const normalized = url.trim();

    const existingScan = await LinkScan.findOne({ link: normalized });

    if (existingScan) {
      // ✅ FOUND → return cached result
      return res.json({
        cached: true,
        data: JSON.parse(existingScan.response),
      });
    }

    // 1️⃣ Run your custom URL scanner
    const myScanResult = await scanURL(normalized);

    // 2️⃣ Run VirusTotal scan
    const { analysisId, report } = await VirusTotalScan(normalized);

    // You can keep risk_score/summary if you want
    const stats = report.data.attributes.stats;
    const total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;
    const vt_risk_score = total > 0 ? Math.round((stats.malicious + stats.suspicious * 0.5) / total * 100) : 0;

    let vt_verdict, vt_color;
    if (vt_risk_score === 0) { vt_verdict = "clean"; vt_color = "green"; }
    else if (vt_risk_score <= 20) { vt_verdict = "safe"; vt_color = "lightgreen"; }
    else if (vt_risk_score <= 50) { vt_verdict = "suspicious"; vt_color = "yellow"; }
    else { vt_verdict = "malicious"; vt_color = "red"; }

    const virustotal = {
      analysisId,
      risk_score: vt_risk_score,
      verdict: vt_verdict,
      color: vt_color,
      full_report: report.data // ✅ full VirusTotal JSON
    };
    
    const responsePayload1 = {
      url: normalized,
      qr_guard: myScanResult,
      virustotal,
    };

    res.json({
      cached: false,
      data: responsePayload1
    });

    const responsePayload2 = {
      url: normalized,
      qr_guard: myScanResult,
      virustotal,
    };

    await LinkScan.create({
      link: normalized,                          // string
      response: JSON.stringify(responsePayload2), // string
    });

    

  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).json({
      error: "URL scan failed",
      details: err.response?.data || err.message,
    });
  }
}

module.exports = { check_url };
