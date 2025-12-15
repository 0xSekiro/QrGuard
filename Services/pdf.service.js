const fs = require("fs");
const pdf = require("html-pdf");

function generatePDFReport(data, aiText, outputPath) {
  const html = `
  <html>
  <head>
    <style>
      body { font-family: Arial; padding: 20px; }
      h1 { color: #2c3e50; }
      .safe { color: green; }
      .suspicious { color: orange; }
      .malicious { color: red; }
      .box { border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; }
    </style>
  </head>
  <body>

    <h1>QR Guard – Security Scan Report</h1>

    <div class="box">
      <strong>URL:</strong> ${data.url}<br/>
      <strong>Verdict:</strong>
      <span class="${data.verdict}">${data.verdict.toUpperCase()}</span><br/>
      <strong>Risk Score:</strong> ${data.risk_score}%
    </div>

    <div class="box">
      <h3>VirusTotal Statistics</h3>
      <ul>
        <li>Malicious: ${data.stats.malicious}</li>
        <li>Suspicious: ${data.stats.suspicious}</li>
        <li>Harmless: ${data.stats.harmless}</li>
        <li>Undetected: ${data.stats.undetected}</li>
      </ul>
    </div>

    <div class="box">
      <h3>AI Security Analysis</h3>
      <p>${aiText.replace(/\n/g, "<br/>")}</p>
    </div>

  </body>
  </html>
  `;

  return new Promise((resolve, reject) => {
    pdf.create(html).toFile(outputPath, (err, res) => {
      if (err) reject(err);
      else resolve(res);
    });
  });
}

module.exports = { generatePDFReport };
