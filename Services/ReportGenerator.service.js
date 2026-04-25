
/**
 * Generates a human-readable safety report based on scan results.
 * @param {Object} qrGuardResult - Result from local custom scanner
 * @param {Object} virusTotalResult - Result from VirusTotal API
 * @returns {Object} - { summary, reasons, risk_level }
 */
function generateSafetyReport(qrGuardResult, virusTotalResult) {
    const reports = [];
    let riskLevel = "Low";

    // 1. Analyze VirusTotal Results
    const vtStats = virusTotalResult.full_report.attributes.stats;
    const maliciousCount = vtStats.malicious;
    const suspiciousCount = vtStats.suspicious;

    if (maliciousCount > 0) {
        reports.push(`⚠️ VirusTotal detected ${maliciousCount} security vendors flagging this URL as malicious.`);
        riskLevel = "High";
    }

    if (suspiciousCount > 0) {
        reports.push(`⚠️ ${suspiciousCount} vendors marked this URL as suspicious.`);
        if (riskLevel === "Low") riskLevel = "Medium";
    }

    // 2. Analyze Custom Scanner Flags
    if (qrGuardResult.flags && qrGuardResult.flags.length > 0) {
        qrGuardResult.flags.forEach(flag => {
            reports.push(`🔸 ${flag}`); // e.g., "Phishing keyword detected"
        });

        // Escalate risk if custom flags exist
        if (riskLevel === "Low") riskLevel = "Medium";
        // If multiple flags, maybe High? Let's keep it simple for now or strictly follow score.
        if (qrGuardResult.score >= 50) riskLevel = "High";
    }

    // 3. Construct Summary
    let summary = "";
    if (riskLevel === "High") {
        summary = "⛔ This URL is dangerous. It has been flagged by multiple security providers or contains known threats.";
    } else if (riskLevel === "Medium") {
        summary = "⚠️ This URL is suspicious. Proceed with caution. It may be a phishing attempt or contain misleading content.";
    } else {
        summary = "✅ This URL appears safe. No significant threats were detected.";
    }

    return {
        summary,
        risk_level: riskLevel,
        reasons: reports
    };
}

module.exports = { generateSafetyReport };
