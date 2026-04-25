
/**
 * Smart Explainer Agent (Expert System)
 * Translates technical security data into layman terms.
 * 
 * @param {Object} qrGuardResult - Result from local custom scanner
 * @param {Object} virusTotalResult - Result from VirusTotal API
 * @returns {Object} - { summary, risk_level, advice, human_readable_reasons }
 */
function explainRisk(qrGuardResult, virusTotalResult) {
    const explanations = [];
    let riskLevel = "Safe";
    let riskScore = 0;

    // --- KNOWLEDGE BASE (Dictionary) ---
    const KNOWLEDGE_BASE = {
        "Phishing keyword detected": "This link uses words often used by scammers to trick you (like 'login' or 'verify').",
        "Redirect chain detected": "This link is trying to hide where it really goes by jumping through multiple pages.",
        "Insecure URL (HTTP instead of HTTPS)": "This connection is not encrypted. Attackers could steal data you send here.",
        "URL shortener detected": "The true destination is hidden. Scammers often use this to mask dangerous links.",
        "Dangerous file extension": "This link tries to download a program (like .exe) that could damage your computer.",
        "Potential XSS payload": "This link contains code that tries to hack your web browser.",
        "Potential SQL Injection payload": "This link tries to attack the website's database.",
        "Raw IP address used in URL": "This looks like a server address, not a real website name. Genuine sites rarely use this.",
        "DNS lookup failed": "This website does not exist or is currently down."
    };

    // --- INFERENCE ENGINE ---

    // 1. Analyze VirusTotal (External Intelligence)
    const vtStats = virusTotalResult.full_report.attributes.stats;
    const maliciousCount = vtStats.malicious;
    const suspiciousCount = vtStats.suspicious;

    if (maliciousCount > 0) {
        riskScore += 50; // Major red flag
        explanations.push({
            reason: "security experts flagged it",
            explanation: `${maliciousCount} global security companies have confirmed this website is dangerous.`
        });
    } else if (suspiciousCount > 0) {
        riskScore += 20;
        explanations.push({
            reason: "it behaves suspiciously",
            explanation: "Some security vendors flagged this site as suspicious, but it's not confirmed malicious yet."
        });
    }

    // 2. Analyze Custom Flags (Local Intelligence)
    if (qrGuardResult.flags && qrGuardResult.flags.length > 0) {
        qrGuardResult.flags.forEach(flag => {
            // Clean flag string if it has dynamic parts like "(3)"
            const cleanFlag = Object.keys(KNOWLEDGE_BASE).find(k => flag.includes(k));

            if (cleanFlag) {
                explanations.push({
                    reason: flag,
                    explanation: KNOWLEDGE_BASE[cleanFlag]
                });
                riskScore += 15;
            } else {
                // Fallback for unknown flags
                explanations.push({
                    reason: "it has technical irregularities",
                    explanation: "This is a technical abnormality that suggests the link might be unsafe."
                });
                riskScore += 10;
            }
        });
    }

    // 3. Determine Human Verdict
    let summary = "";
    let advice = "";

    // Strategies to pick the "Main Reason" (General Reason)
    // We take the first explanation as the primary one because our checks are ordered by severity (VirusTotal -> Custom Flags)
    const primaryReason = explanations.length > 0 ? explanations[0].reason.toLowerCase() : null;
    const additionalIssues = explanations.length > 1;

    if (riskScore >= 40 || maliciousCount > 0) {
        riskLevel = "Dangerous";
        summary = "⛔ DO NOT OPEN THIS LINK.";
        if (primaryReason) {
            summary += ` It is flagged as dangerous because ${primaryReason}`;
            if (additionalIssues) summary += " and other security risks";
            summary += ".";
        }
        advice = "This website is confirmed to be harmful. It may steal your passwords or infect your device.";
    } else if (riskScore > 0) {
        riskLevel = "Suspicious";
        summary = "⚠️ Be careful.";
        if (primaryReason) {
            summary += ` We found that ${primaryReason}`;
            if (additionalIssues) summary += " and other irregularities";
            summary += ".";
        }
        advice = "It might be safe, but it has some warning signs. Do not enter any passwords or credit card numbers.";
    } else {
        riskLevel = "Safe";
        summary = "✅ This link looks safe.";
        advice = "We didn't find any obvious threats, but always stay alert.";
    }

    // 4. Compile Passed Checks (Conditions the URL passed successfully)
    const passedChecks = [];

    // VirusTotal Checks
    if (maliciousCount === 0) passedChecks.push("No global blacklists found this URL.");
    if (suspiciousCount === 0) passedChecks.push("No security vendors suspected this URL.");

    // Custom Checks
    const ALL_CHECKS = {
        "Phishing keyword detected": "No phishing keywords found.",
        "Redirect chain detected": "No suspicious redirect chains.",
        "Insecure URL (HTTP instead of HTTPS)": "Connection is encrypted (HTTPS).",
        "URL shortener detected": "URL is not a hidden short-link.",
        "Dangerous file extension": "No dangerous file types (exe, apk) detected.",
        "Potential XSS payload": "No browser hacking code (XSS) detected.",
        "Potential SQL Injection payload": "No database attack code (SQLi) detected.",
        "Raw IP address used in URL": "URL uses a valid domain name, not a raw IP.",
        "DNS lookup failed": "Domain exists and is reachable."
    };

    const activeFlags = qrGuardResult.flags || [];

    Object.keys(ALL_CHECKS).forEach(checkKey => {
        // If this check key is NOT in the active flags, it Passed.
        // We use .some() for partial matching because flags might have extra text
        const isFailed = activeFlags.some(flag => flag.includes(checkKey));
        if (!isFailed) {
            passedChecks.push(ALL_CHECKS[checkKey]);
        }
    });

    return {
        simple_summary: summary,
        risk_level: riskLevel,
        advice: advice,
        detailed_explanations: explanations,
        passed_checks: passedChecks // ✅ Added full details of what is safe
    };
}

module.exports = { explainRisk };
