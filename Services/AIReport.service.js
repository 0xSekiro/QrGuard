const { GoogleGenerativeAI } = require("@google/generative-ai");

/**
 * Generates a user-friendly security explanation using Google Gemini.
 * @param {Object} scanResults - The full scan results (QR Guard + VirusTotal)
 * @returns {Promise<string>} - The AI-generated explanation
 */
async function generateAIExplanation(scanResults) {
    try {
        const apiKey = process.env.GEMINI_API_KEY;
        if (!apiKey) {
            console.warn("GEMINI_API_KEY is missing. AI explanation skipped.");
            return null;
        }

        const genAI = new GoogleGenerativeAI(apiKey);
        const model = genAI.getGenerativeModel({ model: "gemini-2.0-flash" });

        // Prepare a summary of the risks to send to the AI
        const riskSummary = {
            risk_score: scanResults.virustotal.risk_score,
            verdict: scanResults.virustotal.verdict,
            active_flags: scanResults.qr_guard.flags || [],
            vt_malicious: scanResults.virustotal.full_report.attributes.stats.malicious
        };

        const prompt = `
      Act as a friendly cybersecurity expert explaining to a non-technical user.
      Analyze this URL scan result: ${JSON.stringify(riskSummary)}.
      
      Write a short paragraph (max 3 sentences) in simple English explaining WHY this link is dangerous/suspicious and WHAT risks it poses (e.g. stealing passwords, malware).
      Do NOT mention technical terms like "JSON" or "API". Focus on the user's safety.
      If the link is Safe, just say it looks good but to be careful.
    `;

        const result = await model.generateContent(prompt);
        const response = await result.response;
        const text = response.text();

        return text;
    } catch (error) {
        console.error("AI Generation Error:", error.message);

        // ⚠️ FALLBACK: Simulated AI Response (if API fails)
        // This ensures the user always gets a helpful explanation even if the key/network fails.
        const risk = scanResults.virustotal.risk_score > 50 ? "high risk" : "suspicious";
        const flags = scanResults.qr_guard.flags ? scanResults.qr_guard.flags.join(", ") : "technical anomalies";

        return `(Simulated AI) As a security precaution, I advise caution. This link has been flagged as ${risk}. It exhibits ${flags}, which often indicate an attempt to trick users or distribute harmful software. Please do not enter sensitive information.`;
    }
}

module.exports = { generateAIExplanation };
