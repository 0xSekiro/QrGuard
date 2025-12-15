const axios = require("axios");

const HF_API_KEY = process.env.HF_API_KEY;
const MODEL = "mistralai/Mistral-7B-Instruct-v0.2";

async function generateAIReport(data) {
  const prompt = `
You are a cybersecurity analyst.
Generate a professional security report for the following URL scan
Easy for users.

URL: ${data.url}

VirusTotal statistics:
Malicious: ${data.stats.malicious}
Suspicious: ${data.stats.suspicious}
Harmless: ${data.stats.harmless}
Undetected: ${data.stats.undetected}

Risk score: ${data.risk_score}
Verdict: ${data.verdict}

Write:
- Executive summary
- Risk explanation
- Recommendation to user
`;

  const response = await axios.post(
    `https://api-inference.huggingface.co/models/${MODEL}`,
    { inputs: prompt },
    {
      headers: {
        Authorization: `Bearer ${HF_API_KEY}`,
        "Content-Type": "application/json"
      }
    }
  );

  return response.data[0].generated_text;
}

module.exports = { generateAIReport };
