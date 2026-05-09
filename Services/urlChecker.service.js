const dns = require("dns").promises;
const fetch = require("node-fetch");
const validator = require("validator");

const XSS_PAYLOADS = /(<script>|onerror=|onload=|javascript:|"><|<\/script>)/i;
const SQLI_PAYLOADS = /('|;|--|\/\*|\bselect\b|\bdrop\b|\binsert\b|\bunion\b)/i;

async function scanURL(input) {
  // 🔒 VALIDATION
  if (!input || typeof input !== "string") {
    throw new Error("scanURL expects a URL string");
  }

  // 🔧 NORMALIZATION
  let url = input.trim();
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "http://" + url;
  }

  const result = {
    url,
    ip: null,
    score: 0,
    flags: [],
    redirects: 0,
    status: "safe",
  };

  let parsed;

  try {
    parsed = new URL(url);
  } catch {
    return {
      ...result,
      score: 10,
      status: "malicious",
      flags: ["Invalid URL format"],
    };
  }

  const domain = parsed.hostname;

  // 1️⃣ HTTP check
  if (url.startsWith("http://")) {
    result.score += 10;
    result.flags.push("Insecure HTTP connection");
  }

  // 2️⃣ URL shorteners
  const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"];
  if (SHORTENERS.includes(domain)) {
    result.score += 10;
    result.flags.push("URL shortener detected");
  }

  // 3️⃣ Raw IP check
  if (validator.isIP(domain)) {
    result.score += 10;
    result.flags.push("Raw IP address used");
  }

  // 4️⃣ DNS lookup
  try {
    const dnsResult = await dns.lookup(domain);
    result.ip = dnsResult.address;
  } catch {
    result.score += 10;
    result.flags.push("DNS lookup failed");
  }

  // 5️⃣ phishing keywords
  if (/\b(login|verify|secure|update|confirm|free|reward)\b/i.test(parsed.pathname)) {
    result.score += 10;
    result.flags.push("Phishing keywords detected");
  }

  // 6️⃣ dangerous file extensions
  if (/\.(exe|apk|ipa|zip|rar|bat)$/i.test(parsed.pathname)) {
    result.score += 10;
    result.flags.push("Dangerous file extension");
  }

  // 7️⃣ redirect detection
  try {
    let currentURL = url;
    let redirectCount = 0;

    for (let i = 0; i < 5; i++) {
      const res = await fetch(currentURL, { redirect: "manual" });

      if (res.status >= 300 && res.status < 400) {
        const location = res.headers.get("location");
        if (!location) break;

        redirectCount++;
        currentURL = location.startsWith("http")
          ? location
          : new URL(location, currentURL).href;
      } else {
        break;
      }
    }

    if (redirectCount > 0) {
      result.redirects = redirectCount;
      result.score += 10;
      result.flags.push(`Redirect chain detected (${redirectCount})`);
    }
  } catch {
    result.score += 10;
    result.flags.push("Connection failed");
  }

  // 8️⃣ XSS detection
  if (XSS_PAYLOADS.test(url)) {
    result.score += 10;
    result.flags.push("XSS pattern detected");
  }

  // 9️⃣ SQL injection detection
  if (SQLI_PAYLOADS.test(url)) {
    result.score += 10;
    result.flags.push("SQL injection pattern detected");
  }

 // 🔟 FINAL STATUS
if (result.score <= 20) {
  result.status = "safe";
} 
else if (result.score <= 40) {
  result.status = "suspicious";
} 
else {
  result.status = "malicious";
}

return result;
}

module.exports = { scanURL };