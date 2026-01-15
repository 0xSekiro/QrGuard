const dns = require("dns").promises;
const fetch = require("node-fetch");
const validator = require("validator");
const tls = require("tls");



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
    sslValid: false
  };

  // 1️⃣ Insecure HTTP
  if (url.startsWith("http://")) {
    result.score += 10;
    result.flags.push("Insecure URL (HTTP instead of HTTPS)");
  }

  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    result.score += 10;
    result.flags.push("Invalid URL format");
    return result;
  }

  const domain = parsed.hostname;

  // 2️⃣ Shortener

  const SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"
  ];

  if (SHORTENERS.includes(domain)) {
    result.score += 10;
    result.flags.push("URL shortener detected");
  }

  // 3️⃣ Raw IP
  if (validator.isIP(domain)) {
    result.score += 10;
    result.flags.push("Raw IP address used in URL"); 
  }

  // 4️⃣ DNS lookup
  try {
    const dnsResult = await dns.lookup(domain);
    result.ip = dnsResult.address;
  } catch {
    result.score += 10;
    result.flags.push("DNS lookup failed");
  }

  // 5️⃣ Phishing keywords
  if (/\b(login|verify|secure|update|confirm|free|reward)\b/i.test(parsed.pathname)) {
    result.score += 10;
    result.flags.push("Phishing keyword detected");
  }

  // 6️⃣ Dangerous extensions
  if (/\.(exe|apk|ipa|zip|rar|bat)$/i.test(parsed.pathname)) {
    result.score += 10;
    result.flags.push("Dangerous file extension");
  }

  // 7️⃣ Redirects
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
      } else break;
    }

    if (redirectCount > 0) {
      result.redirects = redirectCount;
      result.score += 10;
      result.flags.push(`Redirect chain detected (${redirectCount})`);
    }
  } catch {
    result.score += 10;
    result.flags.push("Connection failed or blocked");
  }

  // 8️⃣ XSS
  if (XSS_PAYLOADS.test(url)) {
    result.score += 10;
    result.flags.push("Potential XSS payload");
  }

  // 9️⃣ SQLi
  if (SQLI_PAYLOADS.test(url)) {
    result.score += 10;
    result.flags.push("Potential SQL Injection payload");
  }

  result.status = result.score === 0 ? "safe" : "malicious";
  return result;


  // 10 URL Length 

  if (url.length > 150) {
    result.score += 10;
    return { safe: false, reason: "Unusually long URL" };
  }
}

module.exports = { scanURL };
