const dns = require("dns").promises;
const fetch = require("node-fetch");
const validator = require("validator");
const tls = require("tls");

const SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"
];

// XSS and SQL Regex
const XSS_PAYLOADS = /(<script>|onerror=|onload=|javascript:|"><|<\/script>)/i;
const SQLI_PAYLOADS = /('|;|--|\/\*|\bselect\b|\bdrop\b|\binsert\b|\bunion\b)/i;

async function scanURL(url) {
  const result = {
    url,
    ip: null,
    score: 0,
    flags: [],
    redirects: 0,
    sslValid: false
  };

  // 1. Check for HTTP (insecure)
  if (url.startsWith("http://")) {
    result.score += 6;
    result.flags.push("Insecure URL (HTTP instead of HTTPS)");
  }

  const parsed = new URL(url);
  const domain = parsed.hostname;

  // 2. Shortener Detection
  if (SHORTENERS.includes(domain)) {
    result.score += 2;
    result.flags.push("URL shortener detected");
  }

  // 3. Raw IP Detection
  if (validator.isIP(domain)) {
    result.score += 4;
    result.flags.push("Raw IP address used in URL");
  }

  // 4. DNS lookup
  try {
    const dnsResult = await dns.lookup(domain);
    result.ip = dnsResult.address;
  } catch {
    result.score += 3;
    result.flags.push("DNS lookup failed");
  }

  // 5. Phishing keywords
  if (/\b(login|verify|secure|update|confirm|free|reward)\b/i.test(parsed.pathname)) {
    result.score += 2;
    result.flags.push("Phishing keyword detected");
  }

  // 6. Dangerous extensions
  if (/\.(exe|apk|ipa|zip|rar|bat)$/i.test(parsed.pathname)) {
    result.score += 4;
    result.flags.push("Dangerous file extension");
  }

  // 7. Redirect chain detection
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
      result.score += redirectCount * 2;
      result.flags.push(`Redirect chain detected (${redirectCount})`);
    }

  } catch {
    result.score += 2;
    result.flags.push("Connection failed or blocked");
  }

  // 8. XSS
  if (XSS_PAYLOADS.test(url)) {
    result.score += 6;
    result.flags.push("Potential XSS payload");
  }

  // 9. SQLi
  if (SQLI_PAYLOADS.test(url)) {
    result.score += 6;
    result.flags.push("Potential SQL Injection payload");
  }

  return result;
}

module.exports = { scanURL };
