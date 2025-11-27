import dns from "dns/promises";
import fetch from "node-fetch";
import validator from "validator";

const SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"
];

export async function scanURL(url) {
  const result = {
    url,
    ip: null,
    score: 0,
    flags: [],
    redirects: 0
  };

  // ✅ 1. Validate URL
  if (!validator.isURL(url, { require_protocol: true })) {
    result.score += 6;
    result.flags.push("Invalid URL format");
    return result;
  }

  const parsed = new URL(url);
  const domain = parsed.hostname;

  // ✅ 2. Shortener Detection
  if (SHORTENERS.includes(domain)) {
    result.score += 2;
    result.flags.push("URL shortener detected");
  }

  // ✅ 3. Raw IP URL Detection
  if (validator.isIP(domain)) {
    result.score += 4;
    result.flags.push("Raw IP address used in URL");
  }

  // ✅ 4. DNS → IP Resolution
  try {
    const dnsResult = await dns.lookup(domain);
    result.ip = dnsResult.address;
  } catch {
    result.score += 3;
    result.flags.push("DNS lookup failed");
  }

  // ✅ 5. Phishing Keywords
  if (/\b(login|verify|secure|update|confirm|free|reward)\b/i.test(parsed.pathname)) {
    result.score += 2;
    result.flags.push("Phishing keyword detected in path");
  }

  // ✅ 6. Dangerous File Extensions
  if (/\.(exe|apk|ipa|zip|rar|bat)$/i.test(parsed.pathname)) {
    result.score += 4;
    result.flags.push("Dangerous file extension detected");
  }

  // ✅ 7. REAL Redirect Chain Detection
  try {
    let currentURL = url;
    let redirectCount = 0;

    for (let i = 0; i < 5; i++) {
      const res = await fetch(currentURL, {
        redirect: "manual",
        timeout: 8000
      });

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

  return result;
}
