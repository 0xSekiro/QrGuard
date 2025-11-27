import { scanURL } from "../services/urlChecker.service.js";

export const check_url = async (req, res) => {
  const data = req.body;

  // ✅ SINGLE URL 
  if (data.url) {
    const result = await scanURL(data.url);
    return res.json(formatResult(result));
  }

  //  BULK
  if (Array.isArray(data)) {
    const results = [];

    for (const item of data) {
      if (!item.url) continue;
      const scan = await scanURL(item.url);
      results.push(formatResult(scan));
    }

    return res.json({
      total: results.length,
      results
    });
  }

  return res.status(400).json({
    error: "Send either { url } or [ { url }, { url } ]"
  });
};

//  Unified result formatter
function formatResult(result) {
  let status = "safe";
  if (result.score >= 7) status = "malicious";
  else if (result.score >= 3) status = "suspicious";

  return {
    url: result.url,
    ip: result.ip,
    status,
    score: result.score,
    flags: result.flags,
    redirects: result.redirects
  };
}
