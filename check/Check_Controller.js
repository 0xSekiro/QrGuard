import { isMalicious } from '../check/url_Checker.js';

export const check_url = (req,res,next) => {
  const { url } = req.body;

  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'Invalid input. Please provide a valid URL.' });
  }

  const result = isMalicious(url);
  return res.json({
    url,
    status: result ? 'malicious' : 'safe'
  });
};
