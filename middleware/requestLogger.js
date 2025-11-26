const { v4: uuidv4 } = require('uuid');

function requestLogger(options = {}) {
  const {
    maxBodyLength = 1000,
    logQueries = true,
    logUserAgent = true,
  } = options;

  return (req, res, next) => {
    const id = req.headers['x-request-id'] || uuidv4();
    req.id = id;
    res.setHeader('X-Request-Id', id);

    const start = process.hrtime.bigint();

    const method = req.method;
    const url = req.originalUrl || req.url;
    const ip = req.ip || (req.connection && req.connection.remoteAddress) || 'unknown';
    const ua = logUserAgent ? (req.get && req.get('user-agent')) : undefined;

    // Prepare a safe body preview for common content types
    const contentType = (req.get && req.get('content-type')) || '';
    let bodyPreview = '<none>';
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      if (contentType.includes('application/json') || contentType.includes('application/x-www-form-urlencoded')) {
        try {
          const serialized = JSON.stringify(req.body);
          bodyPreview = serialized.length > maxBodyLength
            ? serialized.slice(0, maxBodyLength) + '...<truncated>'
            : serialized;
        } catch (e) {
          bodyPreview = '<unserializable>';
        }
      } else if (contentType.includes('multipart/form-data')) {
        bodyPreview = '<multipart/form-data>';
      }
    }

    const queryPreview = logQueries ? JSON.stringify(req.query || {}) : undefined;

    const startLineParts = [
      `--> [${id}]`,
      method,
      url,
      `from ${ip}`,
    ];
    if (logQueries) startLineParts.push(`q=${queryPreview}`);
    if (logUserAgent) startLineParts.push(`ua="${ua || ''}"`);
    if (bodyPreview) startLineParts.push(`body=${bodyPreview}`);

    // Log request start
    console.log(startLineParts.join(' '));

    res.on('finish', () => {
      const durationMs = Number(process.hrtime.bigint() - start) / 1e6;
      const length = res.get ? (res.get('content-length') || 0) : 0;
      console.log(`<-- [${id}] ${method} ${url} ${res.statusCode} ${length}b ${durationMs.toFixed(1)}ms`);
    });

    next();
  };
}

module.exports = requestLogger;
