const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';

/**
 * helper สำหรับส่ง log ไป Log Service
 */
function logEvent(level, event, message, req, meta = {}) {
  fetch('http://log-service:3003/api/logs/internal', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      service: 'task-service',
      level,
      event,
      ip_address: req.headers['x-real-ip'] || req.ip,
      message,
      meta
    })
  }).catch(() => {}); // fire-and-forget
}

/**
 * Middleware ตรวจสอบ JWT Token
 * ถ้าผ่าน → ใส่ req.user = decoded payload
 * ถ้าไม่ผ่าน → ส่ง 401
 */
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];  // "Bearer <token>"

  if (!token) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'กรุณา Login ก่อน — ไม่พบ Token ใน Authorization header'
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {

    // เพิ่ม logEvent ตอน JWT error
    logEvent(
      'ERROR',
      'JWT_INVALID',
      'Invalid JWT token: ' + err.message,
      req,
      { error: err.message }
    );

    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Token Expired',
        message: 'Token หมดอายุ กรุณา Login ใหม่'
      });
    }

    return res.status(401).json({
      error: 'Invalid Token',
      message: 'Token ไม่ถูกต้อง'
    });
  }
}

/**
 * Middleware ตรวจสอบ Role
 */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        error: 'Forbidden',
        message: `ต้องการสิทธิ์: ${roles.join(' หรือ ')} (คุณมีสิทธิ์: ${req.user.role})`
      });
    }
    next();
  };
}

module.exports = { requireAuth, requireRole };
