const jwt = require("jsonwebtoken");

function verifyJwt(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  if (!token) {
    return res.status(401).json({ error: "Token tidak ditemukan" });
  }

  try {
    req.identity = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Token tidak valid atau kedaluwarsa" });
  }
}

function requireGateway(req, res, next) {
  if (
    !process.env.GATEWAY_SECRET ||
    req.headers["x-gateway-secret"] !== process.env.GATEWAY_SECRET
  ) {
    return res.status(403).json({ error: "Akses langsung ke service ditolak" });
  }

  next();
}

module.exports = { verifyJwt, requireGateway };
