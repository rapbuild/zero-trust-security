require("dotenv").config();

const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const db = require("../database/db");

const app = express();

app.use(express.json());

const PORT = Number(process.env.GATEWAY_PORT || 3000);
const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
const GATEWAY_SECRET = process.env.GATEWAY_SECRET;

const NILAI_URL = `http://127.0.0.1:${process.env.NILAI_PORT || 3001}`;
const TRANSKRIP_URL = `http://127.0.0.1:${process.env.TRANSKRIP_PORT || 3002}`;

if (!ACCESS_SECRET || !GATEWAY_SECRET) {
  throw new Error("JWT_ACCESS_SECRET dan GATEWAY_SECRET wajib diatur di .env");
}

// =====================================================
// HELPER
// =====================================================

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function createAccessToken(payload) {
  return jwt.sign(payload, ACCESS_SECRET, { expiresIn: "10m" });
}

function createRefreshToken() {
  return crypto.randomBytes(48).toString("hex");
}

function withinAccessHours() {
  const hour = new Date().getHours();
  return hour >= 7 && hour < 21;
}

async function audit(req, decision, reason, identity = null) {
  try {
    await db.query(
      `INSERT INTO audit_logs
       (subject_type, subject_id, method, endpoint, device_id,
        decision, reason, ip_address)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        identity?.role === "service"
          ? "service"
          : identity
            ? "user"
            : "anonymous",
        identity?.sub || null,
        req.method,
        req.originalUrl,
        req.headers["x-device-id"] || null,
        decision,
        reason,
        req.ip || null,
      ]
    );
  } catch (error) {
    console.error("Audit log gagal:", error.message);
  }
}

async function deny(req, res, status, reason, identity = null) {
  await audit(req, "deny", reason, identity);
  return res.status(status).json({ error: reason });
}

async function allow(req, identity, reason = "Policy diizinkan") {
  await audit(req, "allow", reason, identity);
}

// =====================================================
// AUTHENTICATION MIDDLEWARE
// =====================================================

async function authenticate(req, res, next) {
  const authHeader = req.headers.authorization || "";

  if (!authHeader.startsWith("Bearer ")) {
    return deny(req, res, 401, "Bearer token tidak ditemukan");
  }

  const token = authHeader.substring(7);

  try {
    const identity = jwt.verify(token, ACCESS_SECRET);

    // Service token tidak menggunakan device mahasiswa/dosen.
    if (identity.role === "service") {
      req.identity = identity;
      return next();
    }

    const deviceId = req.headers["x-device-id"];

    if (!deviceId) {
      return deny(
        req,
        res,
        403,
        "Header X-Device-ID wajib dikirim",
        identity
      );
    }

    const [devices] = await db.query(
      `SELECT d.id
       FROM devices d
       JOIN users u ON u.id = d.user_id
       WHERE d.user_id = ?
         AND d.device_id = ?
         AND d.is_active = 1
         AND u.is_active = 1
       LIMIT 1`,
      [identity.sub, deviceId]
    );

    if (devices.length === 0) {
      return deny(
        req,
        res,
        403,
        "Device tidak terdaftar atau tidak aktif",
        identity
      );
    }

    req.identity = identity;
    next();
  } catch (error) {
    return deny(req, res, 401, "Token tidak valid atau kedaluwarsa");
  }
}

// =====================================================
// AUTH: LOGIN
// =====================================================

app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const deviceId = req.headers["x-device-id"];

    if (!email || !password || !deviceId) {
      return deny(
        req,
        res,
        400,
        "Email, password, dan X-Device-ID wajib diisi"
      );
    }

    const [users] = await db.query(
      `SELECT id, nim, name, email, password_hash, role, is_active
       FROM users
       WHERE email = ?
       LIMIT 1`,
      [email]
    );

    if (users.length === 0) {
      return deny(req, res, 401, "Email atau password salah");
    }

    const user = users[0];

    if (!user.is_active) {
      return deny(req, res, 403, "Akun tidak aktif", {
        sub: user.id,
        role: user.role,
      });
    }

    const passwordValid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordValid) {
      return deny(req, res, 401, "Email atau password salah", {
        sub: user.id,
        role: user.role,
      });
    }

    const [devices] = await db.query(
      `SELECT id FROM devices
       WHERE user_id = ?
         AND device_id = ?
         AND is_active = 1
       LIMIT 1`,
      [user.id, deviceId]
    );

    if (devices.length === 0) {
      return deny(
        req,
        res,
        403,
        "Device belum terdaftar untuk akun ini",
        { sub: user.id, role: user.role }
      );
    }

    const identity = {
      sub: user.id,
      role: user.role,
      nim: user.nim,
      email: user.email,
    };

    const accessToken = createAccessToken(identity);
    const refreshToken = createRefreshToken();

    await db.query(
      `INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
       VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 1 DAY))`,
      [user.id, hashToken(refreshToken)]
    );

    await allow(req, identity, "Login berhasil");

    res.json({
      message: "Login berhasil",
      accessToken,
      refreshToken,
      expiresIn: "10 menit",
      user: {
        id: user.id,
        nim: user.nim,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Terjadi kesalahan pada server" });
  }
});

// =====================================================
// AUTH: REFRESH TOKEN
// =====================================================

app.post("/auth/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const deviceId = req.headers["x-device-id"];

    if (!refreshToken || !deviceId) {
      return deny(
        req,
        res,
        400,
        "Refresh token dan X-Device-ID wajib diisi"
      );
    }

    const [tokens] = await db.query(
      `SELECT rt.id, rt.user_id, u.nim, u.email, u.role, u.is_active
       FROM refresh_tokens rt
       JOIN users u ON u.id = rt.user_id
       WHERE rt.token_hash = ?
         AND rt.revoked_at IS NULL
         AND rt.expires_at > NOW()
       LIMIT 1`,
      [hashToken(refreshToken)]
    );

    if (tokens.length === 0) {
      return deny(
        req,
        res,
        401,
        "Refresh token tidak valid, kedaluwarsa, atau sudah dicabut"
      );
    }

    const tokenData = tokens[0];

    if (!tokenData.is_active) {
      return deny(req, res, 403, "Akun tidak aktif");
    }

    const [devices] = await db.query(
      `SELECT id FROM devices
       WHERE user_id = ?
         AND device_id = ?
         AND is_active = 1
       LIMIT 1`,
      [tokenData.user_id, deviceId]
    );

    if (devices.length === 0) {
      return deny(req, res, 403, "Device tidak terdaftar");
    }

    // Cabut refresh token lama agar tidak dapat digunakan kembali.
    await db.query(
      `UPDATE refresh_tokens
       SET revoked_at = NOW()
       WHERE id = ?`,
      [tokenData.id]
    );

    const identity = {
      sub: tokenData.user_id,
      role: tokenData.role,
      nim: tokenData.nim,
      email: tokenData.email,
    };

    const newAccessToken = createAccessToken(identity);
    const newRefreshToken = createRefreshToken();

    await db.query(
      `INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
       VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 1 DAY))`,
      [tokenData.user_id, hashToken(newRefreshToken)]
    );

    await allow(req, identity, "Refresh token berhasil digunakan");

    res.json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      expiresIn: "10 menit",
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Terjadi kesalahan pada server" });
  }
});

// =====================================================
// AUTH: LOGOUT
// =====================================================

app.post("/auth/logout", async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return deny(req, res, 400, "Refresh token wajib diisi");
    }

    const [result] = await db.query(
      `UPDATE refresh_tokens
       SET revoked_at = NOW()
       WHERE token_hash = ?
         AND revoked_at IS NULL`,
      [hashToken(refreshToken)]
    );

    if (result.affectedRows === 0) {
      return deny(
        req,
        res,
        401,
        "Refresh token tidak valid atau sudah dicabut"
      );
    }

    await audit(req, "allow", "Logout berhasil");
    res.json({ message: "Logout berhasil. Refresh token telah dicabut." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Terjadi kesalahan pada server" });
  }
});

// =====================================================
// AUTH: SERVICE TOKEN
// =====================================================

app.post("/auth/service", async (req, res) => {
  try {
    const { clientId, clientSecret } = req.body;

    if (!clientId || !clientSecret) {
      return deny(req, res, 400, "Client ID dan secret wajib diisi");
    }

    const [clients] = await db.query(
      `SELECT client_id, client_secret_hash, service_name, is_active
       FROM service_clients
       WHERE client_id = ?
       LIMIT 1`,
      [clientId]
    );

    if (clients.length === 0 || !clients[0].is_active) {
      return deny(req, res, 401, "Service client tidak valid");
    }

    const client = clients[0];

    const validSecret = await bcrypt.compare(
      clientSecret,
      client.client_secret_hash
    );

    if (!validSecret) {
      return deny(req, res, 401, "Service client tidak valid");
    }

    const serviceIdentity = {
      sub: client.client_id,
      role: "service",
      service: client.service_name,
    };

    const serviceToken = jwt.sign(
      serviceIdentity,
      ACCESS_SECRET,
      { expiresIn: "5m" }
    );

    await allow(req, serviceIdentity, "Service token diterbitkan");

    res.json({
      accessToken: serviceToken,
      tokenType: "Bearer",
      expiresIn: "5 menit",
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Terjadi kesalahan pada server" });
  }
});

// =====================================================
// PROXY KE MICROSERVICE
// =====================================================

async function proxy(req, res, targetUrl) {
  try {
    const headers = {
      "X-Gateway-Secret": GATEWAY_SECRET,
      "Content-Type": "application/json",
    };

    if (req.headers.authorization) {
      headers.Authorization = req.headers.authorization;
    }

    const options = {
      method: req.method,
      headers,
    };

    if (!["GET", "HEAD"].includes(req.method)) {
      options.body = JSON.stringify(req.body || {});
    }

    const response = await fetch(targetUrl, options);
    const responseText = await response.text();

    res.status(response.status);

    if (responseText) {
      res.type("application/json").send(responseText);
    } else {
      res.end();
    }
  } catch (error) {
    console.error("Proxy error:", error.message);
    res.status(502).json({
      error: "Microservice tidak dapat dihubungi",
    });
  }
}

// =====================================================
// POLICY: GET /nilai
// =====================================================

app.get("/nilai", authenticate, async (req, res) => {
  try {
    const identity = req.identity;

    if (!["student", "lecturer"].includes(identity.role)) {
      return deny(
        req,
        res,
        403,
        "Hanya mahasiswa dan dosen yang dapat melihat nilai",
        identity
      );
    }

    await allow(req, identity, "Role diizinkan melihat nilai");
    return proxy(req, res, `${NILAI_URL}/nilai`);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Terjadi kesalahan pada server" });
  }
});

// =====================================================
// POLICY: GET /nilai/:id
// =====================================================

app.get("/nilai/:id", authenticate, async (req, res) => {
  try {
    const identity = req.identity;

    if (!["student", "lecturer"].includes(identity.role)) {
      return deny(req, res, 403, "Role tidak diizinkan", identity);
    }

    const [grades] = await db.query(
      `SELECT g.id, g.student_id, c.lecturer_id
       FROM grades g
       JOIN classes c ON c.id = g.class_id
       WHERE g.id = ?
       LIMIT 1`,
      [req.params.id]
    );

    if (grades.length === 0) {
      return deny(req, res, 404, "Data nilai tidak ditemukan", identity);
    }

    const grade = grades[0];

    if (
      identity.role === "student" &&
      Number(grade.student_id) !== Number(identity.sub)
    ) {
      return deny(req, res, 403, "Mahasiswa hanya boleh melihat nilainya sendiri", identity);
    }

    if (
      identity.role === "lecturer" &&
      Number(grade.lecturer_id) !== Number(identity.sub)
    ) {
      return deny(req, res, 403, "Dosen hanya boleh melihat kelas yang dia ampu", identity);
    }

    await allow(req, identity, "Akses detail nilai diizinkan");
    return proxy(req, res, `${NILAI_URL}/nilai/${req.params.id}`);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Terjadi kesalahan pada server" });
  }
});

// =====================================================
// POLICY: PUT /nilai/:id
// =====================================================

app.put("/nilai/:id", authenticate, async (req, res) => {
  try {
    const identity = req.identity;

    if (identity.role !== "lecturer") {
      return deny(req, res, 403, "Hanya dosen yang boleh mengubah nilai", identity);
    }

    if (!withinAccessHours()) {
      return deny(req, res, 403, "Perubahan nilai hanya diizinkan pukul 07.00-21.00", identity);
    }

    const [grades] = await db.query(
      `SELECT g.id, g.is_final, c.lecturer_id
       FROM grades g
       JOIN classes c ON c.id = g.class_id
       WHERE g.id = ?
       LIMIT 1`,
      [req.params.id]
    );

    if (grades.length === 0) {
      return deny(req, res, 404, "Data nilai tidak ditemukan", identity);
    }

    if (Number(grades[0].lecturer_id) !== Number(identity.sub)) {
      return deny(req, res, 403, "Dosen tidak mengampu kelas ini", identity);
    }

    if (grades[0].is_final) {
      return deny(req, res, 403, "Nilai sudah final dan tidak dapat diubah", identity);
    }

    await allow(req, identity, "Policy perubahan nilai diizinkan");
    return proxy(req, res, `${NILAI_URL}/nilai/${req.params.id}`);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Terjadi kesalahan pada server" });
  }
});

// =====================================================
// POLICY: POST /kelas/:id/finalisasi
// =====================================================

app.post("/kelas/:id/finalisasi", authenticate, async (req, res) => {
  try {
    const identity = req.identity;

    if (identity.role !== "lecturer") {
      return deny(req, res, 403, "Hanya dosen yang boleh finalisasi nilai", identity);
    }

    if (!withinAccessHours()) {
      return deny(req, res, 403, "Finalisasi hanya diizinkan pukul 07.00-21.00", identity);
    }

    const [classes] = await db.query(
      `SELECT id, lecturer_id
       FROM classes
       WHERE id = ?
       LIMIT 1`,
      [req.params.id]
    );

    if (classes.length === 0) {
      return deny(req, res, 404, "Kelas tidak ditemukan", identity);
    }

    if (Number(classes[0].lecturer_id) !== Number(identity.sub)) {
      return deny(req, res, 403, "Dosen tidak mengampu kelas ini", identity);
    }

    await allow(req, identity, "Policy finalisasi nilai diizinkan");
    return proxy(
      req,
      res,
      `${NILAI_URL}/kelas/${req.params.id}/finalisasi`
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Terjadi kesalahan pada server" });
  }
});

// =====================================================
// POLICY: GET /transkrip/:nim
// =====================================================

app.get("/transkrip/:nim", authenticate, async (req, res) => {
  try {
    const identity = req.identity;

    if (!["student", "admin"].includes(identity.role)) {
      return deny(req, res, 403, "Role tidak diizinkan melihat transkrip", identity);
    }

    if (identity.role === "student") {
      const [users] = await db.query(
        "SELECT nim FROM users WHERE id = ? LIMIT 1",
        [identity.sub]
      );

      if (
        users.length === 0 ||
        String(users[0].nim) !== String(req.params.nim)
      ) {
        return deny(req, res, 403, "Mahasiswa hanya boleh melihat transkrip sendiri", identity);
      }
    }

    await allow(req, identity, "Akses transkrip diizinkan");
    return proxy(
      req,
      res,
      `${TRANSKRIP_URL}/transkrip/${encodeURIComponent(req.params.nim)}`
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Terjadi kesalahan pada server" });
  }
});

// =====================================================
// POLICY: POST /transkrip/sinkron
// Hanya Service Nilai dengan service token.
// =====================================================

app.post("/transkrip/sinkron", authenticate, async (req, res) => {
  const identity = req.identity;

  if (
    identity.role !== "service" ||
    identity.sub !== process.env.SERVICE_CLIENT_ID
  ) {
    return deny(
      req,
      res,
      403,
      "Endpoint sinkronisasi hanya untuk Service Nilai",
      identity
    );
  }

  await allow(req, identity, "Service Nilai diizinkan sinkronisasi transkrip");

  return proxy(req, res, `${TRANSKRIP_URL}/transkrip/sinkron`);
});

// =====================================================
// HEALTH CHECK
// =====================================================

app.get("/", (req, res) => {
  res.json({
    service: "Zero Trust API Gateway",
    status: "running",
    port: PORT,
  });
});

// =====================================================
// SERVER
// =====================================================

app.listen(PORT, "127.0.0.1", () => {
  console.log(`API Gateway berjalan di http://127.0.0.1:${PORT}`);
});
