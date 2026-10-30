
require("dotenv").config();

const express = require("express");
const db = require("../database/db");
const { verifyJwt, requireGateway } = require("../lib/security");

const app = express();

app.use(express.json());
app.use(requireGateway);
app.use(verifyJwt);

// ==========================================
// GET TRANSKRIP MAHASISWA
// ==========================================
app.get("/transkrip/:nim", async (req, res) => {
  try {
    const identity = req.identity;

    if (!["student", "admin"].includes(identity.role)) {
      return res.status(403).json({
        error: "Role tidak diizinkan",
      });
    }

    const [users] = await db.execute(
      "SELECT id, nim, name FROM users WHERE nim = ?",
      [req.params.nim]
    );

    if (!users.length) {
      return res.status(404).json({
        error: "Mahasiswa tidak ditemukan",
      });
    }

    const student = users[0];

    if (
      identity.role === "student" &&
      String(identity.sub) !== String(student.id)
    ) {
      return res.status(403).json({
        error: "Mahasiswa hanya boleh melihat transkrip sendiri",
      });
    }

    const [rows] = await db.execute(
      `SELECT
        tr.id,
        tr.grade_id,
        c.class_code,
        c.class_name,
        tr.score,
        tr.synced_at
      FROM transcript_records tr
      JOIN classes c ON c.id = tr.class_id
      WHERE tr.student_id = ?
      ORDER BY c.class_code`,
      [student.id]
    );

    return res.json({
      nim: student.nim,
      name: student.name,
      records: rows,
    });
  } catch (error) {
    console.error("Gagal mengambil transkrip:", error);
    return res.status(500).json({
      error: "Gagal mengambil transkrip",
    });
  }
});

// ==========================================
// POST SINKRONISASI TRANSKRIP
// Hanya Service Nilai
// ==========================================
app.post("/transkrip/sinkron", async (req, res) => {
  try {
    const identity = req.identity;

    // Identitas service token berasal dari Gateway:
    // sub, role, service
    if (
      identity.role !== "service" ||
      identity.sub !== process.env.SERVICE_CLIENT_ID ||
      identity.service !== "Service Nilai"
    ) {
      return res.status(403).json({
        error: "Hanya Service Nilai yang diizinkan",
      });
    }

    const classId = Number(req.body?.classId);

    if (!Number.isInteger(classId) || classId <= 0) {
      return res.status(400).json({
        error: "classId tidak valid",
      });
    }

    const conn = await db.getConnection();

    try {
      await conn.beginTransaction();

      const [result] = await conn.execute(
        `INSERT INTO transcript_records
          (grade_id, student_id, class_id, score, synced_at)
        SELECT
          id, student_id, class_id, score, NOW()
        FROM grades
        WHERE class_id = ?
          AND is_final = TRUE
          AND score IS NOT NULL
        ON DUPLICATE KEY UPDATE
          score = VALUES(score),
          synced_at = NOW()`,
        [classId]
      );

      await conn.commit();

      return res.json({
        message: "Sinkronisasi transkrip berhasil",
        classId,
        affectedRows: result.affectedRows,
      });
    } catch (error) {
      await conn.rollback();
      throw error;
    } finally {
      conn.release();
    }
  } catch (error) {
    console.error("Gagal sinkronisasi transkrip:", error);
    return res.status(500).json({
      error: "Gagal sinkronisasi transkrip",
    });
  }
});

// ==========================================
// SERVER
// ==========================================
const PORT = Number(process.env.TRANSKRIP_PORT || 3002);

app.listen(PORT, "127.0.0.1", () => {
  console.log(`Service Transkrip berjalan pada port ${PORT}`);
});

