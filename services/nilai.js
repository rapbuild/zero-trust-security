require("dotenv").config();

const express = require("express");
const db = require("../database/db");
const { verifyJwt, requireGateway } = require("../lib/security");

const app = express();
app.use(express.json());
app.use(requireGateway);
app.use(verifyJwt);

function withinAccessHours() {
  const hour = new Date().getHours();
  return hour >= 7 && hour < 21;
}

async function getGrade(id) {
  const [rows] = await db.execute(
    `SELECT g.*, c.lecturer_id
     FROM grades g
     JOIN classes c ON c.id = g.class_id
     WHERE g.id = ?`,
    [id]
  );
  return rows[0];
}

// Mahasiswa hanya melihat nilai sendiri.
// Dosen hanya melihat nilai kelas yang diajarnya.
app.get("/nilai", async (req, res) => {
  try {
    const identity = req.identity;
    let sql;
    let params;

    if (identity.role === "student") {
      sql = `SELECT g.id, c.class_code, c.class_name, g.score, g.is_final
             FROM grades g
             JOIN classes c ON c.id = g.class_id
             WHERE g.student_id = ?`;
      params = [identity.sub];
    } else if (identity.role === "lecturer") {
      sql = `SELECT g.id, c.class_code, c.class_name, u.nim,
                    u.name AS student_name, g.score, g.is_final
             FROM grades g
             JOIN classes c ON c.id = g.class_id
             JOIN users u ON u.id = g.student_id
             WHERE c.lecturer_id = ?`;
      params = [identity.sub];
    } else {
      return res.status(403).json({ error: "Role tidak diizinkan" });
    }

    const [rows] = await db.execute(sql, params);
    res.json(rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Gagal mengambil nilai" });
  }
});

// Detail nilai hanya untuk mahasiswa pemiliknya atau dosen pengampu.
app.get("/nilai/:id", async (req, res) => {
  try {
    const grade = await getGrade(req.params.id);

    if (!grade) {
      return res.status(404).json({ error: "Nilai tidak ditemukan" });
    }

    const identity = req.identity;
    const allowed =
      (identity.role === "student" &&
        Number(grade.student_id) === Number(identity.sub)) ||
      (identity.role === "lecturer" &&
        Number(grade.lecturer_id) === Number(identity.sub));

    if (!allowed) {
      return res.status(403).json({ error: "Tidak berhak melihat nilai ini" });
    }

    res.json(grade);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Gagal mengambil nilai" });
  }
});

// Hanya dosen pengampu, nilai belum final, dan dalam jam akses.
app.put("/nilai/:id", async (req, res) => {
  try {
    const identity = req.identity;

    if (identity.role !== "lecturer") {
      return res.status(403).json({ error: "Hanya dosen yang dapat mengubah nilai" });
    }

    if (!withinAccessHours()) {
      return res.status(403).json({ error: "Di luar jam akses 07.00–21.00" });
    }

    const grade = await getGrade(req.params.id);

    if (!grade) {
      return res.status(404).json({ error: "Nilai tidak ditemukan" });
    }

    if (Number(grade.lecturer_id) !== Number(identity.sub)) {
      return res.status(403).json({ error: "Bukan dosen pengampu kelas ini" });
    }

    if (grade.is_final) {
      return res.status(409).json({ error: "Nilai sudah difinalisasi" });
    }

    const score = Number(req.body.score);

    if (!Number.isFinite(score) || score < 0 || score > 100) {
      return res.status(400).json({ error: "Nilai harus antara 0 dan 100" });
    }

    await db.execute(
      `UPDATE grades SET score = ?, updated_by = ?
       WHERE id = ? AND is_final = FALSE`,
      [score, identity.sub, req.params.id]
    );

    res.json({ message: "Nilai berhasil diperbarui" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Gagal mengubah nilai" });
  }
});

// Finalisasi kelas dan sinkronisasi transkrip melalui gateway.
app.post("/kelas/:id/finalisasi", async (req, res) => {
  const conn = await db.getConnection();

  try {
    const identity = req.identity;

    if (identity.role !== "lecturer") {
      return res.status(403).json({ error: "Hanya dosen yang dapat finalisasi" });
    }

    if (!withinAccessHours()) {
      return res.status(403).json({ error: "Di luar jam akses 07.00–21.00" });
    }

    const [classes] = await conn.execute(
      "SELECT id FROM classes WHERE id = ? AND lecturer_id = ?",
      [req.params.id, identity.sub]
    );

    if (!classes.length) {
      return res.status(403).json({ error: "Bukan dosen pengampu kelas ini" });
    }

    await conn.beginTransaction();

    const [result] = await conn.execute(
      `UPDATE grades
       SET is_final = TRUE, finalized_at = NOW(), updated_by = ?
       WHERE class_id = ? AND is_final = FALSE AND score IS NOT NULL`,
      [identity.sub, req.params.id]
    );

    await conn.commit();

    // Dapatkan service token khusus untuk sinkronisasi transkrip.
    const authResponse = await fetch(
      `http://127.0.0.1:${process.env.GATEWAY_PORT || 3000}/auth/service`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          clientId: process.env.SERVICE_CLIENT_ID,
          clientSecret: process.env.SERVICE_CLIENT_SECRET,
        }),
      }
    );

    if (!authResponse.ok) {
      return res.status(502).json({
        message: "Nilai difinalisasi, tetapi service token gagal diperoleh",
        finalized: result.affectedRows,
      });
    }

    const authData = await authResponse.json();

    const syncResponse = await fetch(
      `http://127.0.0.1:${process.env.GATEWAY_PORT || 3000}/transkrip/sinkron`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${authData.accessToken}`,
        },
        body: JSON.stringify({ classId: Number(req.params.id) }),
      }
    );

    if (!syncResponse.ok) {
      const errorDetail = await syncResponse.text();

      console.error("Sinkronisasi gagal:", syncResponse.status, errorDetail);

      return res.status(502).json({
        message: "Nilai difinalisasi, tetapi sinkronisasi transkrip gagal",
        finalized: result.affectedRows,
        syncStatus: syncResponse.status,
        syncError: errorDetail,
     });
  }

    res.json({
      message: "Kelas difinalisasi dan transkrip disinkronkan",
      finalized: result.affectedRows,
    });
  } catch (error) {
    await conn.rollback().catch(() => {});
    console.error(error);
    res.status(500).json({ error: "Gagal memfinalisasi kelas" });
  } finally {
    conn.release();
  }
});

app.listen(Number(process.env.NILAI_PORT || 3001), "127.0.0.1", () => {
  console.log("Service Nilai berjalan pada port 3001");
});
