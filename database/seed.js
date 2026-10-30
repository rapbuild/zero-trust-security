
require("dotenv").config();
const bcrypt = require("bcrypt");
const db = require("./db");

async function main() {
  const conn = await db.getConnection();

  try {
    await conn.beginTransaction();

    // Buat akun demo dengan password yang di-hash
    const users = [
      {
        nim: null,
        name: "Administrator",
        email: "admin@zt.local",
        password: "AdminDemo_2026!",
        role: "admin",
      },
      {
        nim: null,
        name: "Dosen Informatika 1",
        email: "dosen1@zt.local",
        password: "DosenDemo_2026!",
        role: "lecturer",
      },
      {
        nim: null,
        name: "Dosen Informatika 2",
        email: "dosen2@zt.local",
        password: "DosenDemo_2026!",
        role: "lecturer",
      },
      {
        nim: "247006001",
        name: "Mahasiswa 1",
        email: "mahasiswa1@zt.local",
        password: "MhsDemo_2026!",
        role: "student",
      },
      {
        nim: "247006002",
        name: "Mahasiswa 2",
        email: "mahasiswa2@zt.local",
        password: "MhsDemo_2026!",
        role: "student",
      },
      {
        nim: "247006003",
        name: "Mahasiswa 3",
        email: "mahasiswa3@zt.local",
        password: "MhsDemo_2026!",
        role: "student",
      },
    ];

    const userIds = {};

    for (const user of users) {
      const passwordHash = await bcrypt.hash(user.password, 12);

      await conn.execute(
        `INSERT INTO users (nim, name, email, password_hash, role)
         VALUES (?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
           name = VALUES(name),
           password_hash = VALUES(password_hash),
           role = VALUES(role)`,
        [user.nim, user.name, user.email, passwordHash, user.role]
      );

      const [rows] = await conn.execute(
        "SELECT id FROM users WHERE email = ?",
        [user.email]
      );

      userIds[user.email] = rows[0].id;
    }

    // Setiap pengguna memiliki satu perangkat terdaftar
    const devices = [
      ["admin@zt.local", "device-admin-001", "Laptop Admin"],
      ["dosen1@zt.local", "device-dosen1-001", "Laptop Dosen 1"],
      ["dosen2@zt.local", "device-dosen2-001", "Laptop Dosen 2"],
      ["mahasiswa1@zt.local", "device-mhs1-001", "Laptop Mahasiswa 1"],
      ["mahasiswa2@zt.local", "device-mhs2-001", "Laptop Mahasiswa 2"],
      ["mahasiswa3@zt.local", "device-mhs3-001", "Laptop Mahasiswa 3"],
    ];

    for (const [email, deviceId, deviceName] of devices) {
      await conn.execute(
        `INSERT INTO devices (user_id, device_id, device_name)
         VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE
           user_id = VALUES(user_id),
           device_name = VALUES(device_name),
           is_active = TRUE`,
        [userIds[email], deviceId, deviceName]
      );
    }

    // Dua kelas dengan dosen pengampu berbeda
    const classes = [
      ["IF-A", "Keamanan Informasi A", "dosen1@zt.local"],
      ["IF-B", "Keamanan Informasi B", "dosen2@zt.local"],
    ];

    const classIds = {};

    for (const [code, name, lecturerEmail] of classes) {
      await conn.execute(
        `INSERT INTO classes (class_code, class_name, lecturer_id)
         VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE
           class_name = VALUES(class_name),
           lecturer_id = VALUES(lecturer_id)`,
        [code, name, userIds[lecturerEmail]]
      );

      const [rows] = await conn.execute(
        "SELECT id FROM classes WHERE class_code = ?",
        [code]
      );

      classIds[code] = rows[0].id;
    }

    // Mahasiswa 1 dan 2 di kelas A; mahasiswa 3 di kelas B
    const enrollments = [
      ["IF-A", "mahasiswa1@zt.local"],
      ["IF-A", "mahasiswa2@zt.local"],
      ["IF-B", "mahasiswa3@zt.local"],
    ];

    for (const [classCode, studentEmail] of enrollments) {
      await conn.execute(
        `INSERT INTO enrollments (class_id, student_id)
         VALUES (?, ?)
         ON DUPLICATE KEY UPDATE student_id = VALUES(student_id)`,
        [classIds[classCode], userIds[studentEmail]]
      );
    }

    // Nilai awal untuk pengujian
    const grades = [
      ["IF-A", "mahasiswa1@zt.local", 85],
      ["IF-A", "mahasiswa2@zt.local", 90],
      ["IF-B", "mahasiswa3@zt.local", 88],
    ];

    for (const [classCode, studentEmail, score] of grades) {
      await conn.execute(
        `INSERT INTO grades (class_id, student_id, score)
         VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE
           score = IF(is_final = FALSE, VALUES(score), score)`,
        [classIds[classCode], userIds[studentEmail], score]
      );
    }

    // Kredensial Service Nilai; secret hanya disimpan dalam bentuk hash
    const clientId = "service-nilai";
    const clientSecret = "NilaiServiceDemo_2026!";
    const clientSecretHash = await bcrypt.hash(clientSecret, 12);

    await conn.execute(
      `INSERT INTO service_clients
         (client_id, client_secret_hash, service_name)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE
         client_secret_hash = VALUES(client_secret_hash),
         service_name = VALUES(service_name),
         is_active = TRUE`,
      [clientId, clientSecretHash, "Service Nilai"]
    );

    await conn.commit();

    console.log("Seed berhasil.");
    console.log("Akun demo:");
    for (const user of users) {
      console.log(`${user.role.padEnd(9)} ${user.email} | ${user.password}`);
    }
    console.log(`Service client: ${clientId} | ${clientSecret}`);
    console.log("Device IDs:");
    for (const [email, deviceId] of devices) {
      console.log(`${email} | ${deviceId}`);
    }
  } catch (error) {
    await conn.rollback();
    console.error("Seed gagal:", error.message);
    process.exitCode = 1;
  } finally {
    conn.release();
    await db.end();
  }
}

main().catch((error) => {
  console.error("Gagal menjalankan seed:", error.message);
  process.exitCode = 1;
});

