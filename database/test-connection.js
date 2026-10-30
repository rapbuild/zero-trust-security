const db = require("./db");

async function main() {
  try {
    const [rows] = await db.query("SELECT 1 AS hasil");
    console.log("Koneksi MySQL berhasil:", rows[0]);
  } catch (error) {
    console.error("Koneksi MySQL gagal:", error.message);
    process.exitCode = 1;
  } finally {
    await db.end();
  }
}

main();
