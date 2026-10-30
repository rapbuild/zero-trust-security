# ZERO TRUST SECURITY
### Praktikum Keamanan Informasi
**Program Studi Informatika — Universitas Siliwangi**

## 1. Deskripsi Project

Project ini merupakan implementasi konsep **Zero Trust Security** pada sistem pengelolaan nilai mahasiswa.

Sistem menerapkan prinsip *Never Trust, Always Verify*, yaitu setiap request harus melalui proses autentikasi dan pemeriksaan hak akses sebelum diberikan izin.

Teknologi yang digunakan:
- Node.js
- Express.js
- MySQL 8.4
- Docker dan Docker Compose
- JSON Web Token (JWT)
- bcrypt
- Postman

## 2. Arsitektur Sistem

Sistem terdiri dari tiga komponen utama:

| Komponen | Port | Fungsi |
|---|---:|---|
| API Gateway | 3000 | Pintu masuk request, autentikasi, dan pengecekan kebijakan akses |
| Service Nilai | 3001 | Mengelola nilai mahasiswa dan finalisasi nilai |
| Service Transkrip | 3002 | Mengelola dan menampilkan transkrip mahasiswa |
| MySQL | 3306 | Menyimpan data aplikasi |

Alur komunikasi:

```text
Client / Postman
       |
       v
 API Gateway :3000
       |
       +-------------------+
       |                   |
       v                   v
 Service Nilai        Service Transkrip
   :3001                    :3002
       |                   |
       +---------+---------+
                 |
                 v
              MySQL
```

Seluruh request pengguna masuk melalui API Gateway. Service internal juga melakukan pemeriksaan Gateway Secret dan JWT.

## 3. Struktur Project

```text
zero-trust-security/
│
├── database/
│   ├── db.js
│   ├── schema.sql
│   └── seed.js
│
├── gateway/
│   └── server.js
│
├── services/
│   ├── nilai.js
│   └── transkrip.js
│
├── lib/
│   └── security.js
│
├── compose.yaml
├── package.json
├── .env
└── .gitignore
```

## 4. Persyaratan

Sebelum menjalankan project, pastikan sudah tersedia:
- Node.js dan npm
- Docker Desktop atau Docker Engine
- Docker Compose
- Postman

## 5. Konfigurasi Environment

Buat file `.env` di direktori utama project.

Contoh konfigurasi:

```env
DB_ROOT_PASSWORD=isi_password_root
DB_NAME=zero_trust_db
DB_USER=zt_user
DB_PASSWORD=isi_password_database
DB_HOST=127.0.0.1
DB_PORT=3306

JWT_ACCESS_SECRET=isi_secret_jwt
GATEWAY_SECRET=isi_gateway_secret

SERVICE_CLIENT_ID=service-nilai
SERVICE_CLIENT_SECRET=isi_secret_service

GATEWAY_PORT=3000
NILAI_PORT=3001
TRANSKRIP_PORT=3002
```

Sesuaikan nilai konfigurasi dengan environment yang digunakan.

**Penting:** Jangan mengunggah file `.env` ke repository publik karena berisi kredensial dan secret aplikasi.

## 6. Cara Menjalankan Project

### A. Install dependency

Masuk ke direktori project, kemudian jalankan:

```bash
npm install
```

### B. Menjalankan database

Jalankan MySQL menggunakan Docker Compose:

```bash
docker compose up -d
```

Periksa container:

```bash
docker ps
```

### C. Membuat tabel database

Import struktur database:

```bash
docker exec -i zero-trust-mysql mysql -u root -p zero_trust_db < database/schema.sql
```

Masukkan password root MySQL ketika diminta.

### D. Mengisi data awal

Jalankan:

```bash
npm run seed
```

Perintah ini mengisi database dengan data awal berupa akun admin, dosen, mahasiswa, kelas, perangkat terdaftar, dan data nilai.

### E. Menjalankan API Gateway

Buka terminal pertama:

```bash
npm run gateway
```

### F. Menjalankan Service Nilai

Buka terminal kedua:

```bash
npm run nilai
```

### G. Menjalankan Service Transkrip

Buka terminal ketiga:

```bash
npm run transkrip
```

Pastikan ketiga service berjalan tanpa error.

## 7. Akun dan Device ID Data Awal

Berikut akun demo yang dibuat melalui proses seeding:

| Role | Email | Password | Device ID |
|---|---|---|---|
| Admin | admin@zt.local | AdminDemo_2026! | device-admin-001 |
| Dosen 1 | dosen1@zt.local | DosenDemo_2026! | device-dosen1-001 |
| Dosen 2 | dosen2@zt.local | DosenDemo_2026! | device-dosen2-001 |
| Mahasiswa 1 | mahasiswa1@zt.local | MhsDemo_2026! | device-mhs1-001 |
| Mahasiswa 2 | mahasiswa2@zt.local | MhsDemo_2026! | device-mhs2-001 |
| Mahasiswa 3 | mahasiswa3@zt.local | MhsDemo_2026! | device-mhs3-001 |

### Data Mahasiswa

| Mahasiswa | NIM |
|---|---|
| Mahasiswa 1 | 247006001 |
| Mahasiswa 2 | 247006002 |
| Mahasiswa 3 | 247006003 |

### Data Kelas

| Kelas | Dosen Pengampu |
|---|---|
| IF-A | Dosen 1 |
| IF-B | Dosen 2 |

## 8. Implementasi Keamanan

### A. Authentication dengan JWT
- Login menggunakan email dan password.
- Access token berlaku selama 10 menit.
- Refresh token berlaku selama 1 hari dan disimpan di database.
- Logout mencabut refresh token agar tidak dapat digunakan kembali.

### B. Device Verification

Setiap request pengguna pada endpoint yang dilindungi membutuhkan header:

```http
X-Device-ID: device-mhs1-001
```

Device ID harus sesuai dengan perangkat yang terdaftar untuk pengguna tersebut.

### C. Role-Based Access Control (RBAC)

Hak akses dibedakan berdasarkan role:
- Admin dapat melihat transkrip mahasiswa mana pun.
- Mahasiswa hanya dapat melihat nilai dan transkrip miliknya sendiri.
- Dosen hanya dapat mengakses kelas yang diajarnya.
- Service Nilai memiliki akses khusus untuk sinkronisasi transkrip.

### D. Gateway Protection

Service internal membutuhkan Gateway Secret dan verifikasi JWT. Request langsung tanpa autentikasi internal yang sesuai akan ditolak.

### E. Service Token

Service Nilai meminta service token melalui endpoint `/auth/service` untuk melakukan sinkronisasi nilai final ke Service Transkrip.

Service token berlaku selama 5 menit.

### F. Pembatasan Waktu

Perubahan dan finalisasi nilai hanya dapat dilakukan pada pukul 07.00–21.00.

### G. Finalisasi Nilai

Nilai yang sudah difinalisasi tidak dapat diubah kembali melalui endpoint update biasa.

Setelah finalisasi, Service Nilai melakukan sinkronisasi data nilai final ke Service Transkrip.

### H. Audit Log

Sistem mencatat keputusan akses, meliputi:
- Waktu akses
- Subject
- Endpoint
- Device ID
- Keputusan allow atau deny
- Alasan keputusan

## 9. Endpoint Utama

| Method | Endpoint | Keterangan |
|---|---|---|
| POST | `/auth/login` | Login pengguna |
| POST | `/auth/refresh` | Meminta access token baru |
| POST | `/auth/logout` | Logout dan mencabut refresh token |
| POST | `/auth/service` | Meminta service token |
| GET | `/nilai` | Melihat data nilai |
| PUT | `/nilai/:id` | Mengubah nilai |
| POST | `/kelas/:id/finalisasi` | Finalisasi nilai kelas |
| GET | `/transkrip/:nim` | Melihat transkrip mahasiswa |
| POST | `/transkrip/sinkron` | Sinkronisasi transkrip oleh Service Nilai |

## 10. Pengujian Menggunakan Postman

Pengujian dilakukan menggunakan Postman dengan skenario berikut:

1. Login menggunakan akun mahasiswa dan dosen.
2. Mengakses nilai menggunakan access token yang valid.
3. Mengakses endpoint tanpa token dan memastikan request ditolak.
4. Menggunakan Device ID yang tidak sesuai dan memastikan request ditolak.
5. Mengakses service secara langsung tanpa Gateway Secret.
6. Menguji pembatasan akses mahasiswa terhadap data mahasiswa lain.
7. Mengubah nilai menggunakan akun dosen yang berwenang.
8. Memfinalisasi nilai dan menguji penolakan update setelah finalisasi.
9. Memastikan nilai final tersinkronisasi ke transkrip.
10. Menguji refresh token dan logout.

## 11. Catatan

- Pastikan database dan ketiga service aktif sebelum pengujian.
- Gunakan akun dan Device ID sesuai tabel data awal.
- Jangan membagikan file `.env`, access token, refresh token, atau secret aplikasi.
- Jika database perlu dikembalikan ke data awal, sesuaikan proses reset dengan kebutuhan pengujian.

---

**Project Praktikum Keamanan Informasi — Zero Trust Security**  
Program Studi Informatika  
Universitas Siliwangi
