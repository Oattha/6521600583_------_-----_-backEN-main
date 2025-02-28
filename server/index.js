const express = require("express");
const bodyparser = require("body-parser");
const mysql = require("mysql2/promise");
const cors = require("cors");
const bcrypt = require("bcrypt");
const saltRounds = 10; // จำนวนรอบในการแฮช

const app = express();
const port = 3000;

app.use(bodyparser.json());
app.use(cors());

let conn = null;

// เชื่อมต่อ MySQL
const initMySQL = async () => {
  try {
    conn = await mysql.createConnection({
      host: "localhost",
      user: "root",
      password: "root",
      database: "webdb",
      port: 8820,
    });
    console.log("✅ MySQL Connected");
  } catch (error) {
    console.error("❌ MySQL Connection Failed:", error.message);
    process.exit(1); // ปิดเซิร์ฟเวอร์ถ้าเชื่อมต่อไม่ได้
  }
};

// ตรวจสอบข้อมูลก่อนบันทึก
const validateData = (userData) => {
  let errors = [];
  if (!userData.name) errors.push("กรุณากรอกชื่อ");
  if (!userData.email) errors.push("กรุณากรอกอีเมล");
  if (!userData.password) errors.push("กรุณากรอกรหัสผ่าน");

  return errors;
};

// Middleware สำหรับการเข้ารหัสรหัสผ่าน
const hashPassword = async (req, res, next) => {
  try {
    if (req.body.password) {
      // เข้ารหัสรหัสผ่านก่อนบันทึก
      const hashedPassword = await bcrypt.hash(req.body.password, saltRounds);
      req.body.password = hashedPassword; // แทนที่รหัสผ่านด้วยรหัสผ่านที่ถูกเข้ารหัส
    }
    next(); // ไปยังขั้นตอนถัดไป
  } catch (error) {
    console.error("❌ Error hashing password:", error.message);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในการเข้ารหัสรหัสผ่าน" });
  }
};

// ✅ GET /users → ดึงข้อมูล users ทั้งหมด
app.get("/users", async (req, res) => {
  try {
    const [results] = await conn.query("SELECT * FROM users");
    res.json(results);
  } catch (error) {
    console.error("❌ Error fetching users:", error.message);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในเซิร์ฟเวอร์" });
  }
});

// ✅ GET /users/:id → ดึงข้อมูล user รายบุคคล
app.get("/users/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) throw { statusCode: 400, message: "ID ต้องเป็นตัวเลข" };

    const [results] = await conn.query("SELECT * FROM users WHERE id = ?", [id]);

    if (results.length === 0) {
      throw { statusCode: 404, message: "ไม่พบผู้ใช้" };
    }

    res.json(results[0]);
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.message });
  }
});

// ✅ POST /users → เพิ่ม user ใหม่
app.post("/users", hashPassword, async (req, res) => { // ใช้ Middleware hashPassword
  try {
    const user = req.body;
    const errors = validateData(user);
    if (errors.length > 0) {
      throw { message: "กรอกข้อมูลไม่ครบ", errors };
    }

    const sql = `INSERT INTO users (name, email, password) VALUES (?, ?, ?)`;
    const values = [user.name, user.email, user.password];

    const [results] = await conn.query(sql, values);
    res.json({ message: "เพิ่มข้อมูลสำเร็จ", userId: results.insertId });
  } catch (error) {
    res.status(500).json({ message: error.message || "เกิดข้อผิดพลาด", errors: error.errors || [] });
  }
});

// ✅ PUT /users/:id → แก้ไขข้อมูล user
app.put("/users/:id", hashPassword, async (req, res) => { // ใช้ Middleware hashPassword
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) throw { statusCode: 400, message: "ID ต้องเป็นตัวเลข" };

    const updateUser = req.body;
    const [results] = await conn.query("UPDATE users SET name = ?, email = ?, password = ? WHERE id = ?", [updateUser.name, updateUser.email, updateUser.password, id]);

    if (results.affectedRows === 0) throw { statusCode: 404, message: "ไม่พบผู้ใช้" };

    res.json({ message: "แก้ไขข้อมูลสำเร็จ" });
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.message });
  }
});

// ✅ DELETE /users/:id → ลบ user
app.delete("/users/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) throw { statusCode: 400, message: "ID ต้องเป็นตัวเลข" };

    const [results] = await conn.query("DELETE FROM users WHERE id = ?", [id]);

    if (results.affectedRows === 0) throw { statusCode: 404, message: "ไม่พบผู้ใช้" };

    res.json({ message: "ลบข้อมูลสำเร็จ" });
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.message });
  }
});
// ✅ POST /login → เข้าสู่ระบบ
// ✅ Start Server
app.listen(port, async () => {
  await initMySQL();
  console.log(`🚀 Server is running at http://localhost:${port}`);
});
