const bcrypt = require("bcrypt");
const saltRounds = 10; // จำนวนรอบในการแฮช

// Middleware สำหรับการเข้ารหัสรหัสผ่าน
const hashPassword = async (req, res, next) => {
  try {
    if (req.body.password) {
      const hashedPassword = await bcrypt.hash(req.body.password, saltRounds);
      req.body.password = hashedPassword; // แทนที่รหัสผ่านด้วยรหัสผ่านที่ถูกเข้ารหัส
    }
    next(); // ไปยังขั้นตอนถัดไป
  } catch (error) {
    console.error("❌ Error hashing password:", error.message);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในการเข้ารหัสรหัสผ่าน" });
  }
};

// Middleware สำหรับการตรวจสอบรหัสผ่าน (ในกรณีของการ login)
const comparePassword = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const [results] = await conn.query("SELECT * FROM users WHERE email = ?", [email]);

    if (results.length === 0) {
      return res.status(404).json({ message: "ไม่พบผู้ใช้" });
    }

    const user = results[0];

    // ตรวจสอบรหัสผ่าน
    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      return res.status(400).json({ message: "รหัสผ่านไม่ถูกต้อง" });
    }

    // ถ้ารหัสผ่านถูกต้อง, ส่งข้อมูลผู้ใช้ไปยังขั้นตอนถัดไป
    req.user = user;
    next();
  } catch (error) {
    res.status(500).json({ message: "เกิดข้อผิดพลาดในการตรวจสอบรหัสผ่าน" });
  }
};

module.exports = { hashPassword, comparePassword };
