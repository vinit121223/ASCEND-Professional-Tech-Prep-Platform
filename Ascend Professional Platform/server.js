// server.js - Single backend file for AI E-Learning Platform

import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

// ================== Database Connection ==================
mongoose
  .connect(process.env.MONGO_URI || "mongodb://127.0.0.1:27017/elearning", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ DB Error:", err));

// ================== Schemas & Models ==================
const userSchema = new mongoose.Schema(
  {
    name: String,
    email: { type: String, unique: true },
    password: String,
    role: { type: String, enum: ["student", "admin"], default: "student" },
  },
  { timestamps: true }
);

const courseSchema = new mongoose.Schema(
  {
    title: String,
    description: String,
    category: String,
    level: { type: String, enum: ["beginner", "intermediate", "advanced"] },
    content: [String], // video URLs, PDFs etc.
  },
  { timestamps: true }
);

const progressSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    course: { type: mongoose.Schema.Types.ObjectId, ref: "Course" },
    completedLessons: { type: Number, default: 0 },
    totalLessons: { type: Number, default: 0 },
    status: { type: String, enum: ["in-progress", "completed"], default: "in-progress" },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
const Course = mongoose.model("Course", courseSchema);
const Progress = mongoose.model("Progress", progressSchema);

// ================== Middleware ==================
const authMiddleware = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(401).json({ msg: "No token provided" });

  try {
    const decoded = jwt.verify(token.split(" ")[1], process.env.JWT_SECRET || "secretkey");
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ msg: "Invalid token" });
  }
};

// ================== Routes ==================

// --- User Register ---
app.post("/api/users/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ msg: "User already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hashed, role });
    res.json({ msg: "User registered successfully", user });
  } catch (err) {
    res.status(500).json({ msg: "Error registering user", error: err.message });
  }
});

// --- User Login ---
app.post("/api/users/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ msg: "Invalid credentials" });

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET || "secretkey", { expiresIn: "1d" });
    res.json({ msg: "Login successful", token });
  } catch (err) {
    res.status(500).json({ msg: "Error logging in", error: err.message });
  }
});

// --- Add Course (Admin only) ---
app.post("/api/courses", authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== "admin") return res.status(403).json({ msg: "Not authorized" });

    const course = await Course.create(req.body);
    res.json({ msg: "Course added successfully", course });
  } catch (err) {
    res.status(500).json({ msg: "Error adding course", error: err.message });
  }
});

// --- Get All Courses ---
app.get("/api/courses", async (req, res) => {
  const courses = await Course.find();
  res.json(courses);
});

// --- Update Progress ---
app.post("/api/progress", authMiddleware, async (req, res) => {
  try {
    const { courseId, completedLessons, totalLessons } = req.body;
    let progress = await Progress.findOne({ user: req.user.id, course: courseId });

    if (!progress) {
      progress = new Progress({ user: req.user.id, course: courseId, completedLessons, totalLessons });
    } else {
      progress.completedLessons = completedLessons;
      progress.totalLessons = totalLessons;
      progress.status = completedLessons >= totalLessons ? "completed" : "in-progress";
    }

    await progress.save();
    res.json({ msg: "Progress updated", progress });
  } catch (err) {
    res.status(500).json({ msg: "Error updating progress", error: err.message });
  }
});

// --- Get User Progress ---
app.get("/api/progress/:courseId", authMiddleware, async (req, res) => {
  try {
    const progress = await Progress.findOne({ user: req.user.id, course: req.params.courseId }).populate("course");
    res.json(progress);
  } catch (err) {
    res.status(500).json({ msg: "Error fetching progress", error: err.message });
  }
});

// ================== Start Server ==================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
