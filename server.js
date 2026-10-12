const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = 3000;
const JWT_SECRET = "lab3-secret-change-in-production";

app.use(cors());
app.use(express.json());
app.use(express.static("public"));

let users = [];
let nextId = 1;

users.push({
  id: nextId++,
  username: "admin",
  password: bcrypt.hashSync("admin123", 10),
  role: "admin",
});

// admin token
// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc5MTEwNjg4NCwiZXhwIjoxNzkxMTEwNDg0fQ.Ri7WAtHjImFEmbZK1Ftmjz0tA2iu7xYGi_LbyXl1KPc

// user token
// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJrZW5ueSIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzkxMTA4NDA4LCJleHAiOjE3OTExMTIwMDh9.xqfCUkH68gjt3HX5-0NbrIi-1jrQwVZzCGpPFIKe3ns

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(404).json({ message: "No token provided" });

  const token = header.split(" ")[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (error) {
    return res.status(403).json({ message: "Invalid token" });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin only" });
  }

  next();
}

app.get("/api/health", (req, res) => {
  res.json({ status: "Ok", message: "REST API is running " });
});

app.get("/api/users", auth, adminOnly, (req, res) => {
  const safeUsers = users.map((user) => ({
    id: user.id,
    username: user.username,
    role: user.role,
  }));
  res.json(safeUsers);
});

app.get("/api/users/:id", auth, (req, res) => {
  const id = Number(req.params.id);
  const user = users.find((u) => u.id === id);

  if (!user) return res.status(404).json({ message: "User not found" });
  if (req.user.id !== user.id && req.user.role !== "admin") {
    return res.status(403).json({ message: "Forbidden" });
  }
  res.json({ id: user.id, username: user.username, role: user.role });
});

app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password required" });
  }

  const existingUser = users.find((u) => u.username === username);

  if (existingUser) {
    return res.status(409).json({ message: "Username already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = {
    id: nextId++,
    username,
    password: hashedPassword,
    role: "user",
  };

  users.push(newUser);

  res.status(201).json({
    message: "User registered successfully",

    user: { id: newUser.id, username: newUser.username, role: newUser.role },
  });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  const user = users.find((u) => u.username === username);

  if (!user) return res.status(401).json({ message: "Invalid credentials" });

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) return res.status(401).json({ message: "Invalid credentials" });

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },

    JWT_SECRET,

    { expiresIn: "1h" },
  );

  res.json({
    message: "Login successful",

    token,

    user: { id: user.id, username: user.username, role: user.role },
  });
});

app.put("/api/users/:id", auth, async (req, res) => {
  const id = Number(req.params.id);

  const user = users.find((u) => u.id === id);

  if (!user) return res.status(404).json({ message: "User not found" });

  if (req.user.id !== user.id && req.user.role !== "admin") {
    return res.status(403).json({ message: "Forbidden" });
  }

  const { username, password, role } = req.body;

  if (username) user.username = username;

  if (password) user.password = await bcrypt.hash(password, 10);

  if (role && req.user.role === "admin") user.role = role;

  res.json({
    message: "User updated successfully",

    user: { id: user.id, username: user.username, role: user.role },
  });
});

app.delete("/api/users/:id", auth, adminOnly, (req, res) => {
  const id = Number(req.params.id);

  const index = users.findIndex((u) => u.id === id);

  if (index === -1) return res.status(404).json({ message: "User not found" });

  const deletedUser = users.splice(index, 1)[0];

  res.json({
    message: "User deleted successfully",

    user: { id: deletedUser.id, username: deletedUser.username },
  });
});

app.get("/api/profile", auth, (req, res) => {
  const user = users.find((u) => u.id === req.user.id);

  res.json({ id: user.id, username: user.username, role: user.role });
});

app.get("/", (req, res) => {
  res.redirect("/login.html");
});

app.listen(PORT, () => {
  console.log(`Server is running on: http://localhost:${PORT}`);
});
