const express = require("express")
const Database = require("better-sqlite3")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")

const app = express()
app.use(express.json())
app.use(express.static("."))

const db = new Database("notes.db")
const SECRET = "mynoteappsecret123"

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`)

db.exec(`
  CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    text TEXT NOT NULL,
    is_deleted INTEGER DEFAULT 0,
    user_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`)

// Middleware — check token on protected routes
function authenticate(req, res, next) {
  const token = req.headers.authorization

  if (!token) {
    return res.status(401).send({ message: "Please login first" })
  }

  try {
    const decoded = jwt.verify(token, SECRET)
    req.userId = decoded.userId
    next()
  } catch(e) {
    res.status(401).send({ message: "Invalid token" })
  }
}

// SIGNUP
app.post("/signup", async function(req, res) {
  const { email, password } = req.body

  if (!email || !password) {
    return res.status(400).send({ message: "Email and password required" })
  }

  // Check if email already exists
  const existing = db.prepare("SELECT * FROM users WHERE email = ?").get(email)
  if (existing) {
    return res.status(400).send({ message: "Email already registered" })
  }

  // Encrypt password
  const hashedPassword = await bcrypt.hash(password, 10)

  // Save user
  db.prepare("INSERT INTO users (email, password) VALUES (?, ?)").run(email, hashedPassword)

  res.send({ message: "Account created! Please login." })
})

// LOGIN
app.post("/login", async function(req, res) {
  const { email, password } = req.body

  // Find user
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email)
  if (!user) {
    return res.status(400).send({ message: "Email not found" })
  }

  // Check password
  const match = await bcrypt.compare(password, user.password)
  if (!match) {
    return res.status(400).send({ message: "Wrong password" })
  }

  // Create token
  const token = jwt.sign({ userId: user.id }, SECRET)

  res.send({ message: "Logged in!", token: token })
})

// GET active notes — protected
app.get("/notes", authenticate, function(req, res) {
  const notes = db.prepare("SELECT * FROM notes WHERE is_deleted = 0 AND user_id = ?").all(req.userId)
  res.send(notes)
})

// GET deleted notes — protected
app.get("/notes/deleted", authenticate, function(req, res) {
  const notes = db.prepare("SELECT * FROM notes WHERE is_deleted = 1 AND user_id = ?").all(req.userId)
  res.send(notes)
})

// POST — save note — protected
app.post("/notes", authenticate, function(req, res) {
  const text = req.body.text
  db.prepare("INSERT INTO notes (text, user_id) VALUES (?, ?)").run(text, req.userId)
  res.send({ message: "Note saved!" })
})

// DELETE — soft delete — protected
app.delete("/notes/:id", authenticate, function(req, res) {
  const id = req.params.id
  db.prepare("UPDATE notes SET is_deleted = 1 WHERE id = ? AND user_id = ?").run(id, req.userId)
  res.send({ message: "Note moved to recycle bin!" })
})

// RESTORE — must come BEFORE the edit route
app.put("/notes/:id/restore", authenticate, function(req, res) {
  const id = req.params.id
  db.prepare("UPDATE notes SET is_deleted = 0 WHERE id = ? AND user_id = ?").run(id, req.userId)
  res.send({ message: "Note restored!" })
})

// EDIT — comes after restore
app.put("/notes/:id", authenticate, function(req, res) {
  const id = req.params.id
  const text = req.body.text
  db.prepare("UPDATE notes SET text = ? WHERE id = ? AND user_id = ?").run(text, id, req.userId)
  res.send({ message: "Note updated!" })
})

// PERMANENT delete — protected
app.delete("/notes/:id/permanent", authenticate, function(req, res) {
  const id = req.params.id
  db.prepare("DELETE FROM notes WHERE id = ? AND user_id = ?").run(id, req.userId)
  res.send({ message: "Note permanently deleted!" })
})

app.listen(3000, function() {
  console.log("Server running on http://localhost:3000")
})