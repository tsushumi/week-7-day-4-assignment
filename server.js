import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import { authenticate, authenticateCookie } from "./middleware/auth.js";
import { authorize } from "./middleware/authorize.js";
import { csrfProtection, generateCsrfToken } from "./middleware/csrf.js";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cookieParser());

const SALT_ROUNDS = 10;
const PORT = process.env.PORT || 3000;
const VALID_ROLES = ["USER", "EDITOR", "ADMIN"];

// Seed data. Plaintext passwords below are ONLY so you can log in and test
// each role locally — they're hashed into passwordHash on startup and the
// plaintext is never stored or returned.
const SEED_CREDENTIALS = {
  "admin@mail.com": "Admin123",
  "editor@mail.com": "Editor123",
  "wanjiku@mail.com": "Wanjiku123",
  "ochieng@mail.com": "Ochieng123",
};

const users = [
  { id: 1, email: "admin@mail.com", name: "Admin User", role: "ADMIN", passwordHash: "" },
  { id: 2, email: "editor@mail.com", name: "Editor User", role: "EDITOR", passwordHash: "" },
  { id: 3, email: "wanjiku@mail.com", name: "Wanjiku", role: "USER", passwordHash: "" },
  { id: 4, email: "ochieng@mail.com", name: "Ochieng", role: "USER", passwordHash: "" },
];

const posts = [
  { id: 1, title: "My First Post", content: "Hello world", userId: 3 },
  { id: 2, title: "Express Tips", content: "Middleware is powerful", userId: 4 },
  { id: 3, title: "Nairobi Guide", content: "Best restaurants in Westlands", userId: 3 },
];
let nextPostId = posts.length + 1;

async function seedPasswords() {
  for (const user of users) {
    user.passwordHash = await bcrypt.hash(SEED_CREDENTIALS[user.email], SALT_ROUNDS);
  }
}

// Helpers
function findUserByEmail(email) {
  const lower = email.toLowerCase();
  return users.find((u) => u.email.toLowerCase() === lower);
}

function findUserById(id) {
  return users.find((u) => u.id === id);
}

function publicUser(user) {
  const { passwordHash, ...safe } = user;
  return safe;
}

function generateToken(user) {
  return jwt.sign(
    { userId: user.id, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "24h" }
  );
}

// POST /api/auth/login — plain JSON token, used for all Bearer-token tests
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};

  if (typeof email !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "Email and password are required" });
  }

  const user = findUserByEmail(email);
  const passwordMatches = user
    ? await bcrypt.compare(password, user.passwordHash)
    : false;

  if (!user || !passwordMatches) {
    return res.status(401).json({ error: "Invalid email or password" });
  }

  const token = generateToken(user);
  return res.status(200).json({ token, user: publicUser(user) });
});

// Task 1: role-based routes

// ADMIN only — list all users
app.get("/api/admin/users", authenticate, authorize("ADMIN"), (req, res) => {
  return res.status(200).json({ users: users.map(publicUser) });
});

// ADMIN only — change a user's role
app.patch(
  "/api/admin/users/:id/role",
  authenticate,
  authorize("ADMIN"),
  (req, res) => {
    const targetId = Number(req.params.id);
    const { role } = req.body || {};

    if (!VALID_ROLES.includes(role)) {
      return res.status(400).json({
        error: `Role must be one of: ${VALID_ROLES.join(", ")}`,
      });
    }

    const targetUser = findUserById(targetId);
    if (!targetUser) {
      return res.status(404).json({ error: "User not found" });
    }

    if (targetUser.id === req.user.userId) {
      return res
        .status(403)
        .json({ error: "Admins cannot change their own role" });
    }

    targetUser.role = role;
    return res.status(200).json({ user: publicUser(targetUser) });
  }
);

// EDITOR and ADMIN — all posts from all users
app.get(
  "/api/editor/posts",
  authenticate,
  authorize("EDITOR", "ADMIN"),
  (req, res) => {
    return res.status(200).json({ posts });
  }
);

// Any authenticated user — only their own posts
app.get("/api/posts", authenticate, (req, res) => {
  const ownPosts = posts.filter((p) => p.userId === req.user.userId);
  return res.status(200).json({ posts: ownPosts });
});

// Task 2: resource-level authorization

// Any authenticated user can view any single post
app.get("/api/posts/:id", authenticate, (req, res) => {
  const post = posts.find((p) => p.id === Number(req.params.id));
  if (!post) {
    return res.status(404).json({ error: "Post not found" });
  }
  return res.status(200).json({ post });
});

function canModifyPost(req, post) {
  return post.userId === req.user.userId || req.user.role === "ADMIN";
}

// Owner or ADMIN only
app.put("/api/posts/:id", authenticate, (req, res) => {
  const post = posts.find((p) => p.id === Number(req.params.id));
  if (!post) {
    return res.status(404).json({ error: "Post not found" });
  }
  if (!canModifyPost(req, post)) {
    return res.status(403).json({ error: "You can only edit your own posts" });
  }

  const { title, content } = req.body || {};
  if (typeof title === "string" && title.trim().length > 0) post.title = title;
  if (typeof content === "string") post.content = content;

  return res.status(200).json({ post });
});

// Owner or ADMIN only
app.delete("/api/posts/:id", authenticate, (req, res) => {
  const index = posts.findIndex((p) => p.id === Number(req.params.id));
  if (index === -1) {
    return res.status(404).json({ error: "Post not found" });
  }
  const post = posts[index];
  if (!canModifyPost(req, post)) {
    return res
      .status(403)
      .json({ error: "You can only delete your own posts" });
  }

  posts.splice(index, 1);
  return res.status(200).json({ message: "Post deleted" });
});

// Bonus: cookie-based auth + CSRF protection

// Sets the JWT as an httpOnly cookie instead of returning it in the body.
app.post("/api/auth/login-cookie", async (req, res) => {
  const { email, password } = req.body || {};

  if (typeof email !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "Email and password are required" });
  }

  const user = findUserByEmail(email);
  const passwordMatches = user
    ? await bcrypt.compare(password, user.passwordHash)
    : false;

  if (!user || !passwordMatches) {
    return res.status(401).json({ error: "Invalid email or password" });
  }

  const token = generateToken(user);
  res.cookie("token", token, {
    httpOnly: true,
    // Browsers (and curl) only ever send a `Secure` cookie back over
    // HTTPS, so this is gated on NODE_ENV to keep local `http://localhost`
    // testing possible. Set NODE_ENV=production (or just always true)
    // once this is actually deployed behind HTTPS.
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 24 * 60 * 60 * 1000,
  });

  return res.status(200).json({ message: "Login successful", user: publicUser(user) });
});

// Issues a CSRF token for the current cookie-authenticated session.
app.get("/api/csrf-token", authenticateCookie, (req, res) => {
  const csrfToken = generateCsrfToken(req.user.userId);
  return res.status(200).json({ csrfToken });
});

// Demo state-changing route protected by cookie auth + CSRF token, to show
// the full bonus flow end-to-end (login-cookie -> csrf-token -> this route).
app.post(
  "/api/secure/posts",
  authenticateCookie,
  csrfProtection,
  (req, res) => {
    const { title, content } = req.body || {};
    if (typeof title !== "string" || title.trim().length === 0) {
      return res.status(400).json({ error: "Title is required" });
    }

    const post = {
      id: nextPostId++,
      title,
      content: content || "",
      userId: req.user.userId,
    };
    posts.push(post);

    return res.status(201).json({ post });
  }
);

seedPasswords().then(() => {
  app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
  });
});
