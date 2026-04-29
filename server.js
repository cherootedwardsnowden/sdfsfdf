/*
 * MetaUpload - Production File Hosting
 * All rights reserved. Unauthorized redistribution prohibited.
 */

const xp = require("express");
const ml = require("multer");
const bc = require("bcryptjs");
const jw = require("jsonwebtoken");
const cp = require("cookie-parser");
const fs = require("fs");
const pt = require("path");
const cr = require("crypto");
const uu = require("uuid");
const ht = require("helmet");
const rl = require("express-rate-limit");
const app = xp();

const _0x = (s) => cr.createHash("sha256").update(s).digest("hex");
const _1x = (n, k) => { const c = cr.createCipheriv("aes-256-cbc", Buffer.from(_0x(k).slice(0,32)), Buffer.from(_0x(k).slice(0,16))); return c.update(n,"utf8","hex") + c.final("hex"); };
const _2x = (n, k) => { try { const c = cr.createDecipheriv("aes-256-cbc", Buffer.from(_0x(k).slice(0,32)), Buffer.from(_0x(k).slice(0,16))); return c.update(n,"hex","utf8") + c.final("utf8"); } catch(e) { return null; } };

const OWNER_IP = "176.42.131.129";
const JWT_SECRET = process.env.JWT_SECRET || _0x("metaupload_secret_9x2k_" + Date.now().toString().slice(0,6));
const DATA_KEY = process.env.DATA_KEY || _0x("datakey_mu_" + OWNER_IP);
const PORT = process.env.PORT || 3000;

const DIRS = { uploads: "./mu_files", thumbs: "./mu_thumbs", data: "./mu_data" };
Object.values(DIRS).forEach(d => !fs.existsSync(d) && fs.mkdirSync(d, { recursive: true }));

const DB = {
  _f: (n) => pt.join(DIRS.data, _0x(n).slice(0,16) + ".dat"),
  _r: (n) => { try { const raw = fs.readFileSync(DB._f(n),"utf8"); return JSON.parse(_2x(raw, DATA_KEY) || "{}"); } catch(e) { return {}; } },
  _w: (n, d) => { fs.writeFileSync(DB._f(n), _1x(JSON.stringify(d), DATA_KEY), "utf8"); },
  get: (n) => DB._r(n),
  set: (n, d) => DB._w(n, d),
  merge: (n, d) => { const old = DB._r(n); DB._w(n, Object.assign(old, d)); }
};

function initData() {
  if (!DB.get("users").initialized) {
    const DEFAULT_OWNER_PW = "MetaOwner@2024!";
    DB.set("users", {
      initialized: true,
      list: {
        "owner": { id: "owner", username: "owner", password: bc.hashSync(DEFAULT_OWNER_PW, 10), role: "owner", created: Date.now(), uploadedToday: 0, lastDay: new Date().toDateString(), totalUploads: 0 }
      }
    });
    console.log("╔══════════════════════════════════════╗");
    console.log("║   MetaUpload - Owner Account Created  ║");
    console.log("║   Username : owner                    ║");
    console.log("║   Password : MetaOwner@2024!          ║");
    console.log("║   >> Change password via admin panel  ║");
    console.log("╚══════════════════════════════════════╝");
  }
  }
  if (!DB.get("files").initialized) DB.set("files", { initialized: true, list: {} });
  if (!DB.get("config").initialized) DB.set("config", { initialized: true, premiumEnabled: false, maintenance: false, maxFreeDaily: 30*1024*1024, maxVipDaily: 1024*1024*1024 });
  if (!DB.get("sessions").initialized) DB.set("sessions", { initialized: true, list: {} });
}
initData();

const LIMITS = { free: 30*1024*1024, vip: 1024*1024*1024, owner: Infinity, mod: Infinity };
const ROLES = ["owner","mod","vip","free"];

function getUser(username) { const d = DB.get("users"); return d.list && d.list[username] ? d.list[username] : null; }
function saveUser(u) { const d = DB.get("users"); d.list[u.username] = u; DB.set("users", d); }
function getFile(fid) { const d = DB.get("files"); return d.list && d.list[fid] ? d.list[fid] : null; }
function saveFile(f) { const d = DB.get("files"); d.list[f.id] = f; DB.set("files", d); }
function deleteFile(fid) { const d = DB.get("files"); if (d.list) { delete d.list[fid]; DB.set("files", d); } }
function getCfg() { return DB.get("config"); }
function saveCfg(c) { DB.set("config", c); }

function checkDailyReset(u) {
  const today = new Date().toDateString();
  if (u.lastDay !== today) { u.uploadedToday = 0; u.lastDay = today; }
  return u;
}

const storage = ml.diskStorage({
  destination: (req, file, cb) => cb(null, DIRS.uploads),
  filename: (req, file, cb) => {
    const ext = pt.extname(file.originalname).toLowerCase();
    const fid = _0x(uu.v4() + Date.now() + file.originalname).slice(0,32);
    cb(null, fid + ext);
  }
});

const fileFilter = (req, file, cb) => {
  const allowed = ["image/jpeg","image/png","image/gif","image/webp","video/mp4","video/webm","video/ogg","video/quicktime"];
  allowed.includes(file.mimetype) ? cb(null, true) : cb(new Error("INVALID_TYPE"), false);
};

const upload = ml({ storage, fileFilter, limits: { fileSize: 1024*1024*1024 } });

function authMW(req, res, next) {
  const token = req.cookies && req.cookies["_mu_sess"];
  if (!token) return res.status(401).json({ error: "AUTH_REQUIRED" });
  try {
    const pl = jw.verify(token, JWT_SECRET);
    const u = getUser(pl.username);
    if (!u) return res.status(401).json({ error: "USER_NOT_FOUND" });
    req.user = u;
    next();
  } catch(e) { return res.status(401).json({ error: "INVALID_TOKEN" }); }
}

function ownerMW(req, res, next) {
  const clientIp = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket.remoteAddress || req.ip;
  const isOwner = clientIp === OWNER_IP || clientIp === "::ffff:" + OWNER_IP || clientIp === "::1";
  if (!isOwner) return res.status(403).json({ error: "IP_FORBIDDEN", detail: "Owner actions restricted to authorized IP." });
  authMW(req, res, () => {
    if (req.user.role !== "owner") return res.status(403).json({ error: "ROLE_FORBIDDEN" });
    next();
  });
}

function modMW(req, res, next) {
  authMW(req, res, () => {
    if (!["owner","mod"].includes(req.user.role)) return res.status(403).json({ error: "MOD_REQUIRED" });
    next();
  });
}

const limiter = rl({ windowMs: 15*60*1000, max: 120, standardHeaders: true, legacyHeaders: false });
const authLimiter = rl({ windowMs: 15*60*1000, max: 20, standardHeaders: true, legacyHeaders: false });

app.use(ht({ contentSecurityPolicy: false }));
app.use(limiter);
app.use(xp.json({ limit: "2mb" }));
app.use(xp.urlencoded({ extended: true, limit: "2mb" }));
app.use(cp());
app.set("trust proxy", 1);

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────

app.post("/api/register", authLimiter, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.json({ ok: false, error: "MISSING_FIELDS" });
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) return res.json({ ok: false, error: "INVALID_USERNAME" });
  if (password.length < 6) return res.json({ ok: false, error: "PASS_TOO_SHORT" });
  if (getUser(username)) return res.json({ ok: false, error: "USER_EXISTS" });
  const hashed = await bc.hash(password, 12);
  const u = { id: uu.v4(), username, password: hashed, role: "free", created: Date.now(), uploadedToday: 0, lastDay: new Date().toDateString(), totalUploads: 0, banned: false };
  saveUser(u);
  res.json({ ok: true });
});

app.post("/api/login", authLimiter, async (req, res) => {
  const { username, password } = req.body;
  const u = getUser(username);
  if (!u) return res.json({ ok: false, error: "INVALID_CREDENTIALS" });
  if (u.banned) return res.json({ ok: false, error: "ACCOUNT_BANNED" });
  const valid = await bc.compare(password, u.password);
  if (!valid) return res.json({ ok: false, error: "INVALID_CREDENTIALS" });
  const token = jw.sign({ username: u.username, role: u.role }, JWT_SECRET, { expiresIn: "7d" });
  res.cookie("_mu_sess", token, { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict", maxAge: 7*24*60*60*1000 });
  res.json({ ok: true, role: u.role, username: u.username });
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("_mu_sess");
  res.json({ ok: true });
});

app.get("/api/me", authMW, (req, res) => {
  const u = checkDailyReset(req.user);
  saveUser(u);
  const limit = LIMITS[u.role] || LIMITS.free;
  const remaining = limit === Infinity ? -1 : Math.max(0, limit - (u.uploadedToday || 0));
  res.json({ ok: true, username: u.username, role: u.role, remaining, totalUploads: u.totalUploads || 0 });
});

// ─── UPLOAD ROUTE ─────────────────────────────────────────────────────────────

app.post("/api/upload", authMW, upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ ok: false, error: "NO_FILE" });
  const u = checkDailyReset(req.user);
  const cfg = getCfg();
  const fsize = req.file.size;
  const limit = LIMITS[u.role] || LIMITS.free;

  if (limit !== Infinity && (u.uploadedToday || 0) + fsize > limit) {
    fs.unlinkSync(req.file.path);
    return res.json({ ok: false, error: "DAILY_LIMIT_EXCEEDED" });
  }

  const isVideo = req.file.mimetype.startsWith("video/");
  const isImage = req.file.mimetype.startsWith("image/");
  const isGif = req.file.mimetype === "image/gif";
  // User can mark video as premium only if premium mode is enabled; images/gifs are never premium
  const userWantsPremium = req.body && req.body.markPremium === "1";
  const isPremiumContent = isVideo && cfg.premiumEnabled && userWantsPremium;
  const fid = pt.basename(req.file.filename, pt.extname(req.file.filename));
  const thumbName = fid + "_t.jpg";
  const gifThumbName = fid + "_g.gif";
  const thumbPath = pt.join(DIRS.thumbs, thumbName);
  const gifThumbPath = pt.join(DIRS.thumbs, gifThumbName);

  let thumbReady = false;
  let gifReady = false;

  // Setup ffmpeg with static binary (Railway compatible)
  const ffmpegPath = require("ffmpeg-static");
  const ffprobePath = require("@ffprobe-installer/ffprobe").path;
  const ffmpeg = require("fluent-ffmpeg");
  ffmpeg.setFfmpegPath(ffmpegPath);
  ffmpeg.setFfprobePath(ffprobePath);

  // Generate static thumbnail
  try {
    if (isImage && !isGif) {
      const sharp = require("sharp");
      await sharp(req.file.path).resize(320, 240, { fit: "cover" }).jpeg({ quality: 70 }).toFile(thumbPath);
      thumbReady = true;
    } else if (isVideo) {
      await new Promise((resolve) => {
        ffmpeg(req.file.path)
          .seekInput(Math.random() * 4 + 0.5)
          .frames(1)
          .size("320x240")
          .output(thumbPath)
          .on("end", () => { thumbReady = true; resolve(); })
          .on("error", (e) => { console.log("[thumb]", e.message); resolve(); })
          .run();
      });
    }
  } catch(e) { console.log("[thumb-outer]", e.message); }

  // Generate hover GIF: 7 frames each 1s, 1.5s apart → combined webp-palette GIF
  try {
    if (isVideo) {
      const segPaths = [];
      for (let i = 0; i < 7; i++) {
        const sp = pt.join(DIRS.thumbs, fid + "_s" + i + ".gif");
        await new Promise((resolve) => {
          ffmpeg(req.file.path)
            .seekInput(i * 1.5)
            .duration(1)
            .outputOptions(["-vf","fps=8,scale=320:240:flags=lanczos,split[a][b];[a]palettegen=max_colors=64[p];[b][p]paletteuse","−loop","0"])
            .output(sp)
            .on("end", () => { if (fs.existsSync(sp)) segPaths.push(sp); resolve(); })
            .on("error", () => resolve())
            .run();
        });
      }
      if (segPaths.length >= 2) {
        // Concat all segment GIFs into one using fluent-ffmpeg
        let cmd = ffmpeg();
        segPaths.forEach(s => cmd.input(s));
        await new Promise((resolve) => {
          cmd.complexFilter([`concat=n=${segPaths.length}:v=1:a=0[v]`], ["v"])
            .outputOptions(["-loop","0"])
            .output(gifThumbPath)
            .on("end", () => { gifReady = fs.existsSync(gifThumbPath); resolve(); })
            .on("error", () => resolve())
            .run();
        });
      } else if (segPaths.length === 1) {
        try { fs.renameSync(segPaths[0], gifThumbPath); gifReady = true; } catch(e2) {}
      }
      segPaths.forEach(s => { try { fs.unlinkSync(s); } catch(e3) {} });
    }
  } catch(e) { console.log("[gifthumb]", e.message); }

  u.uploadedToday = (u.uploadedToday || 0) + fsize;
  u.totalUploads = (u.totalUploads || 0) + 1;
  saveUser(u);

  const fd = {
    id: fid,
    originalName: _1x(req.file.originalname, DATA_KEY),
    filename: req.file.filename,
    mimetype: req.file.mimetype,
    size: fsize,
    uploader: u.username,
    uploaded: Date.now(),
    premium: isPremiumContent,
    thumbReady,
    gifReady,
    views: 0,
    downloads: 0
  };
  saveFile(fd);

  const remaining = limit === Infinity ? -1 : Math.max(0, limit - u.uploadedToday);
  res.json({ ok: true, id: fid, premium: isPremiumContent, remaining });
});

// ─── FILE SERVING ─────────────────────────────────────────────────────────────

app.get("/f/:fid", authMW, (req, res) => {
  const f = getFile(req.params.fid);
  if (!f) return res.status(404).json({ error: "NOT_FOUND" });

  const clientIp = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket.remoteAddress;
  const u = req.user;
  const isVideo = f.mimetype.startsWith("video/");
  const isOwnerIp = clientIp === OWNER_IP || clientIp === "::ffff:" + OWNER_IP;

  if (f.premium && isVideo) {
    if (!["owner","mod","vip"].includes(u.role) && !isOwnerIp) {
      return res.status(403).json({ error: "VIP_REQUIRED", preview: true });
    }
  }

  f.views = (f.views || 0) + 1;
  saveFile(f);

  const fp = pt.join(DIRS.uploads, f.filename);
  if (!fs.existsSync(fp)) return res.status(404).json({ error: "FILE_MISSING" });

  // Anti-leech: block non-browser clients by user-agent signature
  const ua = (req.headers["user-agent"] || "").toLowerCase();
  const _bk = ["w"+"get","cu"+"rl","ar"+"ia","id"+"m","internet download","fd"+"m","jdown","downloadmgr","getr"+"ight","flashg"+"et","libwww","python-requests","go-http","java/","okhttp"];
  if (_bk.some(b => ua.includes(b))) return res.status(403).json({ error: "ACCESS_DENIED" });

  const stat = fs.statSync(fp);
  const range = req.headers.range;

  if (isVideo && range) {
    const cfg = getCfg();
    const canFull = ["owner","mod","vip"].includes(u.role) || isOwnerIp;

    if (cfg.premiumEnabled && f.premium && !canFull) {
      // Only allow first 15 seconds of video (approx bitrate-based limiting)
      const maxBytes = Math.min(stat.size, Math.floor(stat.size * 0.15 + 1024*512));
      const parts = range.replace(/bytes=/, "").split("-");
      const start = parseInt(parts[0], 10);
      if (start > maxBytes) return res.status(403).setHeader("X-Preview-Limit", "15s").end();

      const end = Math.min(parts[1] ? parseInt(parts[1], 10) : stat.size - 1, maxBytes - 1);
      const chunksize = (end - start) + 1;
      const file = fs.createReadStream(fp, { start, end });
      res.writeHead(206, {
        "Content-Range": `bytes ${start}-${end}/${stat.size}`,
        "Accept-Ranges": "bytes",
        "Content-Length": chunksize,
        "Content-Type": f.mimetype,
        "X-Content-Options": "nosniff",
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Pragma": "no-cache",
        "X-Preview-Limit": "15s"
      });
      file.pipe(res);
      return;
    }

    // Full range request
    const parts = range.replace(/bytes=/, "").split("-");
    const start = parseInt(parts[0], 10);
    const end = parts[1] ? parseInt(parts[1], 10) : stat.size - 1;
    const chunksize = (end - start) + 1;
    const file = fs.createReadStream(fp, { start, end });
    res.writeHead(206, {
      "Content-Range": `bytes ${start}-${end}/${stat.size}`,
      "Accept-Ranges": "bytes",
      "Content-Length": chunksize,
      "Content-Type": f.mimetype,
      "Content-Disposition": `inline; filename="${_0x(f.filename).slice(0,12)}"`,
      "X-Content-Options": "nosniff",
      "Cache-Control": "no-store"
    });
    file.pipe(res);
    return;
  }

  res.setHeader("Content-Type", f.mimetype);
  res.setHeader("Content-Length", stat.size);
  res.setHeader("Content-Disposition", `inline; filename="${_0x(f.filename).slice(0,12)}"`);
  res.setHeader("Cache-Control", "no-store, no-cache");
  res.setHeader("X-Content-Options", "nosniff");
  fs.createReadStream(fp).pipe(res);
});

// Thumbnail
app.get("/t/:fid", (req, res) => {
  const tp = pt.join(DIRS.thumbs, req.params.fid + "_t.jpg");
  if (!fs.existsSync(tp)) return res.status(404).end();
  res.setHeader("Cache-Control", "public, max-age=86400");
  res.setHeader("Content-Type", "image/jpeg");
  fs.createReadStream(tp).pipe(res);
});

// Hover GIF thumbnail
app.get("/g/:fid", (req, res) => {
  const gp = pt.join(DIRS.thumbs, req.params.fid + "_g.gif");
  if (!fs.existsSync(gp)) return res.status(404).end();
  res.setHeader("Cache-Control", "public, max-age=86400");
  res.setHeader("Content-Type", "image/gif");
  fs.createReadStream(gp).pipe(res);
});

// ─── FILE INFO ────────────────────────────────────────────────────────────────

app.get("/api/file/:fid", authMW, (req, res) => {
  const f = getFile(req.params.fid);
  if (!f) return res.status(404).json({ error: "NOT_FOUND" });
  const cfg = getCfg();
  res.json({
    ok: true,
    id: f.id,
    originalName: _2x(f.originalName, DATA_KEY) || "unknown",
    mimetype: f.mimetype,
    size: f.size,
    uploader: f.uploader,
    uploaded: f.uploaded,
    premium: f.premium && cfg.premiumEnabled,
    thumbReady: f.thumbReady,
    gifReady: f.gifReady,
    views: f.views,
    downloads: f.downloads
  });
});

app.get("/api/myfiles", authMW, (req, res) => {
  const d = DB.get("files");
  const files = Object.values(d.list || {})
    .filter(f => f.uploader === req.user.username)
    .sort((a,b) => b.uploaded - a.uploaded)
    .map(f => ({ id: f.id, originalName: _2x(f.originalName, DATA_KEY) || "file", mimetype: f.mimetype, size: f.size, uploaded: f.uploaded, premium: f.premium, views: f.views || 0 }));
  res.json({ ok: true, files });
});

app.delete("/api/file/:fid", authMW, (req, res) => {
  const f = getFile(req.params.fid);
  if (!f) return res.status(404).json({ error: "NOT_FOUND" });
  if (f.uploader !== req.user.username && !["owner","mod"].includes(req.user.role)) return res.status(403).json({ error: "FORBIDDEN" });
  try { fs.unlinkSync(pt.join(DIRS.uploads, f.filename)); } catch(e) {}
  try { fs.unlinkSync(pt.join(DIRS.thumbs, f.id + "_t.jpg")); } catch(e) {}
  try { fs.unlinkSync(pt.join(DIRS.thumbs, f.id + "_g.gif")); } catch(e) {}
  deleteFile(f.id);
  res.json({ ok: true });
});

// ─── OWNER PANEL ROUTES ───────────────────────────────────────────────────────

app.get("/api/admin/users", ownerMW, (req, res) => {
  const d = DB.get("users");
  const users = Object.values(d.list || {}).map(u => ({
    username: u.username, role: u.role, created: u.created,
    totalUploads: u.totalUploads || 0, banned: u.banned || false,
    uploadedToday: u.uploadedToday || 0
  }));
  res.json({ ok: true, users });
});

app.post("/api/admin/setrole", ownerMW, (req, res) => {
  const { username, role } = req.body;
  if (!ROLES.includes(role)) return res.json({ ok: false, error: "INVALID_ROLE" });
  const u = getUser(username);
  if (!u) return res.json({ ok: false, error: "USER_NOT_FOUND" });
  u.role = role;
  saveUser(u);
  res.json({ ok: true });
});

app.post("/api/admin/ban", ownerMW, (req, res) => {
  const { username, banned } = req.body;
  const u = getUser(username);
  if (!u) return res.json({ ok: false, error: "USER_NOT_FOUND" });
  u.banned = !!banned;
  saveUser(u);
  res.json({ ok: true });
});

app.post("/api/admin/config", ownerMW, (req, res) => {
  const cfg = getCfg();
  const { premiumEnabled, maintenance, maxFreeDaily, maxVipDaily } = req.body;
  if (premiumEnabled !== undefined) cfg.premiumEnabled = !!premiumEnabled;
  if (maintenance !== undefined) cfg.maintenance = !!maintenance;
  if (maxFreeDaily) { cfg.maxFreeDaily = parseInt(maxFreeDaily); LIMITS.free = cfg.maxFreeDaily; }
  if (maxVipDaily) { cfg.maxVipDaily = parseInt(maxVipDaily); LIMITS.vip = cfg.maxVipDaily; }
  saveCfg(cfg);
  res.json({ ok: true, cfg });
});

app.get("/api/admin/config", ownerMW, (req, res) => res.json({ ok: true, cfg: getCfg() }));

app.get("/api/admin/files", ownerMW, (req, res) => {
  const d = DB.get("files");
  const files = Object.values(d.list || {}).sort((a,b) => b.uploaded - a.uploaded).map(f => ({
    id: f.id, originalName: _2x(f.originalName, DATA_KEY) || "file",
    mimetype: f.mimetype, size: f.size, uploader: f.uploader,
    uploaded: f.uploaded, premium: f.premium, views: f.views || 0
  }));
  res.json({ ok: true, files });
});

app.delete("/api/admin/file/:fid", ownerMW, (req, res) => {
  const f = getFile(req.params.fid);
  if (!f) return res.status(404).json({ error: "NOT_FOUND" });
  try { fs.unlinkSync(pt.join(DIRS.uploads, f.filename)); } catch(e) {}
  try { fs.unlinkSync(pt.join(DIRS.thumbs, f.id + "_t.jpg")); } catch(e) {}
  try { fs.unlinkSync(pt.join(DIRS.thumbs, f.id + "_g.gif")); } catch(e) {}
  deleteFile(f.id);
  res.json({ ok: true });
});

app.post("/api/admin/resetpw", ownerMW, async (req, res) => {
  const { username, newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) return res.json({ ok: false, error: "PASS_TOO_SHORT" });
  const u = getUser(username);
  if (!u) return res.json({ ok: false, error: "USER_NOT_FOUND" });
  u.password = await bc.hash(newPassword, 12);
  saveUser(u);
  res.json({ ok: true });
});

app.get("/api/admin/stats", ownerMW, (req, res) => {
  const users = DB.get("users");
  const files = DB.get("files");
  const ulist = Object.values(users.list || {});
  const flist = Object.values(files.list || {});
  let totalSize = 0;
  flist.forEach(f => totalSize += f.size || 0);
  res.json({
    ok: true,
    totalUsers: ulist.length,
    totalFiles: flist.length,
    totalSize,
    vipUsers: ulist.filter(u => u.role === "vip").length,
    modUsers: ulist.filter(u => u.role === "mod").length,
    bannedUsers: ulist.filter(u => u.banned).length
  });
});

// ─── CONFIG PUBLIC ─────────────────────────────────────────────────────────────

app.get("/api/config", (req, res) => {
  const cfg = getCfg();
  res.json({ premiumEnabled: cfg.premiumEnabled, maintenance: cfg.maintenance });
});

// ─── MAINTENANCE MW ────────────────────────────────────────────────────────────

app.use((req, res, next) => {
  const cfg = getCfg();
  if (cfg.maintenance) {
    const clientIp = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket.remoteAddress;
    if (clientIp !== OWNER_IP && clientIp !== "::ffff:" + OWNER_IP) {
      if (req.path.startsWith("/api/") && !req.path.startsWith("/api/login")) {
        return res.status(503).json({ error: "MAINTENANCE_MODE" });
      }
    }
  }
  next();
});

// ─── FRONTEND ─────────────────────────────────────────────────────────────────

app.get("*", (req, res) => {
  const htmlPath = pt.join(__dirname, "index.html");
  if (fs.existsSync(htmlPath)) return res.sendFile(htmlPath);
  res.status(404).send("MetaUpload - index.html not found");
});

app.listen(PORT, () => console.log(`[MetaUpload] Running on :${PORT}`));
