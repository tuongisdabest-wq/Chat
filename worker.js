// Ôn12 - Cloudflare Worker API v2 (thêm kì ôn: tags)
// Binding: DB (D1). Secrets: OWNER_NAME, OWNER_PASS. Biến: ALLOWED_ORIGINS (ví dụ https://tenban.github.io)

const SUBJ = ["su", "dia", "ktpl", "tin", "sinh", "anh"];
const TYPES = ["mcq", "tf4", "w", "cz"];
const DEF_CFG = {
  siteName: "Ôn12",
  slogan: "12A19 cùng nhau tốt nghiệp. Kiếm điểm 10 và 9",
  exam: "2027-06-11",
  periods: [{ k: "gk1", n: "Giữa kì 1" }, { k: "ck1", n: "Cuối kì 1" }, { k: "gk2", n: "Giữa kì 2" }, { k: "ck2", n: "Cuối kì 2" }, { k: "tn", n: "Tốt nghiệp" }],
  author: "", fb: "", tt: "", zalo: "", mail: "", banner: "",
  levels: {
    1: { n: "Cơ bản", dich: 1, goiy: 1, ky: 1 },
    2: { n: "Trung bình", dich: 1, goiy: 1, ky: 0 },
    3: { n: "Nâng cao", dich: 0, goiy: 0, ky: 0 },
  },
};

class E extends Error { constructor(s, m) { super(m); this.s = s; } }

const enc = new TextEncoder();
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
const rnd = n => hex(crypto.getRandomValues(new Uint8Array(n)));
const sha = async s => hex(await crypto.subtle.digest("SHA-256", enc.encode(s)));
async function pbk(secret, salt) {
  const k = await crypto.subtle.importKey("raw", enc.encode(secret), "PBKDF2", false, ["deriveBits"]);
  return hex(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations: 20000 }, k, 256));
}
function eq(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
const str = (v, n) => String(v ?? "").trim().slice(0, n);

function corsH(req, env) {
  const o = req.headers.get("Origin") || "";
  const ok = String(env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
  const h = { "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS", "Access-Control-Allow-Headers": "Authorization,Content-Type", "Vary": "Origin" };
  if (ok.includes(o)) h["Access-Control-Allow-Origin"] = o;
  return h;
}
const send = (b, s, c) => new Response(JSON.stringify(b), { status: s, headers: { "Content-Type": "application/json; charset=utf-8", ...c } });

export default {
  async fetch(req, env) {
    const cors = corsH(req, env);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    try {
      return send(await route(req, env), 200, cors);
    } catch (e) {
      if (e instanceof E) return send({ error: e.message }, e.s, cors);
      return send({ error: "Lỗi máy chủ" }, 500, cors);
    }
  },
};

// ---------- phiên đăng nhập ----------
async function newSession(env, uid, days) {
  const token = rnd(32);
  await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)").bind(await sha(token), uid, Date.now() + days * 864e5).run();
  return token;
}
async function authUser(req, env) {
  const t = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  if (!t) return null;
  const h = await sha(t);
  const u = await env.DB.prepare("SELECT u.id,u.name,u.emoji,u.role,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?").bind(h).first();
  if (!u) return null;
  if (u.expires_at < Date.now()) { await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(h).run(); return null; }
  return { ...u, th: h };
}
async function perms(env, role) {
  if (role === "owner") return ["*"];
  const { results } = await env.DB.prepare("SELECT permission FROM role_permissions WHERE role=?").bind(role).all();
  return results.map(r => r.permission);
}
async function can(env, u, p) {
  const L = await perms(env, u.role);
  if (!L.includes("*") && !L.includes(p)) throw new E(403, "Bạn không có quyền làm việc này");
}
const need = u => { if (!u) throw new E(401, "Bạn cần đăng nhập"); return u; };
const audit = (env, u, a, d) => env.DB.prepare("INSERT INTO audit_log(user_id,action,detail,created_at) VALUES(?,?,?,?)").bind(u ? u.id : null, a, d ? String(d).slice(0, 300) : null, Date.now()).run();

// ---------- chống dò mật khẩu ----------
async function guard(env, key) {
  const r = await env.DB.prepare("SELECT count,first_at FROM login_attempts WHERE key=?").bind(key).first();
  if (r && Date.now() - r.first_at < 9e5 && r.count >= 5) throw new E(429, "Sai quá nhiều lần, thử lại sau 15 phút");
}
async function fail(env, key) {
  const now = Date.now();
  await env.DB.prepare("INSERT INTO login_attempts(key,count,first_at) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN ?-first_at>9e5 THEN 1 ELSE count+1 END, first_at=CASE WHEN ?-first_at>9e5 THEN ? ELSE first_at END").bind(key, now, now, now, now).run();
  throw new E(401, "Sai tên hoặc mật khẩu");
}
const clear = (env, key) => env.DB.prepare("DELETE FROM login_attempts WHERE key=?").bind(key).run();

// ---------- tiện ích ----------
async function getConfig(env) {
  const { results } = await env.DB.prepare("SELECT key,value FROM config").all();
  const c = JSON.parse(JSON.stringify(DEF_CFG));
  for (const r of results) if (r.key in DEF_CFG) { try { c[r.key] = JSON.parse(r.value); } catch (e) {} }
  return c;
}
async function streakOf(env, uid) {
  const { results } = await env.DB.prepare("SELECT DISTINCT date(created_at/1000+25200,'unixepoch') d FROM results WHERE user_id=? ORDER BY d DESC LIMIT 400").bind(uid).all();
  const day = o => new Date(Date.now() + 25200000 - o * 864e5).toISOString().slice(0, 10);
  const set = new Set(results.map(r => r.d));
  let i = set.has(day(0)) ? 0 : 1, n = 0;
  while (set.has(day(i))) { n++; i++; }
  return n;
}
const qOut = r => ({ ...JSON.parse(r.data), id: r.id, s: r.subject, b: r.bai, ky: JSON.parse(r.tags || "[]") });
const tagsOf = (v, cfg) => {
  const ok = cfg.periods.map(p => p.k);
  return [...new Set((Array.isArray(v) ? v : []).map(x => String(x)).filter(x => ok.includes(x)))];
};

// ---------- định tuyến ----------
async function route(req, env) {
  const url = new URL(req.url), m = req.method;
  const p = url.pathname.replace(/\/+$/, "");
  if (!p.startsWith("/api/v1")) throw new E(404, "Không tìm thấy");
  const path = p.slice(7) || "/";
  const body = ["POST", "PUT", "PATCH"].includes(m) ? await req.json().catch(() => ({})) : {};
  const ip = req.headers.get("CF-Connecting-IP") || "x";
  const DB = env.DB;

  // --- công khai ---
  if (m === "GET" && path === "/config") return await getConfig(env);

  if (m === "POST" && path === "/register") {
    const name = str(body.name, 20), pin = String(body.pin || ""), emoji = str(body.emoji, 8) || "🦊";
    if (name.length < 2) throw new E(400, "Tên cần ít nhất 2 ký tự");
    if (!/^\d{4}$/.test(pin)) throw new E(400, "PIN phải gồm đúng 4 số");
    if (await DB.prepare("SELECT 1 FROM users WHERE name=?").bind(name).first()) throw new E(409, "Tên này đã có người dùng");
    const salt = rnd(8);
    const r = await DB.prepare("INSERT INTO users(name,secret_hash,salt,emoji,role,created_at) VALUES(?,?,?,?, 'student', ?)").bind(name, await pbk(pin, salt), salt, emoji, Date.now()).run();
    return { token: await newSession(env, r.meta.last_row_id, 30), user: { id: r.meta.last_row_id, name, emoji, role: "student" } };
  }

  if (m === "POST" && path === "/login") {
    const name = str(body.name, 20), pin = String(body.pin || ""), key = "s:" + ip + ":" + name.toLowerCase();
    await guard(env, key);
    const u = await DB.prepare("SELECT * FROM users WHERE name=? AND role='student'").bind(name).first();
    if (!u || !eq(await pbk(pin, u.salt), u.secret_hash)) await fail(env, key);
    await clear(env, key);
    return { token: await newSession(env, u.id, 30), user: { id: u.id, name: u.name, emoji: u.emoji, role: u.role } };
  }

  if (m === "POST" && path === "/admin/login") {
    const name = str(body.name, 40), pw = String(body.password || ""), key = "a:" + ip + ":" + name.toLowerCase();
    await guard(env, key);
    let u;
    if (env.OWNER_NAME && name.toLowerCase() === String(env.OWNER_NAME).toLowerCase()) {
      if (!eq(pw, String(env.OWNER_PASS || ""))) await fail(env, key);
      await DB.prepare("INSERT OR IGNORE INTO users(name,role,created_at) VALUES(?, 'owner', ?)").bind(env.OWNER_NAME, Date.now()).run();
      await DB.prepare("UPDATE users SET role='owner' WHERE name=?").bind(env.OWNER_NAME).run();
      u = await DB.prepare("SELECT * FROM users WHERE name=?").bind(env.OWNER_NAME).first();
    } else {
      u = await DB.prepare("SELECT * FROM users WHERE name=? AND role IN ('admin','mod')").bind(name).first();
      if (!u || !eq(await pbk(pw, u.salt), u.secret_hash)) await fail(env, key);
    }
    await clear(env, key);
    await audit(env, u, "admin.login");
    return { token: await newSession(env, u.id, 3), user: { id: u.id, name: u.name, emoji: u.emoji, role: u.role }, permissions: await perms(env, u.role) };
  }

  if (m === "GET" && path === "/board") {
    const f = url.searchParams.get("f") || "all";
    if (f === "all") {
      const { results } = await DB.prepare("SELECT u.name,u.emoji,SUM(r.xp) xp FROM results r JOIN users u ON u.id=r.user_id WHERE u.role='student' GROUP BY u.id ORDER BY xp DESC LIMIT 100").all();
      return results;
    }
    if (!SUBJ.includes(f)) throw new E(400, "Môn không hợp lệ");
    const { results } = await DB.prepare("SELECT u.name,u.emoji,MAX(json_extract(r.subs,?1)*10.0/json_extract(r.subs,?2)) s, MIN(r.time_sec) t FROM results r JOIN users u ON u.id=r.user_id WHERE u.role='student' AND json_extract(r.subs,?2)>0 GROUP BY u.id ORDER BY s DESC, t ASC LIMIT 100").bind("$." + f + ".p", "$." + f + ".m").all();
    return results.map(r => ({ ...r, s: Math.round(r.s * 100) / 100 }));
  }

  // --- cần đăng nhập ---
  const user = await authUser(req, env);

  if (m === "POST" && path === "/logout") {
    need(user);
    await DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(user.th).run();
    return { ok: true };
  }

  if (m === "GET" && path === "/me") {
    need(user);
    const { results: hist } = await DB.prepare("SELECT created_at d,score10 score,pts,max,mode,time_sec time,xp,subs FROM results WHERE user_id=? ORDER BY created_at DESC LIMIT 50").bind(user.id).all();
    const x = await DB.prepare("SELECT COALESCE(SUM(xp),0) xp FROM results WHERE user_id=?").bind(user.id).first();
    return { id: user.id, name: user.name, emoji: user.emoji, role: user.role, permissions: await perms(env, user.role), streak: await streakOf(env, user.id), xp: x.xp, history: hist.map(h => ({ ...h, subs: JSON.parse(h.subs) })) };
  }

  if (m === "GET" && path === "/exams") {
    need(user);
    const { results } = await DB.prepare("SELECT e.id,e.subject,e.bai,e.title,e.tags,COUNT(q.id) n FROM exams e LEFT JOIN questions q ON q.exam_id=e.id WHERE e.status='published' GROUP BY e.id ORDER BY e.id DESC").all();
    return results.map(r => ({ ...r, tags: JSON.parse(r.tags || "[]") }));
  }

  if (m === "GET" && path === "/questions") {
    need(user);
    const s = url.searchParams.get("subject"), ky = url.searchParams.get("ky"), bai = url.searchParams.get("bai");
    let sql = "SELECT q.*,e.tags FROM questions q JOIN exams e ON e.id=q.exam_id WHERE e.status='published'";
    const args = [];
    if (s) { sql += " AND q.subject=?"; args.push(s); }
    if (bai) { sql += " AND q.bai=?"; args.push(bai); }
    if (ky) { sql += " AND EXISTS(SELECT 1 FROM json_each(e.tags) WHERE value=?)"; args.push(ky); }
    sql += " ORDER BY q.exam_id,q.position";
    const { results } = await DB.prepare(sql).bind(...args).all();
    return results.map(qOut);
  }

  if (m === "POST" && path === "/results") {
    need(user);
    const pts = +body.pts, max = +body.max, t = Math.max(0, Math.min(+body.time_sec || 0, 36000));
    if (!(max > 0 && max <= 300 && pts >= 0 && pts <= max)) throw new E(400, "Điểm không hợp lệ");
    const att = str(body.attempt, 40);
    if (!att) throw new E(400, "Thiếu mã lượt làm");
    const subs = {};
    for (const k of SUBJ) { const s = body.subs && body.subs[k]; if (s && +s.m > 0 && +s.p >= 0 && +s.p <= +s.m) subs[k] = { p: +s.p, m: +s.m }; }
    const score = Math.round(pts / max * 100) / 10;
    const xp = Math.min(150, Math.round(pts / max * 100) + Math.max(0, Math.floor((+body.left || 0) / 10)));
    try {
      await DB.prepare("INSERT INTO results(user_id,attempt,mode,level,pts,max,score10,xp,time_sec,subs,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)").bind(user.id, att, str(body.mode, 10), +body.level || null, pts, max, score, xp, t, JSON.stringify(subs), Date.now()).run();
    } catch (e) { throw new E(409, "Lượt làm này đã được ghi rồi"); }
    return { score, xp, streak: await streakOf(env, user.id) };
  }

  // --- quản trị ---
  if (path.startsWith("/admin/")) {
    need(user);
    if (!["owner", "admin", "mod"].includes(user.role)) throw new E(403, "Bạn không có quyền làm việc này");
    const seg = path.split("/"); // ["", "admin", ...]

    if (m === "PUT" && path === "/admin/config") {
      await can(env, user, "settings.edit");
      const st = [];
      if ("periods" in body) {
        const ps = Array.isArray(body.periods) ? body.periods : [];
        body.periods = ps.map(p => ({ k: str(p && p.k, 12).replace(/[^a-z0-9]/gi, "").toLowerCase(), n: str(p && p.n, 30) })).filter(p => p.k && p.n).slice(0, 12);
        if (!body.periods.length) throw new E(400, "Cần ít nhất 1 kì");
      }
      for (const k of Object.keys(DEF_CFG)) if (k in body) st.push(DB.prepare("INSERT INTO config(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(k, JSON.stringify(body[k])));
      if (st.length) await DB.batch(st);
      await audit(env, user, "config.update", Object.keys(body).join(","));
      return await getConfig(env);
    }

    if (m === "GET" && path === "/admin/exams") {
      await can(env, user, "exam.upload");
      const { results } = await DB.prepare("SELECT e.id,e.subject,e.bai,e.title,e.status,e.tags,e.updated_at,COUNT(q.id) n FROM exams e LEFT JOIN questions q ON q.exam_id=e.id GROUP BY e.id ORDER BY e.id DESC").all();
      return results.map(r => ({ ...r, tags: JSON.parse(r.tags || "[]") }));
    }

    if (m === "GET" && seg.length === 4 && seg[2] === "exams") {
      await can(env, user, "exam.upload");
      const ex = await DB.prepare("SELECT * FROM exams WHERE id=?").bind(+seg[3]).first();
      if (!ex) throw new E(404, "Không có đề này");
      const { results } = await DB.prepare("SELECT * FROM questions WHERE exam_id=? ORDER BY position").bind(ex.id).all();
      return { ...ex, tags: JSON.parse(ex.tags || "[]"), questions: results.map(r => qOut({ ...r, tags: ex.tags })) };
    }

    if (m === "POST" && path === "/admin/exams") {
      await can(env, user, "exam.upload");
      const qs = Array.isArray(body.questions) ? body.questions : [];
      if (!qs.length || qs.length > 500) throw new E(400, "Đề cần từ 1 đến 500 câu");
      if (!SUBJ.includes(body.subject)) throw new E(400, "Môn không hợp lệ");
      const title = str(body.title, 120) || "Đề chưa đặt tên", bai = str(body.bai, 80) || "Tổng hợp";
      const tags = tagsOf(body.tags, await getConfig(env));
      const rows = qs.map((q, i) => {
        if (!q || !TYPES.includes(q.t)) throw new E(400, "Câu " + (i + 1) + ": dạng câu không hợp lệ");
        const d = JSON.stringify(q);
        if (d.length > 20000) throw new E(400, "Câu " + (i + 1) + " quá dài");
        return d;
      });
      const now = Date.now();
      const ex = await DB.prepare("INSERT INTO exams(subject,bai,title,status,tags,created_at,updated_at) VALUES(?,?,?, 'draft', ?, ?, ?)").bind(body.subject, bai, title, JSON.stringify(tags), now, now).run();
      const id = ex.meta.last_row_id;
      await DB.batch(rows.map((d, i) => DB.prepare("INSERT INTO questions(exam_id,subject,bai,type,data,position) VALUES(?,?,?,?,?,?)").bind(id, body.subject, bai, JSON.parse(d).t, d, i)));
      await audit(env, user, "exam.upload", title + " (" + qs.length + " câu)");
      return { id, n: qs.length, status: "draft", tags };
    }

    if (m === "PATCH" && seg.length === 4 && seg[2] === "exams") {
      const id = +seg[3];
      const ex = await DB.prepare("SELECT * FROM exams WHERE id=?").bind(id).first();
      if (!ex) throw new E(404, "Không có đề này");
      if ("status" in body) {
        await can(env, user, "exam.publish");
        if (!["draft", "published"].includes(body.status)) throw new E(400, "Trạng thái không hợp lệ");
      }
      if ("title" in body || "bai" in body || "tags" in body) await can(env, user, "exam.upload");
      const status = "status" in body ? body.status : ex.status;
      const title = "title" in body ? (str(body.title, 120) || ex.title) : ex.title;
      const bai = "bai" in body ? (str(body.bai, 80) || ex.bai) : ex.bai;
      const tags = "tags" in body ? tagsOf(body.tags, await getConfig(env)) : JSON.parse(ex.tags || "[]");
      await DB.batch([
        DB.prepare("UPDATE exams SET status=?,title=?,bai=?,tags=?,updated_at=? WHERE id=?").bind(status, title, bai, JSON.stringify(tags), Date.now(), id),
        DB.prepare("UPDATE questions SET bai=? WHERE exam_id=?").bind(bai, id),
      ]);
      await audit(env, user, "exam.update", id + " -> " + status);
      return { ok: true };
    }

    if (m === "DELETE" && seg.length === 4 && seg[2] === "exams") {
      await can(env, user, "exam.delete");
      const id = +seg[3];
      await DB.batch([DB.prepare("DELETE FROM questions WHERE exam_id=?").bind(id), DB.prepare("DELETE FROM exams WHERE id=?").bind(id)]);
      await audit(env, user, "exam.delete", id);
      return { ok: true };
    }

    if (m === "GET" && path === "/admin/users") {
      await can(env, user, "user.manage");
      const { results } = await DB.prepare("SELECT u.id,u.name,u.emoji,u.role,u.created_at,COUNT(r.id) n FROM users u LEFT JOIN results r ON r.user_id=u.id GROUP BY u.id ORDER BY u.id DESC LIMIT 500").all();
      return results;
    }

    if (m === "POST" && seg.length === 5 && seg[2] === "users" && seg[4] === "reset-pin") {
      await can(env, user, "user.manage");
      const pin = String(body.pin || "");
      if (!/^\d{4}$/.test(pin)) throw new E(400, "PIN phải gồm đúng 4 số");
      const id = +seg[3], u = await DB.prepare("SELECT role FROM users WHERE id=?").bind(id).first();
      if (!u || u.role !== "student") throw new E(404, "Không có học sinh này");
      const salt = rnd(8);
      await DB.batch([DB.prepare("UPDATE users SET secret_hash=?,salt=? WHERE id=?").bind(await pbk(pin, salt), salt, id), DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(id)]);
      await audit(env, user, "user.reset-pin", id);
      return { ok: true };
    }

    if (m === "DELETE" && seg.length === 4 && seg[2] === "users") {
      await can(env, user, "user.manage");
      const id = +seg[3], u = await DB.prepare("SELECT role FROM users WHERE id=?").bind(id).first();
      if (!u) throw new E(404, "Không có người dùng này");
      if (u.role !== "student") { await can(env, user, "admin.manage"); if (u.role === "owner") throw new E(403, "Không thể xóa owner"); }
      await DB.batch([DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(id), DB.prepare("DELETE FROM results WHERE user_id=?").bind(id), DB.prepare("DELETE FROM users WHERE id=?").bind(id)]);
      await audit(env, user, "user.delete", id);
      return { ok: true };
    }

    if (m === "POST" && path === "/admin/admins") {
      await can(env, user, "admin.manage");
      const name = str(body.name, 40), pw = String(body.password || ""), role = body.role;
      if (name.length < 2) throw new E(400, "Tên cần ít nhất 2 ký tự");
      if (pw.length < 8) throw new E(400, "Mật khẩu cần ít nhất 8 ký tự");
      if (!["admin", "mod"].includes(role)) throw new E(400, "Vai trò không hợp lệ");
      if (await DB.prepare("SELECT 1 FROM users WHERE name=?").bind(name).first()) throw new E(409, "Tên này đã tồn tại");
      const salt = rnd(8);
      const r = await DB.prepare("INSERT INTO users(name,secret_hash,salt,role,created_at) VALUES(?,?,?,?,?)").bind(name, await pbk(pw, salt), salt, role, Date.now()).run();
      await audit(env, user, "admin.create", name + " (" + role + ")");
      return { id: r.meta.last_row_id };
    }
  }

  throw new E(404, "Không tìm thấy");
}
