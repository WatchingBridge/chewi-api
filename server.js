require("dotenv").config();

const path = require("path");
const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const Stripe = require("stripe");
const Database = require("better-sqlite3");

if (!process.env.STRIPE_SECRET_KEY) {
  throw new Error("Missing STRIPE_SECRET_KEY");
}

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const app = express();

const PORT = process.env.PORT || 10000;
const FRONTEND_URL = process.env.FRONTEND_URL || "https://chewi.cc/";
const FRONTEND_ORIGIN = new URL(FRONTEND_URL).origin;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const SESSION_SECRET = process.env.SESSION_SECRET || "";
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "";
const COOKIE_SECURE = process.env.NODE_ENV === "production";
const SESSION_TTL_SECONDS = 60 * 60 * 8;

if (!ADMIN_PASSWORD) {
  console.warn("WARNING: ADMIN_PASSWORD is not set. /admin login will be disabled.");
}
if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.warn("WARNING: SESSION_SECRET should be a random value of at least 32 characters.");
}

const PRICE_IDS = {
  sensation: process.env.SENSATION_PRICE_ID,
  blackout: process.env.BLACKOUT_PRICE_ID,
  sunday: process.env.SUNDAY_PRICE_ID,
  crush: process.env.CRUSH_PRICE_ID,
  stardust: process.env.STARDUST_PRICE_ID,
  "velvet riot": process.env.VELVET_RIOT_PRICE_ID,
};

const ALLOWED_FLAVOURS = new Set(Object.keys(PRICE_IDS));
const ALLOWED_ORDER_STATUSES = new Set([
  "pending_payment",
  "paid",
  "processing",
  "fulfilled",
  "cancelled",
  "refunded",
]);

const APP_DB_PATH =
  process.env.APP_DB_PATH ||
  process.env.REVIEW_DB_PATH ||
  path.join(__dirname, "chewi.db");

const db = new Database(APP_DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    flavour TEXT NOT NULL,
    rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
    message TEXT NOT NULL,
    verified_purchase INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_number TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'pending_payment',
    customer_name TEXT,
    customer_email TEXT,
    customer_phone TEXT,
    shipping_address TEXT,
    delivery_notes TEXT,
    items_json TEXT NOT NULL,
    subtotal_cents INTEGER NOT NULL,
    discount_cents INTEGER NOT NULL DEFAULT 0,
    total_cents INTEGER NOT NULL,
    coupon_code TEXT,
    stripe_session_id TEXT UNIQUE,
    stripe_payment_intent TEXT,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS coupons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL CHECK (type IN ('percent','fixed')),
    value REAL NOT NULL,
    min_subtotal_cents INTEGER NOT NULL DEFAULT 0,
    max_uses INTEGER NOT NULL DEFAULT 0,
    uses INTEGER NOT NULL DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1,
    expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS analytics_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    visitor_hash TEXT NOT NULL,
    session_hash TEXT NOT NULL,
    event_type TEXT NOT NULL,
    event_name TEXT,
    page_mode TEXT NOT NULL,
    page_path TEXT NOT NULL DEFAULT '/',
    referrer TEXT NOT NULL DEFAULT 'direct',
    device TEXT NOT NULL DEFAULT 'unknown',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_analytics_created_at ON analytics_events(created_at);
  CREATE INDEX IF NOT EXISTS idx_analytics_visitor_hash ON analytics_events(visitor_hash);
  CREATE INDEX IF NOT EXISTS idx_analytics_event_type ON analytics_events(event_type);
`);

// Seed two harmless test coupons if they do not exist.
const seedCoupon = db.prepare(`
  INSERT OR IGNORE INTO coupons
  (code, type, value, min_subtotal_cents, max_uses, active)
  VALUES (?, ?, ?, ?, ?, 1)
`);
seedCoupon.run("WELCOME10", "percent", 10, 0, 0);
seedCoupon.run("COOKIE5", "fixed", 5, 2000, 0);

/* -------------------- HELPERS -------------------- */

function normalizeCode(value) {
  return String(value || "").trim().toUpperCase().replace(/[^A-Z0-9_-]/g, "");
}

function moneyToCents(value) {
  const amount = Number(value);
  if (!Number.isFinite(amount) || amount < 0) return null;
  return Math.round(amount * 100);
}

function orderNumber() {
  return `CR-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(2).toString("hex").toUpperCase()}`;
}

function parseCookies(req) {
  const result = {};
  const header = req.headers.cookie || "";
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (key) result[key] = decodeURIComponent(value);
  }
  return result;
}

function timingSafeEqualString(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function signSession(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto
    .createHmac("sha256", SESSION_SECRET || "missing-session-secret")
    .update(body)
    .digest("base64url");
  return `${body}.${signature}`;
}

function verifySession(token) {
  if (!token || !SESSION_SECRET) return null;
  const [body, signature] = String(token).split(".");
  if (!body || !signature) return null;
  const expected = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(body)
    .digest("base64url");
  if (!timingSafeEqualString(signature, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (!payload.exp || Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function setAdminCookie(res, token) {
  const parts = [
    `chewi_admin=${encodeURIComponent(token)}`,
    "HttpOnly",
    "SameSite=Strict",
    "Path=/",
    `Max-Age=${SESSION_TTL_SECONDS}`,
  ];
  if (COOKIE_SECURE) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearAdminCookie(res) {
  const parts = [
    "chewi_admin=",
    "HttpOnly",
    "SameSite=Strict",
    "Path=/",
    "Max-Age=0",
  ];
  if (COOKIE_SECURE) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

function requireAdmin(req, res, next) {
  const token = parseCookies(req).chewi_admin;
  const session = verifySession(token);
  if (!session || session.role !== "admin") {
    return res.status(401).json({ error: "Authentication required." });
  }
  req.admin = session;
  next();
}

function requireCsrf(req, res, next) {
  if (req.method === "GET" || req.method === "HEAD") return next();
  if (!req.admin || !timingSafeEqualString(req.headers["x-csrf-token"] || "", req.admin.csrf || "")) {
    return res.status(403).json({ error: "Invalid CSRF token." });
  }
  next();
}

function getCoupon(code) {
  if (!code) return null;
  return db.prepare("SELECT * FROM coupons WHERE code = ?").get(normalizeCode(code)) || null;
}

function validateCouponRecord(coupon, subtotalCents) {
  if (!coupon) return { valid: false, message: "coupon not found" };
  if (!coupon.active) return { valid: false, message: "coupon is disabled" };
  if (coupon.expires_at && new Date(coupon.expires_at).getTime() <= Date.now()) {
    return { valid: false, message: "coupon has expired" };
  }
  if (coupon.max_uses > 0 && coupon.uses >= coupon.max_uses) {
    return { valid: false, message: "coupon usage limit reached" };
  }
  if (subtotalCents < coupon.min_subtotal_cents) {
    return {
      valid: false,
      message: `minimum spend is €${(coupon.min_subtotal_cents / 100).toFixed(2)}`,
    };
  }

  let discountCents = 0;
  if (coupon.type === "percent") {
    const percentage = Math.max(0, Math.min(100, Number(coupon.value)));
    discountCents = Math.round(subtotalCents * (percentage / 100));
  } else {
    discountCents = Math.round(Number(coupon.value) * 100);
  }
  discountCents = Math.max(0, Math.min(subtotalCents, discountCents));

  return {
    valid: true,
    code: coupon.code,
    discountCents,
    message: `${coupon.code} applied`,
  };
}

function hydrateOrder(row) {
  if (!row) return null;
  let items = [];
  try { items = JSON.parse(row.items_json || "[]"); } catch {}
  return { ...row, items };
}

function hashAnalyticsId(value) {
  const clean = String(value || "").slice(0, 128);
  return crypto
    .createHmac("sha256", SESSION_SECRET || "chewi-analytics-fallback")
    .update(clean)
    .digest("hex");
}

function cleanAnalyticsText(value, max = 120) {
  return String(value || "")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .trim()
    .slice(0, max);
}

const ANALYTICS_PAGE_MODES = new Set(["release", "prerelease", "maintenance"]);
const ANALYTICS_EVENT_TYPES = new Set([
  "page_view",
  "shop_view",
  "product_view",
  "add_to_bag",
  "cart_open",
  "checkout_start",
]);

const analyticsRate = new Map();
function analyticsRateLimit(req, res, next) {
  const key = req.ip || "unknown";
  const now = Date.now();
  const minute = 60 * 1000;
  const current = analyticsRate.get(key) || { count: 0, resetAt: now + minute };
  if (now > current.resetAt) {
    current.count = 0;
    current.resetAt = now + minute;
  }
  if (current.count >= 180) return res.status(429).json({ error: "Too many analytics events." });
  current.count += 1;
  analyticsRate.set(key, current);
  next();
}

async function buildValidatedItems(items) {
  if (!Array.isArray(items) || items.length === 0) {
    throw new Error("Your bag is empty.");
  }

  const normalized = [];
  for (const item of items) {
    const name = String(item.name || "").toLowerCase().trim();
    const quantity = Number(item.quantity);
    if (!PRICE_IDS[name]) throw new Error(`Unknown product: ${name}`);
    if (!Number.isInteger(quantity) || quantity < 1 || quantity > 20) {
      throw new Error(`Invalid quantity for ${name}`);
    }
    const price = await stripe.prices.retrieve(PRICE_IDS[name]);
    if (!price.active || typeof price.unit_amount !== "number") {
      throw new Error(`Stripe price is unavailable for ${name}`);
    }
    normalized.push({
      name,
      quantity,
      priceId: PRICE_IDS[name],
      unitCents: price.unit_amount,
      lineCents: price.unit_amount * quantity,
    });
  }
  return normalized;
}

/* -------------------- STRIPE WEBHOOK -------------------- */
// This route MUST be before express.json() so Stripe can verify the raw body.
app.post("/api/stripe/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  if (!STRIPE_WEBHOOK_SECRET) {
    return res.status(503).send("Webhook secret not configured");
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      req.headers["stripe-signature"],
      STRIPE_WEBHOOK_SECRET
    );
  } catch (error) {
    console.error("Stripe webhook signature error:", error.message);
    return res.status(400).send("Invalid webhook signature");
  }

  try {
    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      const orderId = Number(session.metadata && session.metadata.order_id);
      if (orderId) {
        const customerDetails = session.customer_details || {};
        const shipping = session.shipping_details || session.collected_information?.shipping_details || null;
        const address = shipping?.address || customerDetails.address || null;
        const addressText = address
          ? [address.line1, address.line2, address.city, address.postal_code, address.country].filter(Boolean).join(", ")
          : null;
        const notes = Array.isArray(session.custom_fields)
          ? session.custom_fields.find((f) => f.key === "delivery_notes")?.text?.value || null
          : null;

        const existing = db.prepare("SELECT * FROM orders WHERE id = ?").get(orderId);
        if (existing && existing.status === "pending_payment") {
          const tx = db.transaction(() => {
            db.prepare(`
              UPDATE orders SET
                status = 'paid',
                customer_name = ?,
                customer_email = ?,
                customer_phone = ?,
                shipping_address = ?,
                delivery_notes = ?,
                stripe_session_id = ?,
                stripe_payment_intent = ?,
                updated_at = CURRENT_TIMESTAMP
              WHERE id = ?
            `).run(
              customerDetails.name || null,
              customerDetails.email || session.customer_email || null,
              customerDetails.phone || null,
              addressText,
              notes,
              session.id,
              typeof session.payment_intent === "string" ? session.payment_intent : null,
              orderId
            );
            if (existing.coupon_code) {
              db.prepare("UPDATE coupons SET uses = uses + 1, updated_at = CURRENT_TIMESTAMP WHERE code = ?")
                .run(existing.coupon_code);
            }
          });
          tx();
        }
      }
    }

    if (event.type === "checkout.session.expired") {
      const session = event.data.object;
      const orderId = Number(session.metadata && session.metadata.order_id);
      if (orderId) {
        db.prepare(`
          UPDATE orders SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP
          WHERE id = ? AND status = 'pending_payment'
        `).run(orderId);
      }
    }

    res.json({ received: true });
  } catch (error) {
    console.error("Stripe webhook processing error:", error);
    res.status(500).json({ error: "Webhook processing failed." });
  }
});

/* -------------------- NORMAL MIDDLEWARE -------------------- */

const ALLOWED_ORIGINS = new Set([
  FRONTEND_ORIGIN,
  "https://chewi.cc",
  "https://www.chewi.cc",
  "https://chewi-api.onrender.com",
  "http://localhost:3000",
  "http://127.0.0.1:3000",
].filter(Boolean));

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || ALLOWED_ORIGINS.has(origin)) {
        return callback(null, true);
      }

      console.warn("Blocked CORS origin:", origin);
      return callback(new Error("Not allowed by CORS"));
    },
    methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "X-CSRF-Token"],
    credentials: true,
  })
);

app.options(/.*/, cors({
  origin(origin, callback) {
    if (!origin || ALLOWED_ORIGINS.has(origin)) {
      return callback(null, true);
    }
    return callback(new Error("Not allowed by CORS"));
  },
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "X-CSRF-Token"],
  credentials: true,
}));

app.use(express.json({ limit: "50kb" }));
app.use(express.static(path.join(__dirname, "public")));

app.get("/", (_req, res) => {
  res.json({ ok: true, service: "chewi-api" });
});

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

app.get("/admin", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

/* -------------------- REVIEWS -------------------- */

app.get("/reviews", (req, res) => {
  try {
    const flavour = typeof req.query.flavour === "string" ? req.query.flavour.toLowerCase().trim() : "";
    const rows = flavour && ALLOWED_FLAVOURS.has(flavour)
      ? db.prepare(`
          SELECT id,name,flavour,rating,message,
                 verified_purchase AS verifiedPurchase,
                 created_at AS createdAt
          FROM reviews WHERE flavour = ? ORDER BY id DESC LIMIT 100
        `).all(flavour)
      : db.prepare(`
          SELECT id,name,flavour,rating,message,
                 verified_purchase AS verifiedPurchase,
                 created_at AS createdAt
          FROM reviews ORDER BY id DESC LIMIT 100
        `).all();

    res.json({
      reviews: rows.map((review) => ({
        ...review,
        verifiedPurchase: Boolean(review.verifiedPurchase),
      })),
    });
  } catch (error) {
    console.error("Get reviews error:", error);
    res.status(500).json({ error: "Could not load reviews." });
  }
});

app.post("/reviews", (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const flavour = String(req.body.flavour || "").toLowerCase().trim();
    const rating = Number(req.body.rating);
    const message = String(req.body.message || "").trim();

    if (name.length < 1 || name.length > 40) {
      return res.status(400).json({ error: "Name must be between 1 and 40 characters." });
    }
    if (!ALLOWED_FLAVOURS.has(flavour)) {
      return res.status(400).json({ error: "Invalid cookie flavour." });
    }
    if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
      return res.status(400).json({ error: "Rating must be a whole number from 1 to 5." });
    }
    if (message.length < 2 || message.length > 280) {
      return res.status(400).json({ error: "Review must be between 2 and 280 characters." });
    }

    const result = db.prepare(`
      INSERT INTO reviews (name, flavour, rating, message)
      VALUES (?, ?, ?, ?)
    `).run(name, flavour, rating, message);

    const review = db.prepare(`
      SELECT id,name,flavour,rating,message,
             verified_purchase AS verifiedPurchase,
             created_at AS createdAt
      FROM reviews WHERE id = ?
    `).get(result.lastInsertRowid);

    res.status(201).json({
      review: { ...review, verifiedPurchase: Boolean(review.verifiedPurchase) },
    });
  } catch (error) {
    console.error("Create review error:", error);
    res.status(500).json({ error: "Could not save review." });
  }
});

/* -------------------- COUPONS -------------------- */

app.post("/api/coupons/validate", (req, res) => {
  try {
    const code = normalizeCode(req.body.code);
    const subtotalCents = moneyToCents(req.body.subtotal);
    if (!code) return res.status(400).json({ valid: false, message: "enter a coupon code" });
    if (subtotalCents === null) return res.status(400).json({ valid: false, message: "invalid subtotal" });
    const result = validateCouponRecord(getCoupon(code), subtotalCents);
    if (!result.valid) return res.status(400).json(result);
    res.json({
      ...result,
      discount: result.discountCents / 100,
      subtotal: subtotalCents / 100,
      total: (subtotalCents - result.discountCents) / 100,
    });
  } catch (error) {
    console.error("Validate coupon error:", error);
    res.status(500).json({ valid: false, message: "coupon validation failed" });
  }
});

/* -------------------- WEBSITE ANALYTICS -------------------- */

app.post("/api/analytics/event", analyticsRateLimit, (req, res) => {
  try {
    const visitorId = cleanAnalyticsText(req.body.visitorId, 128);
    const sessionId = cleanAnalyticsText(req.body.sessionId, 128);
    const eventType = cleanAnalyticsText(req.body.eventType, 40);
    const eventName = cleanAnalyticsText(req.body.eventName, 80) || null;
    const pageMode = cleanAnalyticsText(req.body.pageMode, 24);
    const pagePath = cleanAnalyticsText(req.body.pagePath || "/", 160) || "/";
    const referrer = cleanAnalyticsText(req.body.referrer || "direct", 120) || "direct";
    const device = cleanAnalyticsText(req.body.device || "unknown", 24) || "unknown";

    if (!visitorId || !sessionId) return res.status(400).json({ error: "Missing analytics identifier." });
    if (!ANALYTICS_EVENT_TYPES.has(eventType)) return res.status(400).json({ error: "Invalid analytics event." });
    if (!ANALYTICS_PAGE_MODES.has(pageMode)) return res.status(400).json({ error: "Invalid page mode." });

    db.prepare(`
      INSERT INTO analytics_events
      (visitor_hash,session_hash,event_type,event_name,page_mode,page_path,referrer,device)
      VALUES (?,?,?,?,?,?,?,?)
    `).run(
      hashAnalyticsId(visitorId),
      hashAnalyticsId(sessionId),
      eventType,
      eventName,
      pageMode,
      pagePath,
      referrer,
      device
    );

    res.status(204).end();
  } catch (error) {
    console.error("Analytics event error:", error);
    res.status(500).json({ error: "Could not record analytics event." });
  }
});

/* -------------------- CHECKOUT + ORDER CREATION -------------------- */

async function createCheckout(req, res) {
  try {
    const items = await buildValidatedItems(req.body.items);
    const subtotalCents = items.reduce((sum, item) => sum + item.lineCents, 0);
    const couponCode = normalizeCode(req.body.couponCode);

    let discountCents = 0;
    let appliedCoupon = null;
    if (couponCode) {
      const validation = validateCouponRecord(getCoupon(couponCode), subtotalCents);
      if (!validation.valid) {
        return res.status(400).json({ error: validation.message || "Invalid coupon." });
      }
      discountCents = validation.discountCents;
      appliedCoupon = validation.code;
    }

    const totalCents = Math.max(0, subtotalCents - discountCents);
    const number = orderNumber();
    const result = db.prepare(`
      INSERT INTO orders
      (order_number,status,items_json,subtotal_cents,discount_cents,total_cents,coupon_code)
      VALUES (?, 'pending_payment', ?, ?, ?, ?, ?)
    `).run(number, JSON.stringify(items), subtotalCents, discountCents, totalCents, appliedCoupon);
    const orderId = Number(result.lastInsertRowid);

    let stripeCouponId = null;
    if (discountCents > 0) {
      const coupon = await stripe.coupons.create({
        duration: "once",
        amount_off: discountCents,
        currency: "eur",
        name: `${appliedCoupon} / ${number}`,
        metadata: { local_coupon_code: appliedCoupon, order_id: String(orderId) },
      });
      stripeCouponId = coupon.id;
    }

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      line_items: items.map((item) => ({ price: item.priceId, quantity: item.quantity })),
      ...(stripeCouponId ? { discounts: [{ coupon: stripeCouponId }] } : {}),
      customer_creation: "always",
      phone_number_collection: { enabled: true },
      shipping_address_collection: { allowed_countries: ["MT"] },
      custom_fields: [
        {
          key: "delivery_notes",
          label: { type: "custom", custom: "Delivery notes" },
          type: "text",
          optional: true,
          text: { maximum_length: 200 },
        },
      ],
      success_url: `${FRONTEND_URL}?checkout=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${FRONTEND_URL}?checkout=cancelled#shop`,
      metadata: {
        brand: "chewi",
        delivery_market: "malta",
        order_id: String(orderId),
        order_number: number,
        coupon_code: appliedCoupon || "",
      },
    });

    db.prepare(`
      UPDATE orders SET stripe_session_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
    `).run(session.id, orderId);

    res.json({ url: session.url, orderNumber: number });
  } catch (error) {
    console.error("Checkout error:", error);
    res.status(500).json({ error: error.message || "Could not create checkout session." });
  }
}

app.post("/api/checkout", createCheckout);
app.post("/create-checkout-session", createCheckout); // backwards compatibility

/* -------------------- ADMIN AUTH -------------------- */

const loginAttempts = new Map();
function loginRateLimit(req, res, next) {
  const key = req.ip || "unknown";
  const now = Date.now();
  const current = loginAttempts.get(key) || { count: 0, resetAt: now + 15 * 60 * 1000 };
  if (now > current.resetAt) {
    current.count = 0;
    current.resetAt = now + 15 * 60 * 1000;
  }
  if (current.count >= 10) {
    return res.status(429).json({ error: "Too many login attempts. Try again later." });
  }
  req.loginRate = { key, current };
  next();
}

app.post("/api/admin/login", loginRateLimit, (req, res) => {
  if (!ADMIN_PASSWORD || !SESSION_SECRET) {
    return res.status(503).json({ error: "Admin login is not configured." });
  }

  const username = String(req.body.username || "");
  const password = String(req.body.password || "");
  const ok = timingSafeEqualString(username, ADMIN_USERNAME) && timingSafeEqualString(password, ADMIN_PASSWORD);

  if (!ok) {
    req.loginRate.current.count += 1;
    loginAttempts.set(req.loginRate.key, req.loginRate.current);
    return res.status(401).json({ error: "Invalid username or password." });
  }

  loginAttempts.delete(req.loginRate.key);
  const csrf = crypto.randomBytes(24).toString("base64url");
  const token = signSession({
    role: "admin",
    username: ADMIN_USERNAME,
    csrf,
    exp: Date.now() + SESSION_TTL_SECONDS * 1000,
  });
  setAdminCookie(res, token);
  res.json({ ok: true });
});

app.get("/api/admin/me", requireAdmin, (req, res) => {
  res.json({ username: req.admin.username, csrf: req.admin.csrf });
});

app.post("/api/admin/logout", requireAdmin, requireCsrf, (_req, res) => {
  clearAdminCookie(res);
  res.json({ ok: true });
});

/* -------------------- ADMIN DASHBOARD -------------------- */

app.get("/api/admin/dashboard", requireAdmin, (req, res) => {
  const totalOrders = db.prepare("SELECT COUNT(*) AS n FROM orders").get().n;
  const paidOrders = db.prepare("SELECT COUNT(*) AS n FROM orders WHERE status IN ('paid','processing','fulfilled')").get().n;
  const pendingOrders = db.prepare("SELECT COUNT(*) AS n FROM orders WHERE status = 'pending_payment'").get().n;
  const revenueCents = db.prepare("SELECT COALESCE(SUM(total_cents),0) AS n FROM orders WHERE status IN ('paid','processing','fulfilled')").get().n;
  const todayOrders = db.prepare("SELECT COUNT(*) AS n FROM orders WHERE date(created_at) = date('now')").get().n;
  const activeCoupons = db.prepare("SELECT COUNT(*) AS n FROM coupons WHERE active = 1").get().n;
  res.json({ totalOrders, paidOrders, pendingOrders, revenueCents, todayOrders, activeCoupons });
});

app.get("/api/admin/analytics", requireAdmin, (_req, res) => {
  try {
    const summary = db.prepare(`
      SELECT
        COUNT(CASE WHEN event_type = 'page_view' AND date(created_at) = date('now') THEN 1 END) AS viewsToday,
        COUNT(DISTINCT CASE WHEN event_type = 'page_view' AND date(created_at) = date('now') THEN visitor_hash END) AS visitorsToday,
        COUNT(CASE WHEN event_type = 'page_view' AND created_at >= datetime('now','-7 days') THEN 1 END) AS views7d,
        COUNT(DISTINCT CASE WHEN event_type = 'page_view' AND created_at >= datetime('now','-7 days') THEN visitor_hash END) AS visitors7d,
        COUNT(CASE WHEN event_type = 'page_view' AND created_at >= datetime('now','-30 days') THEN 1 END) AS views30d,
        COUNT(DISTINCT CASE WHEN event_type = 'page_view' AND created_at >= datetime('now','-30 days') THEN visitor_hash END) AS visitors30d,
        COUNT(DISTINCT CASE WHEN event_type = 'page_view' THEN visitor_hash END) AS visitorsAll
      FROM analytics_events
    `).get();

    const daily = db.prepare(`
      WITH RECURSIVE days(day) AS (
        SELECT date('now','-6 days')
        UNION ALL
        SELECT date(day,'+1 day') FROM days WHERE day < date('now')
      )
      SELECT days.day,
        COUNT(a.id) AS views,
        COUNT(DISTINCT a.visitor_hash) AS visitors
      FROM days
      LEFT JOIN analytics_events a
        ON date(a.created_at) = days.day AND a.event_type = 'page_view'
      GROUP BY days.day
      ORDER BY days.day
    `).all();

    const modes = db.prepare(`
      SELECT page_mode AS mode, COUNT(*) AS views, COUNT(DISTINCT visitor_hash) AS visitors
      FROM analytics_events
      WHERE event_type = 'page_view' AND created_at >= datetime('now','-30 days')
      GROUP BY page_mode ORDER BY views DESC
    `).all();

    const devices = db.prepare(`
      SELECT device, COUNT(*) AS views, COUNT(DISTINCT visitor_hash) AS visitors
      FROM analytics_events
      WHERE event_type = 'page_view' AND created_at >= datetime('now','-30 days')
      GROUP BY device ORDER BY views DESC
    `).all();

    const referrers = db.prepare(`
      SELECT referrer, COUNT(*) AS views
      FROM analytics_events
      WHERE event_type = 'page_view' AND created_at >= datetime('now','-30 days')
      GROUP BY referrer ORDER BY views DESC LIMIT 8
    `).all();

    const events = db.prepare(`
      SELECT event_type AS eventType, COUNT(*) AS count
      FROM analytics_events
      WHERE created_at >= datetime('now','-30 days')
      GROUP BY event_type ORDER BY count DESC
    `).all();

    const products = db.prepare(`
      SELECT event_name AS name,
        SUM(CASE WHEN event_type = 'product_view' THEN 1 ELSE 0 END) AS views,
        SUM(CASE WHEN event_type = 'add_to_bag' THEN 1 ELSE 0 END) AS adds
      FROM analytics_events
      WHERE event_name IS NOT NULL
        AND event_type IN ('product_view','add_to_bag')
        AND created_at >= datetime('now','-30 days')
      GROUP BY event_name
      ORDER BY views DESC, adds DESC
      LIMIT 8
    `).all();

    const recent = db.prepare(`
      SELECT event_type AS eventType,event_name AS eventName,page_mode AS pageMode,
             page_path AS pagePath,referrer,device,created_at AS createdAt
      FROM analytics_events
      ORDER BY id DESC LIMIT 20
    `).all();

    res.json({ summary, daily, modes, devices, referrers, events, products, recent });
  } catch (error) {
    console.error("Admin analytics error:", error);
    res.status(500).json({ error: "Could not load website analytics." });
  }
});

app.get("/api/admin/orders", requireAdmin, (req, res) => {
  const q = String(req.query.q || "").trim();
  const status = String(req.query.status || "all").trim();
  const params = [];
  const where = [];

  if (q) {
    where.push("(order_number LIKE ? OR customer_email LIKE ? OR customer_name LIKE ?)");
    const like = `%${q}%`;
    params.push(like, like, like);
  }
  if (status !== "all" && ALLOWED_ORDER_STATUSES.has(status)) {
    where.push("status = ?");
    params.push(status);
  }

  const rows = db.prepare(`
    SELECT * FROM orders
    ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
    ORDER BY id DESC LIMIT 500
  `).all(...params);

  res.json({ orders: rows.map(hydrateOrder) });
});

app.patch("/api/admin/orders/:id", requireAdmin, requireCsrf, (req, res) => {
  const id = Number(req.params.id);
  const status = String(req.body.status || "");
  const notes = String(req.body.notes || "").slice(0, 5000);
  if (!Number.isInteger(id) || id < 1) return res.status(400).json({ error: "Invalid order id." });
  if (!ALLOWED_ORDER_STATUSES.has(status)) return res.status(400).json({ error: "Invalid order status." });
  const result = db.prepare(`
    UPDATE orders SET status = ?, notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
  `).run(status, notes, id);
  if (!result.changes) return res.status(404).json({ error: "Order not found." });
  res.json({ order: hydrateOrder(db.prepare("SELECT * FROM orders WHERE id = ?").get(id)) });
});

app.post("/api/admin/orders/:id/refund", requireAdmin, requireCsrf, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const order = db.prepare("SELECT * FROM orders WHERE id = ?").get(id);
    if (!order) return res.status(404).json({ error: "Order not found." });
    if (!order.stripe_payment_intent) return res.status(400).json({ error: "This order has no Stripe payment intent." });
    if (order.status === "refunded") return res.status(400).json({ error: "Order is already refunded." });

    const refund = await stripe.refunds.create({ payment_intent: order.stripe_payment_intent });
    db.prepare(`UPDATE orders SET status = 'refunded', updated_at = CURRENT_TIMESTAMP WHERE id = ?`).run(id);
    res.json({ ok: true, refundId: refund.id });
  } catch (error) {
    console.error("Refund error:", error);
    res.status(500).json({ error: error.message || "Refund failed." });
  }
});

app.get("/api/admin/orders.csv", requireAdmin, (req, res) => {
  const rows = db.prepare("SELECT * FROM orders ORDER BY id DESC").all();
  const esc = (value) => `"${String(value == null ? "" : value).replace(/"/g, '""')}"`;
  const lines = [
    ["order_number","status","customer_name","customer_email","customer_phone","subtotal","discount","total","coupon","created_at"].join(","),
    ...rows.map((row) => [
      row.order_number,row.status,row.customer_name,row.customer_email,row.customer_phone,
      (row.subtotal_cents/100).toFixed(2),(row.discount_cents/100).toFixed(2),(row.total_cents/100).toFixed(2),row.coupon_code,row.created_at,
    ].map(esc).join(",")),
  ];
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="chewi-orders.csv"`);
  res.send(lines.join("\n"));
});

/* -------------------- ADMIN COUPONS -------------------- */

app.get("/api/admin/coupons", requireAdmin, (req, res) => {
  const coupons = db.prepare("SELECT * FROM coupons ORDER BY id DESC").all().map((c) => ({ ...c, active: Boolean(c.active) }));
  res.json({ coupons });
});

app.post("/api/admin/coupons", requireAdmin, requireCsrf, (req, res) => {
  try {
    const code = normalizeCode(req.body.code);
    const type = String(req.body.type || "");
    const value = Number(req.body.value);
    const minSubtotalCents = moneyToCents(req.body.minSubtotal || 0);
    const maxUses = Number(req.body.maxUses || 0);
    const expiresAt = req.body.expiresAt ? new Date(req.body.expiresAt).toISOString() : null;

    if (!code || code.length > 32) return res.status(400).json({ error: "Invalid coupon code." });
    if (!new Set(["percent", "fixed"]).has(type)) return res.status(400).json({ error: "Invalid coupon type." });
    if (!Number.isFinite(value) || value <= 0) return res.status(400).json({ error: "Coupon value must be positive." });
    if (type === "percent" && value > 100) return res.status(400).json({ error: "Percentage cannot exceed 100%." });
    if (minSubtotalCents === null) return res.status(400).json({ error: "Invalid minimum subtotal." });
    if (!Number.isInteger(maxUses) || maxUses < 0) return res.status(400).json({ error: "Invalid usage limit." });

    db.prepare(`
      INSERT INTO coupons (code,type,value,min_subtotal_cents,max_uses,active,expires_at)
      VALUES (?,?,?,?,?,1,?)
      ON CONFLICT(code) DO UPDATE SET
        type=excluded.type,
        value=excluded.value,
        min_subtotal_cents=excluded.min_subtotal_cents,
        max_uses=excluded.max_uses,
        expires_at=excluded.expires_at,
        updated_at=CURRENT_TIMESTAMP
    `).run(code, type, value, minSubtotalCents, maxUses, expiresAt);

    res.json({ coupon: db.prepare("SELECT * FROM coupons WHERE code = ?").get(code) });
  } catch (error) {
    console.error("Save coupon error:", error);
    res.status(500).json({ error: "Could not save coupon." });
  }
});

app.patch("/api/admin/coupons/:id", requireAdmin, requireCsrf, (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ error: "Invalid coupon id." });
    }

    const existing = db.prepare("SELECT * FROM coupons WHERE id = ?").get(id);
    if (!existing) {
      return res.status(404).json({ error: "Coupon not found." });
    }

    // Backwards compatible: callers can still send only { active: true/false }.
    const type =
      req.body.type === undefined ? existing.type : String(req.body.type || "");

    const value =
      req.body.value === undefined ? Number(existing.value) : Number(req.body.value);

    const minSubtotalCents =
      req.body.minSubtotal === undefined
        ? Number(existing.min_subtotal_cents)
        : moneyToCents(req.body.minSubtotal);

    const maxUses =
      req.body.maxUses === undefined
        ? Number(existing.max_uses)
        : Number(req.body.maxUses);

    let expiresAt = existing.expires_at;
    if (Object.prototype.hasOwnProperty.call(req.body, "expiresAt")) {
      expiresAt = req.body.expiresAt
        ? new Date(req.body.expiresAt).toISOString()
        : null;
    }

    const active =
      req.body.active === undefined
        ? Number(existing.active)
        : (req.body.active ? 1 : 0);

    if (!new Set(["percent", "fixed"]).has(type)) {
      return res.status(400).json({ error: "Invalid coupon type." });
    }

    if (!Number.isFinite(value) || value <= 0) {
      return res.status(400).json({ error: "Coupon value must be positive." });
    }

    if (type === "percent" && value > 100) {
      return res.status(400).json({ error: "Percentage cannot exceed 100%." });
    }

    if (minSubtotalCents === null) {
      return res.status(400).json({ error: "Invalid minimum subtotal." });
    }

    if (!Number.isInteger(maxUses) || maxUses < 0) {
      return res.status(400).json({ error: "Invalid usage limit." });
    }

    if (expiresAt && Number.isNaN(new Date(expiresAt).getTime())) {
      return res.status(400).json({ error: "Invalid expiry date." });
    }

    db.prepare(`
      UPDATE coupons SET
        type = ?,
        value = ?,
        min_subtotal_cents = ?,
        max_uses = ?,
        active = ?,
        expires_at = ?,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(
      type,
      value,
      minSubtotalCents,
      maxUses,
      active,
      expiresAt,
      id
    );

    const coupon = db.prepare("SELECT * FROM coupons WHERE id = ?").get(id);
    res.json({ coupon: { ...coupon, active: Boolean(coupon.active) } });
  } catch (error) {
    console.error("Update coupon error:", error);
    res.status(500).json({ error: "Could not update coupon." });
  }
});

app.delete("/api/admin/coupons/:id", requireAdmin, requireCsrf, (req, res) => {
  const id = Number(req.params.id);
  const result = db.prepare("DELETE FROM coupons WHERE id = ?").run(id);
  if (!result.changes) return res.status(404).json({ error: "Coupon not found." });
  res.json({ ok: true });
});

/* -------------------- ERROR HANDLER -------------------- */

app.use((error, _req, res, _next) => {
  if (error && error.message === "Not allowed by CORS") {
    return res.status(403).json({ error: "Origin not allowed." });
  }
  console.error("Unhandled server error:", error);
  res.status(500).json({ error: "Internal server error." });
});

app.listen(PORT, () => {
  console.log(`CHEWI API running on port ${PORT}`);
  console.log(`Database: ${APP_DB_PATH}`);
  console.log(`Admin: /admin`);
});
