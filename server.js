require("dotenv").config();

const path = require("path");
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
const FRONTEND_URL =
  process.env.FRONTEND_URL || "http://localhost:3000";

const PRICE_IDS = {
  sensation: process.env.SENSATION_PRICE_ID,
  blackout: process.env.BLACKOUT_PRICE_ID,
  sunday: process.env.SUNDAY_PRICE_ID,
  crush: process.env.CRUSH_PRICE_ID,
  stardust: process.env.STARDUST_PRICE_ID,
  "velvet riot": process.env.VELVET_RIOT_PRICE_ID,
};

const ALLOWED_FLAVOURS = new Set([
  "sensation",
  "blackout",
  "sunday",
  "crush",
  "stardust",
  "velvet riot",
]);

// On Render, set REVIEW_DB_PATH to a mounted persistent disk path later,
// e.g. /var/data/reviews.db. For local testing this defaults to reviews.db
// in the project folder.
const REVIEW_DB_PATH =
  process.env.REVIEW_DB_PATH || path.join(__dirname, "reviews.db");

const db = new Database(REVIEW_DB_PATH);

db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    flavour TEXT NOT NULL,
    rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
    message TEXT NOT NULL,
    verified_purchase INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )
`);

app.use(
  cors({
    origin(origin, callback) {
      // Allow browser requests from the configured frontend and requests
      // without an Origin header (e.g. curl/Postman/server-to-server).
      if (!origin || origin === FRONTEND_URL) {
        return callback(null, true);
      }

      return callback(new Error("Not allowed by CORS"));
    },
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type"],
  })
);

app.use(express.json({ limit: "50kb" }));

app.get("/", (_req, res) => {
  res.json({ ok: true, service: "chewi-api" });
});

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

/* -------------------- REVIEWS -------------------- */

app.get("/reviews", (req, res) => {
  try {
    const flavour =
      typeof req.query.flavour === "string"
        ? req.query.flavour.toLowerCase().trim()
        : "";

    let rows;

    if (flavour && ALLOWED_FLAVOURS.has(flavour)) {
      rows = db
        .prepare(`
          SELECT
            id,
            name,
            flavour,
            rating,
            message,
            verified_purchase AS verifiedPurchase,
            created_at AS createdAt
          FROM reviews
          WHERE flavour = ?
          ORDER BY id DESC
          LIMIT 100
        `)
        .all(flavour);
    } else {
      rows = db
        .prepare(`
          SELECT
            id,
            name,
            flavour,
            rating,
            message,
            verified_purchase AS verifiedPurchase,
            created_at AS createdAt
          FROM reviews
          ORDER BY id DESC
          LIMIT 100
        `)
        .all();
    }

    const reviews = rows.map((review) => ({
      ...review,
      verifiedPurchase: Boolean(review.verifiedPurchase),
    }));

    res.json({ reviews });
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
      return res
        .status(400)
        .json({ error: "Name must be between 1 and 40 characters." });
    }

    if (!ALLOWED_FLAVOURS.has(flavour)) {
      return res.status(400).json({ error: "Invalid cookie flavour." });
    }

    if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
      return res
        .status(400)
        .json({ error: "Rating must be a whole number from 1 to 5." });
    }

    if (message.length < 2 || message.length > 280) {
      return res
        .status(400)
        .json({ error: "Review must be between 2 and 280 characters." });
    }

    const result = db
      .prepare(`
        INSERT INTO reviews (name, flavour, rating, message)
        VALUES (?, ?, ?, ?)
      `)
      .run(name, flavour, rating, message);

    const review = db
      .prepare(`
        SELECT
          id,
          name,
          flavour,
          rating,
          message,
          verified_purchase AS verifiedPurchase,
          created_at AS createdAt
        FROM reviews
        WHERE id = ?
      `)
      .get(result.lastInsertRowid);

    res.status(201).json({
      review: {
        ...review,
        verifiedPurchase: Boolean(review.verifiedPurchase),
      },
    });
  } catch (error) {
    console.error("Create review error:", error);
    res.status(500).json({ error: "Could not save review." });
  }
});

/* -------------------- STRIPE CHECKOUT -------------------- */

app.post("/create-checkout-session", async (req, res) => {
  try {
    const { items } = req.body;

    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: "Your bag is empty." });
    }

    const lineItems = items.map((item) => {
      const name = String(item.name || "").toLowerCase().trim();
      const quantity = Number(item.quantity);

      if (!PRICE_IDS[name]) {
        throw new Error(`Unknown product: ${name}`);
      }

      if (!Number.isInteger(quantity) || quantity < 1 || quantity > 20) {
        throw new Error(`Invalid quantity for ${name}`);
      }

      return {
        price: PRICE_IDS[name],
        quantity,
      };
    });

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      line_items: lineItems,
      customer_creation: "always",
      phone_number_collection: { enabled: true },
      shipping_address_collection: {
        allowed_countries: ["MT"],
      },
      custom_fields: [
        {
          key: "delivery_notes",
          label: {
            type: "custom",
            custom: "Delivery notes",
          },
          type: "text",
          optional: true,
          text: { maximum_length: 200 },
        },
      ],
      success_url: `${FRONTEND_URL}?checkout=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${FRONTEND_URL}?checkout=cancelled#shop-anchor`,
      metadata: {
        brand: "chewi",
        delivery_market: "malta",
      },
    });

    res.json({ url: session.url });
  } catch (error) {
    console.error("Checkout error:", error);
    res.status(500).json({
      error: error.message || "Could not create checkout session.",
    });
  }
});

app.listen(PORT, () => {
  console.log(`CHEWI API running on port ${PORT}`);
  console.log(`Review database: ${REVIEW_DB_PATH}`);
});
