require("dotenv").config();

const express = require("express");
const cors = require("cors");
const Stripe = require("stripe");

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

app.use(
  cors({
    origin: FRONTEND_URL,
    methods: ["GET", "POST"],
  })
);

app.use(express.json());

app.get("/", (_req, res) => {
  res.json({ ok: true, service: "chewi-api" });
});

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

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
});
