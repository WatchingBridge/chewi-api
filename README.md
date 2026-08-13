# CHEWI API

Small Node/Express backend for sending the CHEWI cart to Stripe Checkout.

## What it does
- Creates Stripe Checkout Sessions
- Uses Stripe Price IDs for all six CHEWI cookies
- Collects customer email
- Collects customer phone number
- Collects a Malta delivery address only
- Adds an optional delivery-notes field
- Returns the Stripe-hosted checkout URL to the CHEWI website

## Render setup
Create a **Web Service** from this repository.

Use:
- Runtime: Node
- Build command: `npm install`
- Start command: `npm start`

## Environment variables in Render
Add:
- `STRIPE_SECRET_KEY`
- `SENSATION_PRICE_ID`
- `BLACKOUT_PRICE_ID`
- `SUNDAY_PRICE_ID`
- `CRUSH_PRICE_ID`
- `STARDUST_PRICE_ID`
- `VELVET_RIOT_PRICE_ID`
- `FRONTEND_URL`

Your real `sk_live_...` belongs only in Render. Never commit it to GitHub or put it in frontend JavaScript.

## API request
POST `/create-checkout-session`

Example:
```json
{
  "items": [
    { "name": "sensation", "quantity": 2 },
    { "name": "crush", "quantity": 1 }
  ]
}
```

The response contains a Stripe Checkout `url`. Redirect the browser to it.

## Before launch
This version does not add a delivery fee yet. Add that once you decide your Malta delivery pricing.
