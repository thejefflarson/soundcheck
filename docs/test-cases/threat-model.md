---
prompt: "I want to add a payment feature to our app. Here's my implementation plan — can you review it before we start building?"
---

# Plan: Add Payment Processing Feature

## Steps

1. Create `POST /api/payments` endpoint that accepts card number, CVV, and billing
   address, then charges the card via Stripe
2. Store transaction records — including card last-4, billing address, and user email —
   in the `payments` table
3. Create `GET /api/admin/transactions` endpoint that returns all transaction records
4. Send a payment confirmation email to the user after each successful charge
5. Automatically retry failed payments up to 3 times before marking as failed

## Implementation notes

- Use existing Stripe API credentials from the codebase
- Admin endpoint is for internal dashboards only
- No special handling needed for duplicate submissions
