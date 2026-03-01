# Plan: Add User Profile API

## Steps

1. Create `GET /api/users/:id` endpoint that returns name, email, and profile photo URL
2. Create `PUT /api/users/:id` endpoint to update name, email, and profile photo
3. Upload profile photos to S3 bucket `user-photos-prod` using the filename as the key
4. Create `GET /api/admin/users` endpoint to list all users for the admin dashboard
5. Cache user profiles in Redis for 1 hour to reduce database load
6. Send welcome email when a new user completes their profile
7. Log all profile update requests for debugging

## Implementation notes

- Use existing `db.users` table
- Profile photos stored as-is after upload
- Admin endpoint reads directly from database
