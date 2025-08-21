# Okta Secure CRUD API (no DB)

This API enforces **role/scope-based** access using:

- **Client Credentials (M2M)** → scopes `read` / `write` / `delete`
- **“Basic” via ROPC** → Okta Groups (`ReadUsers` / `WriteUsers` / `DeleteUsers`) mapped to roles

## 1) Configure .env

Already filled for your org. Update only if values change.

## 2) Install & Run

```bash
npm i
npm run dev   # or: npm start
# API on http://localhost:3000
```

## 3) Basic Auth with Okta (MFA aware)

Use HTTP Basic Auth in Postman or curl. The server will call Okta AuthN API and, if MFA is required, automatically initiate Okta Verify Push and poll until you approve on your device.

- Username: your Okta username (e.g. `user@example.com`)
- Password: your Okta password

If the user has no Okta Verify Push factor, the API returns 401 with details.

Group-to-scope mapping (Okta Groups → API scope):

- ReadUsers → `read`
- WriteUsers → `write`
- DeleteUsers → `delete`

Ensure your user is assigned to exactly one of these groups.

To test quickly without Okta, hardcoded users exist:

- `readuser:readpass` → ReadUsers
- `writeuser:writepass` → WriteUsers
- `deleteuser:deletepass` → DeleteUsers

## 4) Check our API

Once the server is running, you can test the API using tools like [curl](https://curl.se/) or [Postman](https://www.postman.com/).

- **Base URL:** `http://localhost:3000`
- **Authentication:** Use either Client Credentials (for M2M) or Basic Auth (for ROPC) as described above.
- **Example request:**
  ```bash
  curl -H "Authorization: Bearer <your_access_token>" http://localhost:3000/your-endpoint
  ```

Replace `<your_access_token>` with a valid token.

## 5) Test the API

Here are example `curl` commands for each operation (replace `<token>` as needed):

- **Health check**

  ```bash
  curl http://localhost:3000/health
  ```

- **List items (Bearer)**

  ```bash
  curl -H "Authorization: Bearer <token>" http://localhost:3000/items
  ```

- **Get item by ID (Bearer)**

  ```bash
  curl -H "Authorization: Bearer <token>" http://localhost:3000/items/1
  ```

- **Create item (Bearer)**

  ```bash
  curl -X POST -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d '{"name":"Item Name"}' http://localhost:3000/items
  ```

- **Update item (Bearer)**

  ```bash
  curl -X PUT -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d '{"name":"New Name"}' http://localhost:3000/items/1
  ```

  ```bash
  curl -X DELETE -H "Authorization: Bearer <token>" http://localhost:3000/items/1
  ```

- **List items (Basic with MFA)**
  ```bash
  curl -H "Authorization: Basic $(printf 'user@example.com:password' | base64)" http://localhost:3000/items
  # Approve push on your Okta Verify app
  ```

## Role/Scope Permissions

- **ReadUsers** group or `read` scope: can only GET items.
- **WriteUsers** group or `write` scope: can only POST/PUT items (cannot delete).
- **DeleteUsers** group or `delete` scope: can only DELETE items.

Each user/client should only be assigned to one group/scope for exclusive access.

## Service Requirements

- Standalone API application.
- Authenticates using Okta JWT (Client Credentials) or Basic Auth (ROPC).
- Enforces scope-based access control (`read` for GET, `write` for POST/PUT/DELETE).
- Exposes CRUD endpoints for `/items`.
- Health check at `/health` (no auth required).
- Rejects invalid/expired credentials or insufficient scopes.
- All configuration is via `.env`.
- Logs requests and errors (no sensitive info).
- Supports admin (Basic) and client (JWT) access in parallel.
- Secure by default; all endpoints except `/health` require authentication.

## Troubleshooting 401 Unauthorized

- Ensure you are using a valid **access token** (not ID token) from Okta.
- The token must have the correct `aud` (audience) and required `scp` (scope) for the endpoint.
- Use the correct OAuth2 flow (Client Credentials for M2M, ROPC for Basic).
- Double-check the `Authorization: Bearer <token>` header in Postman.
- Decode your token at [jwt.io](https://jwt.io/) to inspect claims.
- Check API logs for more details on the error.

For Basic + MFA:
- Make sure the user is enrolled in Okta Verify Push.
- Approve the push within ~90 seconds.
- If you see "MFA required but no Push factor", enroll Push or adjust policy.
