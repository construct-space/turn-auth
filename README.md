# turn-auth - ephemeral TURN credential service for Construct Meet

Mints short-lived TURN credentials using the coturn `use-auth-secret` (TURN
REST API) scheme. The shared secret stays server-side; Meet fetches a fresh
credential before each call. Pairs with the `turn` (coturn) app, which
validates these credentials with the same secret.

```
username   = "<unix-expiry>"[:"<user-id>"]
credential = base64( HMAC-SHA1( TURN_SHARED_SECRET, username ) )
```

## API

`GET /credentials` (auth-gated by the gateway at `/api/turn/credentials`):

```json
{
  "username": "1748620800:u_abc",
  "credential": "base64hmac...",
  "ttl": 86400,
  "realm": "turn.lisaos.dev",
  "iceServers": [
    { "urls": ["stun:turn.lisaos.dev:3478"] },
    { "urls": ["turn:turn.lisaos.dev:3478?transport=udp",
               "turn:turn.lisaos.dev:3478?transport=tcp",
               "turns:turn.lisaos.dev:5349"],
      "username": "1748620800:u_abc", "credential": "base64hmac..." }
  ]
}
```

Meet uses `iceServers` verbatim in its `RTCConfiguration`.

`GET /health` -> `{ "ok": true }`.

## Deploy (CapRover)

1. Create app `turn-auth`. Deploy this folder (`caprover deploy --appName turn-auth`).
2. Env vars:
   ```
   TURN_SHARED_SECRET=<SAME value as the turn/coturn app>
   TURN_REALM=turn.lisaos.dev
   TURN_TTL_SECONDS=86400
   TURN_URLS=stun:turn.lisaos.dev:3478,turn:turn.lisaos.dev:3478?transport=udp,turn:turn.lisaos.dev:3478?transport=tcp,turns:turn.lisaos.dev:5349
   INTERNAL_SHARED_SECRET=<same as the gateway, so only the gateway can call this>
   ```
3. The gateway (`my`) routes `/api/turn/credentials` here, auth-gated. No
   public domain needed on this app.

## Security

- Secret never leaves the server; credentials expire after `TTL`.
- `INTERNAL_SHARED_SECRET` rejects any request that didn't come through the
  authenticated gateway edge.
- `X-Auth-User-ID` (set by the gateway) is folded into the username for abuse
  attribution; coturn HMACs the whole string so it stays valid.
