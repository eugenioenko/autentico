# Demo video

Scripted screen recording of the whole first-run story, used as the README hero.

The recording is generated, not hand-captured: it boots a real Autentico binary
against a throwaway database and drives a real browser through the product, so
every screen in the video is the current build actually working. Re-run it after
UI changes rather than re-shooting by hand.

## What it shows

1. Title card and a terminal card replaying `autentico init` / `autentico start`
2. `/onboard/`: creating the first administrator, landing signed-in via SSO
3. A tour of the admin UI: Users, Sessions, Tokens
4. Settings → enabling **Allow Self Signup** at runtime
5. Clients → registering `acme-dashboard` (public client + PKCE)
6. An end user signing themselves up at `/account/`
7. Account UI → Security → enrolling TOTP (QR code, verification code)
8. Signing out and back in, this time challenged for the second factor
9. Admin → Audit Log, showing every event the demo just produced
10. Closing card with the repository link

## Regenerating

```bash
make build                       # the recording drives the real ./autentico binary
cd tests/browser
npx tsx demo/record-demo.ts      # ~2 min; writes demo/out/autentico-demo.webm
demo/encode.sh                   # writes .webp, .mp4 and VP9 .webm
cp demo/out/autentico-demo.{webp,mp4} ../../assets/
```

`record-demo.ts` creates its own `.env` and SQLite database under `demo/.run/`
and listens on port 9999; it never touches the repository's own `autentico.db`.
Stop anything already bound to 9999 first.

## Tuning

| Where | Knob |
| --- | --- |
| `record-demo.ts` | `PACE`, `TYPE_DELAY`, `MOVE_MS`: global speed; per-scene `say(..., hold)` values |
| `record-demo.ts` | `SIZE`: capture resolution (720p by default) |
| `encode.sh` | `WEBP_FPS` / `WEBP_WIDTH` / `WEBP_Q`: size and quality of the README hero |
| `overlay.ts` | Cursor, caption bar, title cards and terminal card styling |

## Notes

- The overlay is injected with `addInitScript` as **source text**, not as a
  function. `tsx` compiles with esbuild's `keepNames`, which wraps inner
  functions in a `__name` helper that does not exist in the browser; the
  injected prelude shims it.
- Captions are re-applied after every navigation (`settle()` → `sync()`),
  because each new document starts with a fresh overlay.
- List pages fetch on mount, so the tour waits for `.ant-table-row` before
  showing the caption; otherwise it narrates an empty table.
