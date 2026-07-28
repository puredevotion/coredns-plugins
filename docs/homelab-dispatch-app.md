# Setup: reusing homelab's `homelab-arc` GitHub App for release dispatch

What `release-please.yml`'s "notify homelab of new release" step needs to
actually fire. Reuses the **existing** `homelab-arc` GitHub App (see
homelab's `docs/arc-github-app.md`) instead of creating a second App — it's
already installed on `puredevotion/homelab` and nowhere else, which is
exactly the scope this needs too.

## Why reuse instead of a new App

- Same target repo, same "only homelab" installation scope — no new
  installation decision to make.
- One fewer App to track/rotate/remember exists.
- GitHub Apps support multiple concurrent private keys per App, so this
  doesn't require extracting or reusing the *same key bytes* ARC depends on
  (which live in sops, `secrets/common.yaml`'s `arc.github_app_*`, and feed
  an in-cluster Secret) — a second key can be generated for this use alone,
  independently revocable without touching ARC's.

**Tradeoff, stated plainly:** this does widen what the `homelab-arc`
identity *can* do if a key is ever compromised — Contents:Read/write gets
added alongside its existing Administration:Read/write. In practice this
doesn't move the risk tier much (Administration already allows far more —
managing collaborators, branch protection, repo settings — than Contents
does), but it's a real increment worth naming rather than silently
accepting.

## 1. Add the Contents permission to `homelab-arc`

GitHub → Settings → Developer settings → GitHub Apps → `homelab-arc` →
Permissions & events → **Repository permissions → Contents: Read and
write** → Save changes.

This is a permission *upgrade* on an already-installed App — GitHub will
ask you to review and accept the new permission on the installation (a
one-time click-through, not a reinstall).

## 2. Generate a second private key

Same App's page → Private keys → Generate a private key → downloads a new
`.pem`. This is additional to (not a replacement for) the key ARC already
uses from sops — both stay valid simultaneously. Treat the download like
any other private key; delete the local copy once it's in the repo secret
below.

Note the **App ID** or **Client ID** shown near the top of the same page —
either works with `create-github-app-token` (`client-id` is the input name
this repo's workflow uses; the numeric App ID is also accepted as a legacy
`app-id` value if that's easier to read off the sops value instead — see
homelab's `secrets/common.yaml` `arc.github_app_id` for that number, no need
to open the GitHub UI just for this one value).

## 3. Installation — nothing to do

Already installed on `puredevotion/homelab` only, per `arc-github-app.md`'s
own setup. Adding a permission to an existing installation doesn't change
what repos it's installed on.

## 4. Add to coredns-plugins' repo settings

`puredevotion/coredns-plugins` → Settings → Secrets and variables →
Actions:

- **Variables tab** → New repository variable →
  `HOMELAB_DISPATCH_APP_CLIENT_ID` = the App ID or Client ID from step 2.
  (Not secret by itself — insufficient to authenticate as anything without
  the private key.)
- **Secrets tab** → New repository secret →
  `HOMELAB_DISPATCH_APP_PRIVATE_KEY` = the full contents of the *new*
  `.pem` from step 2 (not the one in sops), unmodified.

## Verify

Once both are set, the next real release-please release (a merged
"chore(main): release X.Y.Z" PR) should show the "mint homelab-scoped
installation token" and "notify homelab of new release" steps actually run
instead of the `::warning::` skip. Check for a new
`chore/coredns-plugins-bump-<rev>` PR opening on homelab shortly after.

Until this is set up, the workflow degrades gracefully: it logs a warning
and release-please itself still completes normally — flake.lock just needs
a manual bump in the meantime, same as before any of this existed.

## If you'd rather isolate blast radius instead

If the permission-widening tradeoff above isn't acceptable on reflection,
the alternative is a dedicated second App scoped to Contents-only — same
mechanics as above, just "New GitHub App" instead of editing `homelab-arc`,
and its own separate installation on `homelab`. Nothing else in this setup
changes either way; only where the Client ID / private key come from.
