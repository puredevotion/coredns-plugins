# Setup: the homelab release App

`release.yml`'s `deploy` job pushes the new image tag straight to
`puredevotion/homelab` main (homelab's `ci/release/deploy-image.sh`), using an
installation token minted from the homelab dispatch App
(`actions/create-github-app-token`, `repositories: homelab`).

## App

The App needs **Contents: Read and write** on `puredevotion/homelab` and must be
installed there. It never needs access to this repository, and nothing here
touches homelab's `.github/`, so no Workflows permission.

This repo historically reused the `homelab-arc` App (which also carries
Administration for ARC). A dedicated Contents-only App narrows the blast
radius of a leaked key; nothing in this workflow changes either way.

## This repository

Settings → Environments → `homelab-release`:

- variable `HOMELAB_DISPATCH_APP_CLIENT_ID` = the App's Client ID;
- secret `HOMELAB_DISPATCH_APP_PRIVATE_KEY` = a private key generated for this
  use (Apps allow several; revoke it independently).

Only `release.yml` names that environment, and it runs on pushes to `main`
only, so fork pull requests never see the key. Restrict the environment's
deployment branches to `main` as well.

## ghcr.io

The first release creates `ghcr.io/puredevotion/coredns-plugins`. Make the
package **public** (Package settings → Change visibility): homelab's Zot pulls
it anonymously on first use.

## Verify

After a merge that touches a plugin: a `vX.Y.Z` tag, a GitHub Release, the
package version on ghcr.io, and a `deploy(coredns-plugins): X.Y.Z` commit on
homelab main by the App's bot.
