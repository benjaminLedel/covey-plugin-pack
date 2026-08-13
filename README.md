# covey-plugin-pack

Manifest plugins for [Covey](https://github.com/benjaminLedel/covey) — target systems an agent can work in, described as JSON rather than compiled into the binary.

This repository **hosts the plugins**. It is not the catalogue: the catalogue is [covey-plugins](https://github.com/benjaminLedel/covey-plugins), which points at the files here and pins each version by digest. That split is the point — a plugin lives with its author, and the index only says where.

## What is in here

| Plugin | System | Actions |
|---|---|---|
| [`plugins/redmine.json`](plugins/redmine.json) | Redmine | find, read, comment, update, create issues |
| [`plugins/gitea.json`](plugins/gitea.json) | Gitea / Forgejo | find and read issues and pull requests, comment, label, close, see a PR's files |
| [`plugins/openproject.json`](plugins/openproject.json) | OpenProject | find and read work packages, comment, move through status |

All three are self-hostable and authenticate with a token in a header, which is what a manifest plugin can express. Each declares the optional capabilities too: a `probe` (so the store can test the connection), a `poll` (so `nur-wenn:` in `HEARTBEAT.md` gates on real work), a `scopes` vocabulary for `ACCESS.md`, and per-action `doc` lines so the prompt documentation can be narrowed to what an agent may actually do.

## Installing

Do not copy these files by hand. Install them from the catalogue — the store's **Catalogue** tab under Target systems — so that the digest is verified and the version is recorded. A plugin arrives disabled; storing credentials and switching it on stay separate, deliberate steps.

Credentials follow Covey's convention, stored under Secrets and assigned to the agent:

| Plugin | `<name>_url` | `<name>_token` |
|---|---|---|
| redmine | `https://redmine.example.com` | the API key from *My account → API access key* |
| gitea | `https://git.example.com` | a personal access token with the scopes you want it to have |
| openproject | `https://op.example.com` | base64 of `apikey:<your-api-key>` (OpenProject uses HTTP Basic) |

## Status: untested against live systems

These manifests are written from each system's published API documentation. They lint clean, and their shape is verified — but **they have not been exercised against a running Redmine, Gitea or OpenProject**. That is why they are `0.1.0`.

If you run one of these systems and something is wrong — a path, a parameter, a field the poll reads — please open an issue or a pull request. A corrected version is a new version in the catalogue; the old one keeps working for whoever installed it until they choose to update.

## Changing a plugin

1. Edit the file under `plugins/`.
2. `covey plugin lint plugins/<name>.json` — the same check the catalogue's CI and every Covey instance runs.
3. Open a pull request here.
4. After the merge, tag a release and open a pull request against [covey-plugins](https://github.com/benjaminLedel/covey-plugins) adding the new version, with the digest of the file at that tag:

```sh
curl -sL https://raw.githubusercontent.com/benjaminLedel/covey-plugin-pack/vX.Y.Z/plugins/<name>.json | shasum -a 256
```

Never edit a published version in place. Instances have pinned its digest, and rewriting it would change what they believe they installed — which is precisely what the digest exists to prevent.

## Licence

MIT — see [LICENSE](LICENSE).
