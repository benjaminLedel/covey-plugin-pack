# covey-plugin-pack

The target-system plugins [Covey](https://github.com/benjaminLedel/covey) ships with — and the proof that shipping with Covey is not a privilege.

These used to live inside Covey's own repository, compiled in from `internal/`. They live here now, as an ordinary Go module against the public [SDK](https://github.com/benjaminLedel/covey-plugin-sdk), built the same way anybody else's plugin is built. Covey's default binary blank-imports this module; you can leave it out, replace it, or add your own alongside.

## What is in here

**Compiled plugins** (Go, one package each):

| | System | |
|---|---|---|
| `zammad/` | Zammad | helpdesk: read tickets, reply, set state, escalate; webhook intake |
| `gitlab/` · `github/` | GitLab, GitHub | issues and merge/pull requests as the working set: check out, fix, commit, open an MR/PR, live the review loop |
| `email/` | IMAP/SMTP | a mail account of its own: sift the inbox, read attachments, reply |
| `teams/` | Microsoft Teams | a chat channel through the Azure Bot Service |
| `sharepoint/` · `nextcloud/` | SharePoint, Nextcloud | document libraries: list, read, write, delete |
| `browser/` | headless Chrome | the universal adapter for web applications without a plugin of their own |
| `dev/` | the sandbox itself | shell commands, long-running processes, sub-agent runs inside a checkout |
| `vulndb/` | OSV, GHSA, NVD | known vulnerabilities in declared dependencies |
| `k8s/` | Kubernetes | read pods, logs, events and workloads; restart a Deployment, delete a stuck Pod. Secrets are never readable, and writes stay small because a GitOps cluster takes its desired state from its repository |

**Manifest plugins** (`manifests/`, JSON — no Go, no rebuild): Redmine, Gitea/Forgejo, OpenProject. These are listed in the [catalogue](https://github.com/benjaminLedel/covey-plugins) and installed at runtime.

## Using it

The default Covey build already includes the compiled ones. To build a Covey with a different set, blank-import what you want:

```go
import (
    _ "github.com/benjaminLedel/covey-plugin-pack/zammad"
    _ "github.com/example/covey-plugin-jira"   // somebody else's, on equal terms
)
```

## Writing a plugin

You do not need this repository for that. A plugin is one package that calls `target.Register` in `init()` — see the [SDK](https://github.com/benjaminLedel/covey-plugin-sdk). If you would rather not compile anything into Covey at all, write a **manifest**, an **MCP configuration** or a **WebAssembly module** and publish it through the [catalogue](https://github.com/benjaminLedel/covey-plugins); those install at runtime, with no rebuild.

These plugins are here because they are the common ones, not because they are special. Nothing in this module can do anything a third-party plugin cannot.

## Development

```sh
go build ./...
go test ./...
covey plugin lint manifests/redmine.json
```

Changing a plugin means changing it here, tagging a release, and — for the manifests — opening a pull request against the catalogue with the new digest.

## Licence

MIT — see [LICENSE](LICENSE).
