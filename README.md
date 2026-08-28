# covey-plugin-pack

The target-system plugins [Covey](https://github.com/benjaminLedel/covey) ships with — and the proof that shipping with Covey is not a privilege.

These used to live inside Covey's own repository, compiled in from `internal/`. They live here now, as an ordinary Go module against the public [SDK](https://github.com/benjaminLedel/covey-plugin-sdk), built the same way anybody else's plugin is built. Covey's default binary blank-imports this module; you can leave it out, replace it, or add your own alongside.

## What is in here

**Compiled plugins** (Go, one package each):

| | System | |
|---|---|---|
| `zammad/` | Zammad | helpdesk: read tickets, reply, set state, escalate; webhook intake |
| `salesforce/` | Salesforce Service Cloud | support cases: read the case and its whole conversation, look at the screenshot the customer attached, look up how the question was answered before, reply as a note, a portal comment or a mail, escalate. Heartbeat intake; a webhook where a flow posts one |
| `gitlab/` · `github/` | GitLab, GitHub | issues and merge/pull requests as the working set: check out, fix, commit, open an MR/PR, live the review loop |
| `jira/` | Jira (Cloud and Server/Data Center) | the ticket half of a developer's day: find work by JQL, read an issue with its thread and its screenshots, take it on, move it through its workflow, comment, keep the board honest (labels, story points, worklog, sub-tasks) — the code stays in GitLab/GitHub, the issue key ties the two together |
| `confluence/` | Confluence (Cloud and Server/Data Center) | the documentation the other two hang off: find a page by words or by CQL, read it as Markdown, append a section, replace a body under the version you read, comment, label, attach. Deliberately not a source of work — it wakes nobody |
| `email/` | IMAP/SMTP | a mail account of its own: sift the inbox, read attachments, reply |
| `teams/` | Microsoft Teams | a chat channel through the Azure Bot Service |
| `sharepoint/` · `nextcloud/` | SharePoint, Nextcloud | document libraries: list, read, write, delete |
| `browser/` | headless Chrome | the universal adapter for web applications without a plugin of their own |
| `dev/` | the sandbox itself | shell commands, long-running processes, sub-agent runs inside a checkout |
| `vulndb/` | OSV, GHSA, NVD | known vulnerabilities in declared dependencies |
| `k8s/` | Kubernetes | read pods, logs, events and workloads; restart a Deployment, delete a stuck Pod. Secrets are never readable, and writes stay small because a GitOps cluster takes its desired state from its repository |

**Manifest plugins** (`manifests/`, JSON — no Go, no rebuild): Redmine, Gitea/Forgejo, OpenProject. These are listed in the [catalogue](https://github.com/benjaminLedel/covey-plugins) and installed at runtime.

**WebAssembly modules** (`wasm/`): `zammad`, `vulndb` and `k8s` exist a second time, as modules published through the [catalogue](https://github.com/benjaminLedel/covey-plugins) and installed at runtime like a manifest. The same three systems, in the form that carries the strongest promise: a module has no socket, no filesystem and never sees the credential. It says `GET /tickets/7`, and the host adds the base URL and the token the organisation stored — which is why a module cannot leak one. It has none, and nothing to leak it through.

`wasm/covey/plugin.go` is the guest side of that protocol. It is vendored rather than imported, on purpose: a plugin must not depend on Covey in order to be built. [covey-plugin-template](https://github.com/benjaminLedel/covey-plugin-template) carries the same file and is where a module of your own starts.

## Using it

The default Covey build already includes the compiled ones. To build a Covey with a different set, blank-import what you want:

```go
import (
    _ "github.com/benjaminLedel/covey-plugin-pack/zammad"
    _ "github.com/example/covey-plugin-servicenow"   // somebody else's, on equal terms
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
