// The plugins Covey ships with — the common ones, as ordinary Go code.
//
// They live here rather than in Covey's own repository so that they are on the
// SAME footing as anybody else's plugin: same SDK, same registry, same build.
// Nothing in here is privileged.
module github.com/benjaminLedel/covey-plugin-pack

go 1.26

require (
	github.com/benjaminLedel/covey-plugin-sdk v0.1.0
	github.com/chromedp/chromedp v0.16.0
	github.com/emersion/go-imap/v2 v2.0.0-beta.8
	github.com/emersion/go-message v0.18.2
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/uuid v1.6.0
)

require (
	github.com/chromedp/cdproto v0.0.0-20260714215040-dc233986426f // indirect
	github.com/chromedp/sysutil v1.1.0 // indirect
	github.com/emersion/go-sasl v0.0.0-20241020182733-b788ff22d5a6 // indirect
	github.com/go-json-experiment/json v0.0.0-20260623181947-01eb4420fa68 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/gobwas/ws v1.4.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.14.0 // indirect
)
