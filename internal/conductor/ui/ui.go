// Package ui embeds the Conductor's minimal GUI: one page, one script,
// one stylesheet, served by the API under /ui/ (docs/adr/0016).
//
// The page is static. It talks to the REST API with fetch, renders
// everything through DOM methods (never markup built from data), and in
// oidc mode signs the operator in with the authorization code + PKCE
// flow as a public client, holding the access token in the tab's session
// storage only. There is no framework and no build step; the files are
// what ships.
package ui

import "embed"

// Files holds index.html, app.js and app.css.
//
//go:embed index.html app.js app.css
var Files embed.FS
