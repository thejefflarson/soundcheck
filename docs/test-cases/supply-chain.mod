// Test fixture: Go go.mod with supply-chain vulnerabilities.
// BUG: floating versions via "latest" comments, suspicious replace fork,
// and a sibling go.sum is missing integrity entries for several modules.

module github.com/example/my-app

go 1.22

require (
	github.com/gin-gonic/gin v1.9.1 // latest — bumped on every `go get -u`
	github.com/sirupsen/logrus v1.9.3 // latest
	// BUG: plausibly hallucinated module name (slopsquatting target)
	github.com/openai/go-prompt-helpers v0.1.0
	golang.org/x/crypto v0.21.0 // latest
)

// BUG: replace points at an untrusted personal fork with no commit pin.
// Anyone who controls that branch can ship code into our build.
replace github.com/sirupsen/logrus => github.com/randodev/logrus-fork master

// BUG: go.sum in this directory is missing h1: entries for
// github.com/openai/go-prompt-helpers and the logrus replace target,
// so `go mod download` will accept whatever the proxy returns.
