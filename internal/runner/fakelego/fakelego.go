// Package fakelego is a test double for the lego CLI.
//
// Tests point the Runner at their own test binary and arrange for the
// binding's environment to carry FAKE_LEGO_MODE; TestMain then dispatches
// to Main, which imitates the observable behaviour of lego: it parses the
// same flags, writes the same files under --path, and exits with the same
// codes. It never talks to a network. It is not compiled into the shipped
// binaries: only test packages import it.
package fakelego

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Environment variables that steer the fake. They are set through the DNS
// binding's non-secret env map in test configurations.
const (
	// EnvMode selects the behaviour: ok (default), fail, hang, wrongdomain,
	// nokey, garbage, missingoutput, longline (1 MiB output lines, then ok).
	EnvMode = "FAKE_LEGO_MODE"
	// EnvDays sets the certificate validity in days (default 90).
	EnvDays = "FAKE_LEGO_DAYS"
	// EnvNotBeforeHours shifts the certificate's NotBefore by this many
	// hours from now (default -1; a positive value yields a not-yet-valid
	// certificate).
	EnvNotBeforeHours = "FAKE_LEGO_NOTBEFORE_HOURS"
	// EnvExtraSAN adds a second subject alternative name to the certificate.
	EnvExtraSAN = "FAKE_LEGO_EXTRA_SAN"
	// EnvKeyTypeOverride generates the certificate key with this lego key
	// type instead of the one requested on the command line.
	EnvKeyTypeOverride = "FAKE_LEGO_KEYTYPE_OVERRIDE"
	// EnvRecord names a file to which argv and environment are written as
	// JSON so tests can characterize the exact invocation.
	EnvRecord = "FAKE_LEGO_RECORD"
	// EnvSentinel is a marker variable tests use to prove that only the
	// configured environment reaches lego.
	EnvSentinel = "FAKE_LEGO_SENTINEL"
)

// LeakedSecret is a value the "fail" mode prints on stderr, so tests can
// prove that lego output never reaches a Result and is redacted in logs.
const LeakedSecret = "fake-hmac-secret-value-0123456789"

// Record is what the fake writes to EnvRecord.
type Record struct {
	Argv []string `json:"argv"`
	Env  []string `json:"env"`
	Dir  string   `json:"dir"`
}

// Main runs the fake with the given arguments and environment and returns
// the exit code.
func Main(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	flags := parseFlags(args)
	if rec := getenv(EnvRecord); rec != "" {
		dir, _ := os.Getwd()
		data, _ := json.Marshal(Record{Argv: args, Env: os.Environ(), Dir: dir})
		if err := os.WriteFile(rec, data, 0o600); err != nil {
			fmt.Fprintln(stderr, "fake lego: record:", err)
			return 3
		}
	}
	mode := getenv(EnvMode)
	if mode == "" {
		mode = "ok"
	}
	path := flags["path"]
	domain := flags["domains"]
	if path == "" || domain == "" || flags["server"] == "" || flags["email"] == "" || flags["dns"] == "" {
		fmt.Fprintln(stderr, "fake lego: missing required flags")
		return 2
	}
	if _, ok := flags["run"]; !ok {
		fmt.Fprintln(stderr, "fake lego: expected the run command")
		return 2
	}
	// Imitate account registration: lego creates the account files under
	// --path/accounts/<host>/<email>/.
	accountDir := filepath.Join(path, "accounts", hostOf(flags["server"]), flags["email"])
	if err := os.MkdirAll(filepath.Join(accountDir, "keys"), 0o700); err != nil {
		fmt.Fprintln(stderr, "fake lego:", err)
		return 1
	}
	accountFile := filepath.Join(accountDir, "account.json")
	if _, err := os.Stat(accountFile); err != nil {
		os.WriteFile(accountFile, []byte(`{"registration":{"fake":true}}`), 0o600)
		os.WriteFile(filepath.Join(accountDir, "keys", flags["email"]+".key"), []byte("-----BEGIN EC PRIVATE KEY-----\nZmFrZS1hY2NvdW50LWtleQ==\n-----END EC PRIVATE KEY-----\n"), 0o600)
		fmt.Fprintln(stdout, "fake lego: registered new account")
	} else {
		fmt.Fprintln(stdout, "fake lego: reusing existing account")
	}
	switch mode {
	case "fail":
		fmt.Fprintf(stderr, "fake lego: Could not obtain certificates: acme: error: 403 :: urn:ietf:params:acme:error:unauthorized :: hmac=%s\n", LeakedSecret)
		fmt.Fprintln(stderr, "-----BEGIN EC PRIVATE KEY-----")
		fmt.Fprintln(stderr, "ZmFrZS1sZWFrZWQta2V5")
		fmt.Fprintln(stderr, "-----END EC PRIVATE KEY-----")
		return 1
	case "hang":
		fmt.Fprintln(stdout, "fake lego: hanging")
		// Ignore SIGTERM so only SIGKILL from the process-group kill ends us.
		ignoreTerm()
		time.Sleep(10 * time.Minute)
		return 0
	case "orphan", "orphanhang":
		// Start a detached child (new session, outside our process group)
		// that inherits stdout and keeps it open for a long time, the way a
		// daemonizing helper would. "orphan" then succeeds normally;
		// "orphanhang" hangs like the hang mode.
		if err := spawnOrphan(); err != nil {
			fmt.Fprintln(stderr, "fake lego: orphan:", err)
			return 1
		}
		if mode == "orphanhang" {
			ignoreTerm()
			time.Sleep(10 * time.Minute)
			return 0
		}
	case "sleep":
		// Used as the orphan child: hold stdout open quietly.
		time.Sleep(20 * time.Second)
		return 0
	case "longline":
		// A single 1 MiB line without newline, then success: the Runner
		// must keep draining the pipe or the fake blocks forever.
		fmt.Fprint(stdout, strings.Repeat("x", 1<<20))
		fmt.Fprintln(stdout)
		fmt.Fprintln(stderr, strings.Repeat("y", 1<<20))
	case "missingoutput":
		fmt.Fprintln(stdout, "fake lego: pretending success without writing files")
		return 0
	}
	days := 90
	if d := getenv(EnvDays); d != "" {
		if n, err := strconv.Atoi(d); err == nil {
			days = n
		}
	}
	certDomain := domain
	if mode == "wrongdomain" {
		certDomain = "other.example.net"
	}
	notBefore := -1
	if v := getenv(EnvNotBeforeHours); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			notBefore = n
		}
	}
	names := []string{certDomain}
	if extra := getenv(EnvExtraSAN); extra != "" {
		names = append(names, extra)
	}
	keyType := flags["key-type"]
	if o := getenv(EnvKeyTypeOverride); o != "" {
		keyType = o
	}
	certPEM, keyPEM, issuerPEM, err := selfSigned(names, keyType, days, notBefore)
	if err != nil {
		fmt.Fprintln(stderr, "fake lego:", err)
		return 1
	}
	certDir := filepath.Join(path, "certificates")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		fmt.Fprintln(stderr, "fake lego:", err)
		return 1
	}
	base := filepath.Join(certDir, strings.NewReplacer(":", "-", "*", "_").Replace(domain))
	bundle := append(append([]byte(nil), certPEM...), issuerPEM...)
	if mode == "garbage" {
		bundle = []byte("this is not a certificate\n")
	}
	if err := os.WriteFile(base+".crt", bundle, 0o600); err != nil {
		return 1
	}
	if err := os.WriteFile(base+".issuer.crt", issuerPEM, 0o600); err != nil {
		return 1
	}
	if mode != "nokey" {
		if err := os.WriteFile(base+".key", keyPEM, 0o600); err != nil {
			return 1
		}
	}
	if err := os.WriteFile(base+".json", []byte(`{"domain":"`+domain+`"}`), 0o600); err != nil {
		return 1
	}
	fmt.Fprintf(stdout, "fake lego: Server responded with a certificate for %s\n", domain)
	return 0
}

// parseFlags handles the "--flag value" and bare-command forms the Runner
// uses. Boolean flags (--accept-tos, --eab) and commands map to "".
func parseFlags(args []string) map[string]string {
	out := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") {
			out[a] = ""
			continue
		}
		name := strings.TrimPrefix(a, "--")
		if name == "accept-tos" || name == "eab" {
			out[name] = "true"
			continue
		}
		if i+1 < len(args) {
			out[name] = args[i+1]
			i++
		}
	}
	return out
}

func hostOf(server string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(server, "https://"), "http://")
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	return strings.ReplaceAll(s, ":", "_")
}

func selfSigned(names []string, keyType string, days, notBeforeHours int) (certPEM, keyPEM, issuerPEM []byte, err error) {
	domain := names[0]
	var pub any
	switch keyType {
	case "rsa2048", "rsa3072", "rsa4096":
		bits := map[string]int{"rsa2048": 2048, "rsa3072": 3072, "rsa4096": 4096}[keyType]
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, nil, nil, err
		}
		pub = &k.PublicKey
		der := x509.MarshalPKCS1PrivateKey(k)
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	default:
		curve := elliptic.P256()
		if keyType == "ec384" {
			curve = elliptic.P384()
		}
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, nil, err
		}
		pub = &k.PublicKey
		der, _ := x509.MarshalECPrivateKey(k)
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	}
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	issuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Fake Lego Issuer"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		return nil, nil, nil, err
	}
	issuerCert, _ := x509.ParseCertificate(issuerDER)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	leafTmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     names,
		NotBefore:    now.Add(time.Duration(notBeforeHours) * time.Hour),
		NotAfter:     now.Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, issuerCert, pub, issuerKey)
	if err != nil {
		return nil, nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	issuerPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER})
	return certPEM, keyPEM, issuerPEM, nil
}
