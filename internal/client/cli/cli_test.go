package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/ilushka-off/GophKeeper/internal/client/remote"
	"github.com/ilushka-off/GophKeeper/internal/testutil"
)

const master = "correct horse battery"

// fakePrompter answers password prompts from a queue.
type fakePrompter struct {
	answers []string
	prompts []string
}

func (p *fakePrompter) Password(prompt string) (string, error) {
	p.prompts = append(p.prompts, prompt)
	if len(p.answers) == 0 {
		return "", errors.New("no more answers")
	}
	a := p.answers[0]
	p.answers = p.answers[1:]
	return a, nil
}

// harness runs CLI commands against an in-process server with one data directory.
type harness struct {
	t       *testing.T
	srv     *testutil.Server
	dataDir string
	env     map[string]string
	offline bool
	stdin   string
}

func newHarness(t *testing.T, srv *testutil.Server) *harness {
	t.Helper()
	return &harness{
		t:       t,
		srv:     srv,
		dataDir: t.TempDir(),
		env:     map[string]string{EnvMasterPassword: master},
	}
}

// run executes the CLI with args and returns stdout, stderr and the exit code.
func (h *harness) run(prompts []string, args ...string) (string, string, int) {
	h.t.Helper()
	var stdout, stderr bytes.Buffer
	env := Env{
		Stdin:    strings.NewReader(h.stdin),
		Stdout:   &stdout,
		Stderr:   &stderr,
		Getenv:   func(k string) string { return h.env[k] },
		Prompter: &fakePrompter{answers: prompts},
		KDF:      testutil.FastKDF,
		NewRemote: func(Options) (Remote, error) {
			if h.offline {
				return remote.Dial("127.0.0.1:1", insecure.NewCredentials())
			}
			return remote.New(h.srv.Dial(h.t)), nil
		},
	}
	code := Execute(context.Background(), env, append([]string{"--data-dir", h.dataDir}, args...))
	return stdout.String(), stderr.String(), code
}

// ok runs a command that must succeed and returns its stdout.
func (h *harness) ok(args ...string) string {
	h.t.Helper()
	out, errOut, code := h.run(nil, args...)
	require.Equal(h.t, 0, code, "args %v: stderr %s", args, errOut)
	return out
}

// fail runs a command that must fail and returns its stderr.
func (h *harness) fail(args ...string) string {
	h.t.Helper()
	out, errOut, code := h.run(nil, args...)
	require.Equal(h.t, 1, code, "args %v: stdout %s", args, out)
	return errOut
}

var addedRe = regexp.MustCompile(`Added ([0-9a-f-]{36})`)

func (h *harness) add(args ...string) string {
	h.t.Helper()
	out := h.ok(append([]string{"add"}, args...)...)
	m := addedRe.FindStringSubmatch(out)
	require.NotNil(h.t, m, out)
	return m[1]
}

func registered(t *testing.T) (*harness, *testutil.Server) {
	t.Helper()
	srv := testutil.StartServer(t)
	h := newHarness(t, srv)
	h.ok("register", "-l", "ilya")
	return h, srv
}

func TestVersion(t *testing.T) {
	h := newHarness(t, testutil.StartServer(t))
	out := h.ok("version")
	assert.Contains(t, out, "Version:")
	assert.Contains(t, out, "Build date:")
	assert.Contains(t, out, "Commit:")
}

func TestRegister(t *testing.T) {
	srv := testutil.StartServer(t)
	h := newHarness(t, srv)
	delete(h.env, EnvMasterPassword)

	_, errOut, code := h.run([]string{master, "different"}, "register", "-l", "ilya")
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "do not match")

	_, errOut, code = h.run([]string{"short"}, "register", "-l", "ilya")
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "at least")

	_, errOut, code = h.run(nil, "register", "-l", "ilya")
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "no more answers")

	out, _, code := h.run([]string{master, master}, "register", "-l", "ilya")
	require.Equal(t, 0, code)
	assert.Contains(t, out, "Registered as ilya")

	assert.Contains(t, h.fail("register"), "required flag")

	other := newHarness(t, srv)
	assert.Contains(t, other.fail("register", "-l", "ilya"), "already")
}

func TestScenario(t *testing.T) {
	h, srv := registered(t)

	// Credentials: the password is asked interactively when not given.
	out, errOut, code := h.run([]string{"s3cret"}, "add", "credentials", "-n", "GitHub", "--login", "ilya", "-m", "https://github.com")
	require.Equal(t, 0, code, errOut)
	credID := addedRe.FindStringSubmatch(out)[1]
	textID := h.add("text", "-n", "note", "--text", "hello")
	textFile := filepath.Join(t.TempDir(), "note.txt")
	require.NoError(t, os.WriteFile(textFile, []byte("from file"), 0o600))
	h.add("text", "-n", "file note", "--file", textFile)
	cardID := h.add("card", "-n", "visa", "--number", "4111 1111 1111 1111", "--holder", "ILYA", "--expiry", "12/30", "--cvv", "123")
	binFile := filepath.Join(t.TempDir(), "photo.jpg")
	content := bytes.Repeat([]byte("gopher"), 300_000)
	require.NoError(t, os.WriteFile(binFile, content, 0o600))
	binID := h.add("binary", "-n", "photo", "--file", binFile)

	list := h.ok("list")
	for _, name := range []string{"GitHub", "note", "file note", "visa", "photo"} {
		assert.Contains(t, list, name)
	}
	assert.Contains(t, list, "https://github.com")
	assert.NotContains(t, list, " no\n")
	cards := h.ok("list", "--type", "card")
	assert.Contains(t, cards, "visa")
	assert.NotContains(t, cards, "GitHub")
	assert.Contains(t, h.fail("list", "-t", "bogus"), "unknown type")

	get := h.ok("get", credID[:8])
	assert.Contains(t, get, "s3cret")
	assert.Contains(t, get, "https://github.com")
	assert.Contains(t, h.ok("get", cardID), "4111111111111111")
	assert.Contains(t, h.ok("get", textID), "hello")
	assert.Contains(t, h.ok("get", binID), "--out")
	assert.Contains(t, h.fail("get", textID, "--out", filepath.Join(t.TempDir(), "x")), "only supported")

	// Second device: login downloads everything.
	h2 := newHarness(t, srv)
	assert.Contains(t, h2.ok("login", "-l", "ilya"), "Logged in as ilya")
	outPath := filepath.Join(t.TempDir(), "photo.out")
	assert.Contains(t, h2.ok("get", binID, "--out", outPath), "Saved")
	got, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Equal(t, content, got)

	// Edits on device 2 reach device 1.
	h2.ok("edit", credID, "--password", "new-pass", "-n", "GitHub work")
	h2.ok("edit", textID, "--text", "updated")
	h2.ok("edit", cardID, "--number", "5555555555554444", "--holder", "X", "--expiry", "01/31", "--cvv", "999", "-m", "bank")
	newFile := filepath.Join(t.TempDir(), "new.bin")
	require.NoError(t, os.WriteFile(newFile, []byte("new content"), 0o600))
	h2.ok("edit", binID, "--file", newFile)
	h2.ok("edit", textID, "--file", textFile)

	assert.Contains(t, h.ok("sync"), "Synced")
	assert.Contains(t, h.ok("get", credID), "new-pass")
	assert.Contains(t, h.ok("get", textID), "from file")
	assert.Contains(t, h.ok("get", cardID), "5555555555554444")
	h.ok("get", binID, "--out", outPath)
	got, err = os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Equal(t, "new content", string(got))

	// Edit errors.
	assert.Contains(t, h.fail("edit", credID), "nothing to change")
	assert.Contains(t, h.fail("edit", credID, "--number", "4111111111111111"), "does not apply")
	assert.Contains(t, h.fail("edit", cardID, "--number", "1234"), "invalid")
	assert.Contains(t, h.fail("edit", textID, "--file", filepath.Join(t.TempDir(), "missing")), "read text file")
	assert.Contains(t, h.fail("edit", "ffffffff", "--name", "x"), "not found")

	// Delete propagates.
	assert.Contains(t, h.ok("delete", credID), "Deleted")
	assert.Contains(t, h.fail("get", credID), "not found")
	h2.ok("sync")
	assert.NotContains(t, h2.ok("list"), "GitHub")

	status := h.ok("status")
	assert.Contains(t, status, "Login:   ilya")
	assert.Contains(t, status, "Pending: 0")

	assert.Contains(t, h.ok("logout"), "Logged out")
	assert.Contains(t, h.fail("sync"), "not logged in")
}

func TestOTP(t *testing.T) {
	h, _ := registered(t)
	id := h.add("otp", "-n", "github", "--secret", "JBSWY3DPEHPK3PXP", "--account", "ilya")
	out := h.ok("get", id)
	assert.Contains(t, out, "Account:")
	assert.Regexp(t, `Code:\s+\d{6} \(valid \d+s\)`, out)

	id2 := h.add("otp", "--uri", "otpauth://totp/GitLab:ilya?secret=JBSWY3DPEHPK3PXP&digits=8")
	out = h.ok("get", id2)
	assert.Contains(t, out, "Name:")
	assert.Contains(t, out, "GitLab")
	assert.Regexp(t, `Code:\s+\d{8} `, out)

	h.ok("edit", id, "--digits", "8", "--issuer", "GitHub")
	assert.Regexp(t, `Code:\s+\d{8} `, h.ok("get", id))
	assert.Contains(t, h.ok("list", "-t", "otp"), "github")

	assert.NotEmpty(t, h.fail("add", "otp", "-n", "x"))
	assert.NotEmpty(t, h.fail("add", "otp", "-n", "x", "--secret", "!!!"))
	assert.NotEmpty(t, h.fail("add", "otp", "--uri", "https://example.com"))
	assert.NotEmpty(t, h.fail("add", "otp", "-n", "x", "--secret", "JBSWY3DPEHPK3PXP", "--uri", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"))
}

func TestTUI(t *testing.T) {
	h := newHarness(t, testutil.StartServer(t))
	assert.NotEmpty(t, h.fail("tui"))

	h, _ = registered(t)
	h.add("text", "-n", "note", "--text", "hello")
	h.stdin = "q"
	assert.Contains(t, h.ok("tui"), "GophKeeper")
}

func TestAddValidation(t *testing.T) {
	h, _ := registered(t)
	assert.Contains(t, h.fail("add", "card", "-n", "bad", "--number", "1234"), "invalid")
	assert.Contains(t, h.fail("add", "text", "-n", "t"), "text")
	assert.Contains(t, h.fail("add", "text", "-n", "t", "--file", filepath.Join(t.TempDir(), "nope")), "read text file")
	assert.Contains(t, h.fail("add", "binary", "-n", "b", "--file", filepath.Join(t.TempDir(), "nope")), "open file")
	assert.Contains(t, h.fail("add", "credentials", "-n", "c", "--login", "l"), "no more answers")
	assert.Contains(t, h.fail("add", "credentials", "-n", "c", "--password", ""), "required")
	assert.Contains(t, h.ok("list"), "No records")
	h.add("credentials", "-n", "c", "--password", "p")
	assert.Contains(t, h.fail("get", "ab"), "at least 4")
	assert.Contains(t, h.fail("delete", "ffffffff"), "not found")
}

func TestWrongMasterPasswordAndNoAccount(t *testing.T) {
	srv := testutil.StartServer(t)
	h := newHarness(t, srv)
	assert.Contains(t, h.fail("list"), "no account")
	assert.Contains(t, h.fail("status"), "no account")

	h.ok("register", "-l", "ilya")
	h.env[EnvMasterPassword] = "wrong password"
	assert.Contains(t, h.fail("list"), "wrong master password")

	delete(h.env, EnvMasterPassword)
	_, errOut, code := h.run([]string{master}, "list")
	assert.Equal(t, 0, code, errOut)

	h2 := newHarness(t, srv)
	h2.env[EnvMasterPassword] = "wrong password"
	assert.Contains(t, h2.fail("login", "-l", "ilya"), "unauthenticated")
}

func TestOffline(t *testing.T) {
	h, _ := registered(t)
	h.offline = true

	out, errOut, code := h.run(nil, "add", "text", "-n", "offline", "--text", "x")
	require.Equal(t, 0, code, errOut)
	assert.Contains(t, out, "Added")
	assert.Contains(t, errOut, "warning: saved locally, sync failed")
	assert.Contains(t, h.ok("status"), "Pending: 1")
	assert.Contains(t, h.ok("list"), " no")
	assert.Contains(t, h.fail("sync"), "cannot reach the server")

	h.offline = false
	assert.Contains(t, h.ok("sync"), "pushed 1")
	assert.Contains(t, h.ok("status"), "Pending: 0")
}

func TestLoginSyncFailure(t *testing.T) {
	srv := testutil.StartServer(t)
	h := newHarness(t, srv)
	h.offline = true
	assert.Contains(t, h.fail("login", "-l", "ilya"), "cannot reach the server")
}

func TestNewRemoteError(t *testing.T) {
	h := newHarness(t, testutil.StartServer(t))
	var stderr bytes.Buffer
	env := Env{
		Stdout: &bytes.Buffer{},
		Stderr: &stderr,
		Getenv: func(string) string { return "" },
		NewRemote: func(Options) (Remote, error) {
			return nil, errors.New("dial failed")
		},
	}
	code := Execute(context.Background(), env, []string{"--data-dir", h.dataDir, "status"})
	assert.Equal(t, 1, code)
	assert.Contains(t, stderr.String(), "dial failed")
}

func TestOptionsPrecedence(t *testing.T) {
	var got Options
	dir := t.TempDir()
	envDir := filepath.Join(dir, "env")
	env := Env{
		Stdout: &bytes.Buffer{},
		Stderr: &bytes.Buffer{},
		Getenv: func(k string) string {
			return map[string]string{EnvServer: "env:1", EnvCACert: "env.crt", EnvDataDir: envDir}[k]
		},
		NewRemote: func(o Options) (Remote, error) {
			got = o
			return nil, errors.New("stop")
		},
	}
	Execute(context.Background(), env, []string{"status"})
	assert.Equal(t, Options{Server: "env:1", CACert: "env.crt", DataDir: envDir}, got)

	Execute(context.Background(), env, []string{"--server", "flag:2", "--ca-cert", "flag.crt", "--data-dir", dir, "status"})
	assert.Equal(t, Options{Server: "flag:2", CACert: "flag.crt", DataDir: dir}, got)

	env.Getenv = func(string) string { return "" }
	Execute(context.Background(), env, []string{"--data-dir", dir, "status"})
	assert.Equal(t, DefaultServer, got.Server)
	assert.Empty(t, got.CACert)
}

func TestDefaultsAndDial(t *testing.T) {
	var e Env
	e.setDefaults()
	assert.NotNil(t, e.Stdin)
	assert.NotNil(t, e.Prompter)
	assert.NotNil(t, e.NewRemote)
	assert.NotZero(t, e.KDF.Memory)
	assert.NotEmpty(t, defaultDataDir())

	r, err := dialRemote(Options{Server: "localhost:1"})
	require.NoError(t, err)
	require.NoError(t, r.Close())
	_, err = dialRemote(Options{Server: "localhost:1", CACert: filepath.Join(t.TempDir(), "missing.crt")})
	require.Error(t, err)
}

func TestShorten(t *testing.T) {
	assert.Equal(t, "short", shorten("short", 10))
	assert.Equal(t, "a b", shorten("a\nb", 10))
	assert.Equal(t, "абв…", shorten("абвгдеё", 4))
}

func TestTerminalPrompter(t *testing.T) {
	var out bytes.Buffer
	p := NewTerminalPrompter(strings.NewReader("first\r\nsecond\nlast"), &out)
	for _, want := range []string{"first", "second", "last"} {
		got, err := p.Password("> ")
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}
	_, err := p.Password("> ")
	require.Error(t, err)
	assert.Equal(t, "> > > > ", out.String())

	// A non-terminal *os.File is read line by line too.
	f, err := os.CreateTemp(t.TempDir(), "in")
	require.NoError(t, err)
	_, err = f.WriteString("from file\n")
	require.NoError(t, err)
	_, err = f.Seek(0, 0)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	got, err := NewTerminalPrompter(f, &out).Password("")
	require.NoError(t, err)
	assert.Equal(t, "from file", got)
}
