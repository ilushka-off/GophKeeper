package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ilushka-off/GophKeeper/internal/client/app"
	"github.com/ilushka-off/GophKeeper/internal/model"
)

type fakeVault struct {
	entries []app.Entry
	syncErr error
	addErr  error
	listErr error
	syncs   int
	deleted []uuid.UUID
}

func (f *fakeVault) List(context.Context, model.RecordType) ([]app.Entry, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]app.Entry(nil), f.entries...), nil
}

func (f *fakeVault) Get(_ context.Context, id uuid.UUID) (app.Entry, error) {
	for _, e := range f.entries {
		if e.ID == id {
			return e, nil
		}
	}
	return app.Entry{}, model.ErrNotFound
}

func (f *fakeVault) Add(_ context.Context, p model.Payload) (uuid.UUID, error) {
	if f.addErr != nil {
		return uuid.Nil, f.addErr
	}
	id := uuid.New()
	f.entries = append(f.entries, app.Entry{ID: id, Payload: p, Dirty: true})
	return id, nil
}

func (f *fakeVault) Delete(_ context.Context, id uuid.UUID) error {
	f.deleted = append(f.deleted, id)
	for i, e := range f.entries {
		if e.ID == id {
			f.entries = append(f.entries[:i], f.entries[i+1:]...)
			return nil
		}
	}
	return model.ErrNotFound
}

func (f *fakeVault) Sync(context.Context) (app.SyncReport, error) {
	f.syncs++
	if f.syncErr != nil {
		return app.SyncReport{}, f.syncErr
	}
	return app.SyncReport{Pushed: 1, Pulled: 2}, nil
}

func entry(name string, d model.Data) app.Entry {
	return app.Entry{ID: uuid.New(), Payload: model.Payload{Name: name, Data: d}, UpdatedAt: time.Unix(0, 0)}
}

type harness struct {
	t     *testing.T
	m     Model
	v     *fakeVault
	ticks int
}

func newHarness(t *testing.T, entries ...app.Entry) *harness {
	t.Helper()
	h := &harness{t: t, v: &fakeVault{entries: entries}}
	h.m = New(context.Background(), h.v)
	h.m.now = func() time.Time { return time.Unix(59, 0) }
	h.m.tick = func(int) tea.Cmd {
		h.ticks++
		return nil
	}
	h.exec(h.m.Init())
	return h
}

// send delivers msg to the model and runs the resulting commands.
func (h *harness) send(msg tea.Msg) {
	h.t.Helper()
	m, cmd := h.m.Update(msg)
	h.m = m.(Model)
	h.exec(cmd)
}

// exec runs cmd and feeds back the messages of vault calls. Timer commands such as
// the cursor blink are skipped.
func (h *harness) exec(cmd tea.Cmd) {
	h.t.Helper()
	if cmd == nil {
		return
	}
	done := make(chan tea.Msg, 1)
	go func() { done <- cmd() }()
	var msg tea.Msg
	select {
	case msg = <-done:
	case <-time.After(50 * time.Millisecond):
		return
	}
	switch msg := msg.(type) {
	case tea.BatchMsg:
		for _, c := range msg {
			h.exec(c)
		}
	case entriesMsg, entryMsg, addedMsg, deletedMsg, syncedMsg:
		h.send(msg)
	}
}

func (h *harness) keys(keys ...string) {
	h.t.Helper()
	for _, k := range keys {
		var msg tea.KeyMsg
		switch k {
		case "enter":
			msg = tea.KeyMsg{Type: tea.KeyEnter}
		case "esc":
			msg = tea.KeyMsg{Type: tea.KeyEsc}
		case "tab":
			msg = tea.KeyMsg{Type: tea.KeyTab}
		case "shift+tab":
			msg = tea.KeyMsg{Type: tea.KeyShiftTab}
		case "up":
			msg = tea.KeyMsg{Type: tea.KeyUp}
		case "down":
			msg = tea.KeyMsg{Type: tea.KeyDown}
		case "ctrl+s":
			msg = tea.KeyMsg{Type: tea.KeyCtrlS}
		case "ctrl+c":
			msg = tea.KeyMsg{Type: tea.KeyCtrlC}
		case "backspace":
			msg = tea.KeyMsg{Type: tea.KeyBackspace}
		default:
			msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
		}
		h.send(msg)
	}
}

// typeText types s rune by rune into the focused input.
func (h *harness) typeText(s string) {
	h.t.Helper()
	for _, r := range s {
		h.send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
}

func (h *harness) view() string { return h.m.View() }

func TestListFilterAndSearch(t *testing.T) {
	h := newHarness(t,
		entry("github", model.Credentials{Login: "ilya", Password: "pw"}),
		entry("notes", model.Text{Content: "hello"}),
		entry("visa", model.Card{Number: "4242424242424242"}),
	)
	v := h.view()
	assert.Contains(t, v, "github")
	assert.Contains(t, v, "notes")
	assert.Contains(t, v, "3 record(s)")

	h.keys("tab") // credentials
	v = h.view()
	assert.Contains(t, v, "github")
	assert.NotContains(t, v, "notes")
	h.keys("shift+tab", "shift+tab") // otp
	assert.Contains(t, h.view(), "No records")
	h.keys("tab")

	h.keys("/")
	h.typeText("vi")
	assert.True(t, h.m.finding)
	v = h.view()
	assert.Contains(t, v, "visa")
	assert.NotContains(t, v, "github")
	h.keys("enter")
	assert.False(t, h.m.finding)
	assert.Contains(t, h.view(), "1 record(s)")
	h.keys("esc")
	assert.Contains(t, h.view(), "3 record(s)")

	h.keys("/")
	h.typeText("zz")
	h.keys("esc")
	assert.Empty(t, h.m.search.Value())
}

func TestNavigationAndView(t *testing.T) {
	h := newHarness(t,
		entry("github", model.Credentials{Login: "ilya", Password: "s3cret"}),
		entry("visa", model.Card{Number: "4242424242424242", Holder: "ILYA", Expiry: "12/30", CVV: "123"}),
	)
	h.send(tea.WindowSizeMsg{Width: 80, Height: 9})
	h.keys("down", "down", "j", "up", "k", "k")
	assert.Equal(t, 0, h.m.cursor)
	h.keys("j", "enter")
	require.Equal(t, screenView, h.m.screen)
	v := h.view()
	assert.Contains(t, v, "•••• 4242")
	assert.NotContains(t, v, "123")
	h.keys("r")
	v = h.view()
	assert.Contains(t, v, "4242424242424242")
	assert.Contains(t, v, "123")
	h.keys("?")
	assert.Contains(t, h.view(), "Keys")
	h.keys("x")
	assert.False(t, h.m.help)
	h.keys("esc")
	assert.Equal(t, screenList, h.m.screen)

	h.keys("k", "enter")
	v = h.view()
	assert.Contains(t, v, "ilya")
	assert.NotContains(t, v, "s3cret")
	h.keys("backspace")
	assert.Equal(t, screenList, h.m.screen)
}

func TestOTPViewTicks(t *testing.T) {
	o := model.OTP{Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Issuer: "GitHub", Account: "ilya", Digits: 8}
	h := newHarness(t, entry("github", o))
	h.keys("enter")
	v := h.view()
	assert.Contains(t, v, "94287082 (valid 1s)") // RFC 6238 vector at t=59
	assert.Equal(t, 1, h.ticks)

	h.send(tickMsg{id: h.m.tickID})
	assert.Equal(t, 2, h.ticks)
	h.send(tickMsg{id: h.m.tickID - 1}) // stale timer
	assert.Equal(t, 2, h.ticks)
	h.keys("esc")
	h.send(tickMsg{id: h.m.tickID})
	assert.Equal(t, 2, h.ticks)

	fields := entryFields(entry("bad", model.OTP{Secret: "!!"}), false, time.Now())
	assert.Contains(t, fields, [2]string{"Code", "otp: invalid parameters: secret is not base32"})
}

func TestEntryFieldsBinaryAndText(t *testing.T) {
	e := entry("doc", model.Binary{FileName: "a.pdf", Size: 10})
	e.Dirty = true
	fields := entryFields(e, false, time.Now())
	assert.Contains(t, fields, [2]string{"File", "a.pdf"})
	assert.Contains(t, fields, [2]string{"Size", "10 bytes"})
	assert.Contains(t, fields, [2]string{"Synced", "no"})
	assert.Contains(t, entryFields(entry("t", model.Text{Content: "x"}), false, time.Now()), [2]string{"Text", "x"})
}

func TestAddCredentials(t *testing.T) {
	h := newHarness(t)
	assert.Contains(t, h.view(), "No records")
	h.keys("a")
	require.Equal(t, screenPick, h.m.screen)
	assert.Contains(t, h.view(), "New record type")
	h.keys("down", "up", "up", "esc")
	assert.Equal(t, screenList, h.m.screen)

	h.keys("a", "enter")
	require.Equal(t, screenForm, h.m.screen)
	assert.Equal(t, model.TypeCredentials, h.m.form.typ)

	h.keys("ctrl+s")
	assert.Contains(t, h.view(), "name is required")
	h.typeText("github")
	h.keys("enter")
	h.typeText("ilya")
	h.keys("tab")
	h.typeText("pw")
	assert.NotContains(t, h.view(), "pw")
	h.keys("enter", "enter") // meta, then save from the last field
	require.Equal(t, screenList, h.m.screen)
	require.Len(t, h.v.entries, 1)
	assert.Equal(t, model.Credentials{Login: "ilya", Password: "pw"}, h.v.entries[0].Payload.Data)
	assert.Equal(t, 1, h.v.syncs)
	assert.Contains(t, h.view(), "Synced: pushed 1, pulled 2")
	assert.Contains(t, h.view(), "* credentials")
}

func TestAddOtherTypes(t *testing.T) {
	h := newHarness(t)
	h.keys("a", "2")
	h.typeText("note")
	h.keys("tab")
	h.typeText("hello")
	h.keys("ctrl+s")

	h.keys("a", "3")
	h.typeText("visa")
	h.keys("tab")
	h.typeText("4242 4242 4242 4241")
	h.keys("ctrl+s")
	assert.Contains(t, h.view(), "card number is invalid")
	h.keys("backspace")
	h.typeText("2")
	h.keys("shift+tab", "down", "down", "down")
	h.typeText("12/30")
	h.keys("ctrl+s")

	h.keys("a", "4")
	h.keys("tab")
	h.typeText("otpauth://totp/GitLab:ilya?secret=JBSWY3DPEHPK3PXP")
	h.keys("ctrl+s")

	h.keys("a", "4", "tab")
	h.typeText("otpauth://bad")
	h.keys("ctrl+s")
	assert.Contains(t, h.view(), "only totp is supported")
	h.keys("esc")

	require.Len(t, h.v.entries, 3)
	assert.Equal(t, model.Text{Content: "hello"}, h.v.entries[0].Payload.Data)
	assert.Equal(t, "4242424242424242", h.v.entries[1].Payload.Data.(model.Card).Number)
	assert.Equal(t, "12/30", h.v.entries[1].Payload.Data.(model.Card).Expiry)
	assert.Equal(t, "GitLab", h.v.entries[2].Payload.Name)
	assert.Equal(t, "ilya", h.v.entries[2].Payload.Data.(model.OTP).Account)
}

func TestFormOTPAccountOverride(t *testing.T) {
	f := newForm(model.TypeOTP)
	f.fields[1].input.SetValue("otpauth://totp/GitLab:ilya?secret=JBSWY3DPEHPK3PXP")
	f.fields[2].input.SetValue("other")
	p, err := f.payload()
	require.NoError(t, err)
	assert.Equal(t, "other", p.Data.(model.OTP).Account)
}

func TestDelete(t *testing.T) {
	a, b := entry("a", model.Text{Content: "1"}), entry("b", model.Text{Content: "2"})
	h := newHarness(t, a, b)
	h.keys("d")
	assert.Contains(t, h.view(), "Delete this record?")
	h.keys("n")
	assert.Empty(t, h.v.deleted)

	h.keys("d", "y")
	assert.Equal(t, []uuid.UUID{a.ID}, h.v.deleted)
	assert.Contains(t, h.view(), "Synced")

	h.keys("enter", "d", "y")
	assert.Equal(t, []uuid.UUID{a.ID, b.ID}, h.v.deleted)
	assert.Equal(t, screenList, h.m.screen)
	assert.Contains(t, h.view(), "No records")

	h.keys("d") // nothing selected
	assert.False(t, h.m.confirm)
	h.send(deletedMsg{err: model.ErrNotFound})
	assert.Contains(t, h.view(), "Error: not found")
}

func TestErrorsAndSync(t *testing.T) {
	h := newHarness(t)
	h.v.syncErr = errors.New("offline")
	h.keys("s")
	assert.Contains(t, h.view(), "sync failed, changes are kept locally: offline")

	h.v.addErr = errors.New("locked")
	h.keys("a", "2")
	h.typeText("n")
	h.keys("tab")
	h.typeText("t")
	h.keys("ctrl+s")
	assert.Contains(t, h.view(), "Error: locked")
	assert.Equal(t, screenForm, h.m.screen)

	h.v.listErr = errors.New("db closed")
	h.exec(h.m.load())
	assert.Contains(t, h.view(), "db closed")
	h.send(entryMsg{err: model.ErrNotFound})
	assert.Contains(t, h.view(), "not found")
}

func TestQuit(t *testing.T) {
	h := newHarness(t, entry("a", model.Text{Content: "1"}))
	for _, k := range []tea.KeyMsg{
		{Type: tea.KeyCtrlC},
		{Type: tea.KeyRunes, Runes: []rune("q")},
	} {
		_, cmd := h.m.Update(k)
		require.NotNil(t, cmd)
		assert.IsType(t, tea.QuitMsg{}, cmd())
	}
	h.keys("enter")
	_, cmd := h.m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	assert.IsType(t, tea.QuitMsg{}, cmd())
}

func TestScrolling(t *testing.T) {
	var entries []app.Entry
	for i := range 20 {
		entries = append(entries, entry(strings.Repeat("x", i+1), model.Text{Content: "c"}))
	}
	h := newHarness(t, entries...)
	h.send(tea.WindowSizeMsg{Width: 80, Height: 10})
	for range 10 {
		h.keys("j")
	}
	assert.Equal(t, 10, h.m.cursor)
	assert.Equal(t, 8, h.m.offset)
	v := h.view()
	assert.NotContains(t, v, " x\n")
	for range 10 {
		h.keys("k")
	}
	assert.Equal(t, 0, h.m.offset)
}

func TestShorten(t *testing.T) {
	assert.Equal(t, "a b", shorten("a\nb", 5))
	assert.Equal(t, "abcd…", shorten("abcdefgh", 5))
}
