// Package tui implements an interactive terminal interface of the GophKeeper client on bubbletea:
// a list of records, a record view with live OTP codes and forms to add new records.
package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/uuid"

	"github.com/ilushka-off/GophKeeper/internal/client/app"
	"github.com/ilushka-off/GophKeeper/internal/model"
)

// Vault is the part of the client application the TUI works with. *app.App implements it.
type Vault interface {
	List(ctx context.Context, filter model.RecordType) ([]app.Entry, error)
	Get(ctx context.Context, id uuid.UUID) (app.Entry, error)
	Add(ctx context.Context, p model.Payload) (uuid.UUID, error)
	Delete(ctx context.Context, id uuid.UUID) error
	Sync(ctx context.Context) (app.SyncReport, error)
}

type screen int

const (
	screenList screen = iota
	screenView
	screenPick
	screenForm
)

// filters are the type filters the list cycles through; the empty type shows everything.
var filters = append([]model.RecordType{""}, model.RecordTypes...)

// addTypes are the record types that can be created from the TUI.
// Binary records need a file and are added with `gophkeeper add binary`.
var addTypes = []model.RecordType{model.TypeCredentials, model.TypeText, model.TypeCard, model.TypeOTP}

type (
	entriesMsg struct {
		entries []app.Entry
		err     error
	}
	entryMsg struct {
		entry app.Entry
		err   error
	}
	addedMsg struct {
		id  uuid.UUID
		err error
	}
	deletedMsg struct{ err error }
	syncedMsg  struct {
		report app.SyncReport
		err    error
	}
	tickMsg struct{ id int }
)

// Model is the bubbletea model of the TUI.
type Model struct {
	ctx   context.Context
	vault Vault
	now   func() time.Time
	tick  func(id int) tea.Cmd

	screen  screen
	entries []app.Entry
	filter  int
	cursor  int
	offset  int
	search  textinput.Model
	finding bool

	current app.Entry
	reveal  bool
	tickID  int

	pick int
	form *form

	confirm bool
	help    bool
	status  string
	errMsg  string
	width   int
	height  int
}

// New creates the TUI model over v. The context bounds all vault calls.
func New(ctx context.Context, v Vault) Model {
	search := textinput.New()
	search.Prompt = "/"
	search.Placeholder = "search by name"
	search.Width = 40
	_ = search.Cursor.SetMode(cursor.CursorStatic)
	return Model{
		ctx:    ctx,
		vault:  v,
		now:    time.Now,
		tick:   tickEvery,
		search: search,
	}
}

func tickEvery(id int) tea.Cmd {
	return tea.Tick(time.Second, func(time.Time) tea.Msg { return tickMsg{id: id} })
}

// Init implements tea.Model: it loads the records.
func (m Model) Init() tea.Cmd {
	return m.load()
}

func (m Model) load() tea.Cmd {
	return func() tea.Msg {
		entries, err := m.vault.List(m.ctx, "")
		return entriesMsg{entries: entries, err: err}
	}
}

func (m Model) sync() tea.Cmd {
	return func() tea.Msg {
		rep, err := m.vault.Sync(m.ctx)
		return syncedMsg{report: rep, err: err}
	}
}

// visible returns the records matching the type filter and the search query.
func (m Model) visible() []app.Entry {
	typ := filters[m.filter]
	q := strings.ToLower(strings.TrimSpace(m.search.Value()))
	out := make([]app.Entry, 0, len(m.entries))
	for _, e := range m.entries {
		if typ != "" && e.Payload.Type() != typ {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(e.Payload.Name), q) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func (m *Model) setErr(err error) {
	m.status = ""
	m.errMsg = err.Error()
}

func (m *Model) setStatus(s string) {
	m.status = s
	m.errMsg = ""
}

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case entriesMsg:
		if msg.err != nil {
			m.setErr(msg.err)
			return m, nil
		}
		m.entries = msg.entries
		m.clampCursor()
		return m, nil
	case entryMsg:
		if msg.err != nil {
			m.setErr(msg.err)
			return m, nil
		}
		return m.openEntry(msg.entry)
	case addedMsg:
		if msg.err != nil {
			m.setErr(msg.err)
			return m, nil
		}
		m.form = nil
		m.screen = screenList
		m.setStatus("Added " + msg.id.String()[:8] + ", syncing…")
		return m, tea.Batch(m.load(), m.sync())
	case deletedMsg:
		if msg.err != nil {
			m.setErr(msg.err)
			return m, nil
		}
		m.screen = screenList
		m.setStatus("Deleted, syncing…")
		return m, tea.Batch(m.load(), m.sync())
	case syncedMsg:
		if msg.err != nil {
			m.setErr(fmt.Errorf("sync failed, changes are kept locally: %w", msg.err))
			return m, nil
		}
		r := msg.report
		m.setStatus(fmt.Sprintf("Synced: pushed %d, pulled %d, conflicts %d.", r.Pushed, r.Pulled, r.Conflicts))
		return m, m.load()
	case tickMsg:
		if msg.id != m.tickID || m.screen != screenView {
			return m, nil
		}
		return m, m.tick(m.tickID)
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.Type == tea.KeyCtrlC {
		return m, tea.Quit
	}
	if m.help {
		m.help = false
		return m, nil
	}
	switch m.screen {
	case screenView:
		return m.viewKey(msg)
	case screenPick:
		return m.pickKey(msg)
	case screenForm:
		return m.formKey(msg)
	default:
		return m.listKey(msg)
	}
}

func (m *Model) clampCursor() {
	n := len(m.visible())
	if m.cursor >= n {
		m.cursor = n - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	rows := m.listRows()
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if rows > 0 && m.cursor >= m.offset+rows {
		m.offset = m.cursor - rows + 1
	}
}

// listRows is how many records fit on the screen; 0 means no limit.
func (m Model) listRows() int {
	if m.height == 0 {
		return 0
	}
	return max(m.height-7, 1)
}

func (m Model) listKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.finding {
		switch msg.Type {
		case tea.KeyEnter, tea.KeyEsc:
			m.finding = false
			m.search.Blur()
			if msg.Type == tea.KeyEsc {
				m.search.SetValue("")
			}
			m.clampCursor()
			return m, nil
		}
		var cmd tea.Cmd
		m.search, cmd = m.search.Update(msg)
		m.cursor = 0
		m.clampCursor()
		return m, cmd
	}
	if m.confirm {
		return m.confirmKey(msg)
	}
	switch msg.String() {
	case "q":
		return m, tea.Quit
	case "?":
		m.help = true
	case "up", "k":
		m.cursor--
		m.clampCursor()
	case "down", "j":
		m.cursor++
		m.clampCursor()
	case "tab":
		m.filter = (m.filter + 1) % len(filters)
		m.clampCursor()
	case "shift+tab":
		m.filter = (m.filter + len(filters) - 1) % len(filters)
		m.clampCursor()
	case "/":
		m.finding = true
		return m, m.search.Focus()
	case "esc":
		m.search.SetValue("")
		m.clampCursor()
	case "a":
		m.screen = screenPick
		m.pick = 0
	case "s":
		m.setStatus("Syncing…")
		return m, m.sync()
	case "d":
		if _, ok := m.selected(); ok {
			m.confirm = true
		}
	case "enter":
		if e, ok := m.selected(); ok {
			id := e.ID
			return m, func() tea.Msg {
				e, err := m.vault.Get(m.ctx, id)
				return entryMsg{entry: e, err: err}
			}
		}
	}
	return m, nil
}

func (m Model) selected() (app.Entry, bool) {
	v := m.visible()
	if m.cursor < 0 || m.cursor >= len(v) {
		return app.Entry{}, false
	}
	return v[m.cursor], true
}

func (m Model) confirmKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	m.confirm = false
	if msg.String() != "y" {
		return m, nil
	}
	var id uuid.UUID
	if m.screen == screenView {
		id = m.current.ID
	} else {
		e, ok := m.selected()
		if !ok {
			return m, nil
		}
		id = e.ID
	}
	return m, func() tea.Msg { return deletedMsg{err: m.vault.Delete(m.ctx, id)} }
}

func (m Model) openEntry(e app.Entry) (tea.Model, tea.Cmd) {
	m.current = e
	m.reveal = false
	m.screen = screenView
	m.tickID++
	if e.Payload.Type() == model.TypeOTP {
		return m, m.tick(m.tickID)
	}
	return m, nil
}

func (m Model) viewKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.confirm {
		return m.confirmKey(msg)
	}
	switch msg.String() {
	case "q":
		return m, tea.Quit
	case "?":
		m.help = true
	case "esc", "backspace", "left", "h":
		m.screen = screenList
		m.tickID++
	case "r":
		m.reveal = !m.reveal
	case "d":
		m.confirm = true
	}
	return m, nil
}

func (m Model) pickKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.screen = screenList
	case "up", "k":
		m.pick = (m.pick + len(addTypes) - 1) % len(addTypes)
	case "down", "j", "tab":
		m.pick = (m.pick + 1) % len(addTypes)
	case "1", "2", "3", "4":
		m.pick = int(msg.Runes[0] - '1')
		return m.startForm()
	case "enter":
		return m.startForm()
	}
	return m, nil
}

func (m Model) startForm() (tea.Model, tea.Cmd) {
	m.form = newForm(addTypes[m.pick])
	m.screen = screenForm
	m.errMsg = ""
	return m, m.form.focus(0)
}

func (m Model) formKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	f := m.form
	switch msg.Type {
	case tea.KeyEsc:
		m.form = nil
		m.screen = screenList
		m.errMsg = ""
		return m, nil
	case tea.KeyTab, tea.KeyDown:
		return m, f.focus(f.active + 1)
	case tea.KeyShiftTab, tea.KeyUp:
		return m, f.focus(f.active - 1)
	case tea.KeyEnter, tea.KeyCtrlS:
		if msg.Type == tea.KeyEnter && f.active < len(f.fields)-1 {
			return m, f.focus(f.active + 1)
		}
		p, err := f.payload()
		if err != nil {
			f.err = err.Error()
			return m, nil
		}
		f.err = ""
		return m, func() tea.Msg {
			id, err := m.vault.Add(m.ctx, p)
			return addedMsg{id: id, err: err}
		}
	}
	return m, f.update(msg)
}
