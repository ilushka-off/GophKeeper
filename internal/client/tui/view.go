package tui

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"

	"github.com/ilushka-off/GophKeeper/internal/client/app"
	"github.com/ilushka-off/GophKeeper/internal/model"
)

var (
	titleStyle    = lipgloss.NewStyle().Bold(true)
	selectedStyle = lipgloss.NewStyle().Reverse(true)
	dimStyle      = lipgloss.NewStyle().Faint(true)
	errStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	okStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	labelStyle    = lipgloss.NewStyle().Width(10)
)

const helpText = `Keys
  ↑/k ↓/j   move              enter   open record
  tab        next type filter  /       search by name
  a          add record        d       delete record
  s          sync              r       reveal secrets (record view)
  esc        back              q       quit
  ?          this help

Binary files are added and saved with the command line:
  gophkeeper add binary, gophkeeper get <id> -o <file>

Press any key to close.`

// View implements tea.Model.
func (m Model) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("GophKeeper"))
	b.WriteString("\n\n")
	switch {
	case m.help:
		b.WriteString(helpText)
		b.WriteString("\n")
		return b.String()
	case m.screen == screenView:
		m.renderEntry(&b)
	case m.screen == screenPick:
		m.renderPick(&b)
	case m.screen == screenForm:
		m.renderForm(&b)
	default:
		m.renderList(&b)
	}
	b.WriteString("\n")
	switch {
	case m.confirm:
		b.WriteString(errStyle.Render("Delete this record? (y/N)"))
	case m.errMsg != "":
		b.WriteString(errStyle.Render("Error: " + m.errMsg))
	case m.status != "":
		b.WriteString(okStyle.Render(m.status))
	}
	b.WriteString("\n")
	return b.String()
}

func (m Model) renderList(b *strings.Builder) {
	tabs := make([]string, len(filters))
	for i, t := range filters {
		name := string(t)
		if t == "" {
			name = "all"
		}
		if i == m.filter {
			tabs[i] = selectedStyle.Render(" " + name + " ")
		} else {
			tabs[i] = " " + name + " "
		}
	}
	b.WriteString(strings.Join(tabs, ""))
	b.WriteString("\n")
	if m.finding || m.search.Value() != "" {
		b.WriteString(m.search.View())
		b.WriteString("\n")
	}
	b.WriteString("\n")
	v := m.visible()
	if len(v) == 0 {
		b.WriteString(dimStyle.Render("No records. Press a to add one."))
		b.WriteString("\n")
	}
	end := len(v)
	if rows := m.listRows(); rows > 0 && m.offset+rows < end {
		end = m.offset + rows
	}
	for i := m.offset; i < end; i++ {
		e := v[i]
		mark := " "
		if e.Dirty {
			mark = "*"
		}
		line := fmt.Sprintf("%s %-12s %s", mark, e.Payload.Type(), shorten(e.Payload.Name, 40))
		if i == m.cursor {
			line = selectedStyle.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(dimStyle.Render(fmt.Sprintf("%d record(s), * not synced · enter open · a add · s sync · ? help · q quit", len(v))))
	b.WriteString("\n")
}

func (m Model) renderEntry(b *strings.Builder) {
	for _, f := range entryFields(m.current, m.reveal, m.now()) {
		if f[1] == "" {
			continue
		}
		b.WriteString(labelStyle.Render(f[0] + ":"))
		b.WriteString(f[1])
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("esc back · r reveal · d delete · q quit"))
	b.WriteString("\n")
}

// entryFields returns the label/value pairs shown for a record. Secrets are masked unless reveal.
func entryFields(e app.Entry, reveal bool, now time.Time) [][2]string {
	secret := func(s string) string {
		if reveal || s == "" {
			return s
		}
		return strings.Repeat("•", 8)
	}
	out := [][2]string{
		{"ID", e.ID.String()},
		{"Type", string(e.Payload.Type())},
		{"Name", e.Payload.Name},
	}
	switch d := e.Payload.Data.(type) {
	case model.Credentials:
		out = append(out, [2]string{"Login", d.Login}, [2]string{"Password", secret(d.Password)})
	case model.Text:
		out = append(out, [2]string{"Text", d.Content})
	case model.Binary:
		out = append(out,
			[2]string{"File", d.FileName},
			[2]string{"Size", fmt.Sprintf("%d bytes", d.Size)},
			[2]string{"Save", "gophkeeper get " + e.ID.String()[:8] + " -o <file>"})
	case model.Card:
		number := d.Number
		if !reveal && len(number) > 4 {
			number = strings.Repeat("•", 4) + " " + number[len(number)-4:]
		}
		out = append(out,
			[2]string{"Number", number},
			[2]string{"Holder", d.Holder},
			[2]string{"Expiry", d.Expiry},
			[2]string{"CVV", secret(d.CVV)})
	case model.OTP:
		out = append(out, [2]string{"Issuer", d.Issuer}, [2]string{"Account", d.Account})
		if code, left, err := d.Code(now); err == nil {
			out = append(out, [2]string{"Code", fmt.Sprintf("%s (valid %ds)", code, int(left.Seconds()))})
		} else {
			out = append(out, [2]string{"Code", err.Error()})
		}
	}
	out = append(out, [2]string{"Meta", e.Payload.Meta}, [2]string{"Updated", e.UpdatedAt.Local().Format("2006-01-02 15:04:05")})
	if e.Dirty {
		out = append(out, [2]string{"Synced", "no"})
	}
	return out
}

func (m Model) renderPick(b *strings.Builder) {
	b.WriteString("New record type:\n\n")
	for i, t := range addTypes {
		line := fmt.Sprintf("%d. %s", i+1, t)
		if i == m.pick {
			line = selectedStyle.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("enter choose · esc back"))
	b.WriteString("\n")
}

func (m Model) renderForm(b *strings.Builder) {
	f := m.form
	b.WriteString("New " + string(f.typ) + "\n\n")
	for i, fl := range f.fields {
		cursor := "  "
		if i == f.active {
			cursor = "> "
		}
		b.WriteString(cursor)
		b.WriteString(labelStyle.Render(fl.label))
		b.WriteString(fl.input.View())
		b.WriteString("\n")
	}
	if f.err != "" {
		b.WriteString("\n")
		b.WriteString(errStyle.Render(f.err))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("tab/enter next field · ctrl+s or enter on the last field save · esc cancel"))
	b.WriteString("\n")
}

func shorten(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}
