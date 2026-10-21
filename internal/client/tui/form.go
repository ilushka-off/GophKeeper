package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/ilushka-off/GophKeeper/internal/model"
	"github.com/ilushka-off/GophKeeper/internal/otp"
)

// field keys of the add forms.
const (
	fName     = "name"
	fLogin    = "login"
	fPassword = "password"
	fText     = "text"
	fNumber   = "number"
	fHolder   = "holder"
	fExpiry   = "expiry"
	fCVV      = "cvv"
	fSecret   = "secret"
	fAccount  = "account"
	fMeta     = "meta"
)

type formField struct {
	key   string
	label string
	input textinput.Model
}

// form is the add form of one record type.
type form struct {
	typ    model.RecordType
	fields []formField
	active int
	err    string
}

func newForm(typ model.RecordType) *form {
	f := &form{typ: typ}
	add := func(key, label, placeholder string, secret bool) {
		in := textinput.New()
		in.Prompt = ""
		in.Placeholder = placeholder
		in.CharLimit = 4096
		in.Width = 50
		_ = in.Cursor.SetMode(cursor.CursorStatic)
		if secret {
			in.EchoMode = textinput.EchoPassword
			in.EchoCharacter = '•'
		}
		f.fields = append(f.fields, formField{key: key, label: label, input: in})
	}
	add(fName, "Name", "", false)
	switch typ {
	case model.TypeCredentials:
		add(fLogin, "Login", "", false)
		add(fPassword, "Password", "", true)
	case model.TypeText:
		add(fText, "Text", "", false)
	case model.TypeCard:
		add(fNumber, "Number", "4242 4242 4242 4242", false)
		add(fHolder, "Holder", "", false)
		add(fExpiry, "Expiry", "MM/YY", false)
		add(fCVV, "CVV", "", true)
	case model.TypeOTP:
		add(fSecret, "Secret", "base32 secret or otpauth:// URI", true)
		add(fAccount, "Account", "", false)
	}
	add(fMeta, "Meta", "optional notes", false)
	return f
}

// focus moves the cursor to field i, wrapping around.
func (f *form) focus(i int) tea.Cmd {
	n := len(f.fields)
	f.active = (i%n + n) % n
	var cmd tea.Cmd
	for j := range f.fields {
		if j == f.active {
			cmd = f.fields[j].input.Focus()
		} else {
			f.fields[j].input.Blur()
		}
	}
	return cmd
}

func (f *form) update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	f.fields[f.active].input, cmd = f.fields[f.active].input.Update(msg)
	return cmd
}

func (f *form) value(key string) string {
	for _, fl := range f.fields {
		if fl.key == key {
			return strings.TrimSpace(fl.input.Value())
		}
	}
	return ""
}

// payload builds and validates the record from the form values.
func (f *form) payload() (model.Payload, error) {
	p := model.Payload{Name: f.value(fName), Meta: f.value(fMeta)}
	switch f.typ {
	case model.TypeCredentials:
		p.Data = model.Credentials{Login: f.value(fLogin), Password: f.value(fPassword)}
	case model.TypeText:
		p.Data = model.Text{Content: f.value(fText)}
	case model.TypeCard:
		p.Data = model.Card{
			Number: model.NormalizeCardNumber(f.value(fNumber)),
			Holder: f.value(fHolder),
			Expiry: f.value(fExpiry),
			CVV:    f.value(fCVV),
		}
	case model.TypeOTP:
		data := model.OTP{Secret: f.value(fSecret), Account: f.value(fAccount)}
		if strings.HasPrefix(data.Secret, "otpauth://") {
			u, err := otp.ParseURI(data.Secret)
			if err != nil {
				return model.Payload{}, err
			}
			data = model.OTP{Secret: u.Secret, Issuer: u.Issuer, Account: u.Account,
				Algorithm: u.Algorithm, Digits: u.Digits, Period: u.Period}
			if acc := f.value(fAccount); acc != "" {
				data.Account = acc
			}
		}
		if p.Name == "" {
			p.Name = data.Issuer
		}
		p.Data = data
	}
	if err := p.Validate(); err != nil {
		return model.Payload{}, err
	}
	return p, nil
}
