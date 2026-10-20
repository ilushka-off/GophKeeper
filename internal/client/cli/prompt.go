package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// Prompter asks the user for secrets.
type Prompter interface {
	// Password prints prompt and reads a line without echo when possible.
	Password(prompt string) (string, error)
}

// TerminalPrompter reads passwords from a terminal without echo, or line by line
// from a non-terminal input such as a pipe.
type TerminalPrompter struct {
	in     io.Reader
	out    io.Writer
	reader *bufio.Reader
}

// NewTerminalPrompter creates a prompter that reads from in and prints prompts to out.
func NewTerminalPrompter(in io.Reader, out io.Writer) *TerminalPrompter {
	return &TerminalPrompter{in: in, out: out}
}

// Password implements Prompter.
func (p *TerminalPrompter) Password(prompt string) (string, error) {
	_, _ = fmt.Fprint(p.out, prompt)
	if f, ok := p.in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		b, err := term.ReadPassword(int(f.Fd()))
		_, _ = fmt.Fprintln(p.out)
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		return string(b), nil
	}
	if p.reader == nil {
		p.reader = bufio.NewReader(p.in)
	}
	line, err := p.reader.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", fmt.Errorf("read password: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}
