package api

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
)

// Secret describes a Lastpass object.
type Secret struct {
	Fullname        string            `json:"fullname"`
	Group           string            `json:"group"`
	ID              string            `json:"id"`
	LastModifiedGmt string            `json:"last_modified_gmt"`
	LastTouch       string            `json:"last_touch"`
	Name            string            `json:"name"`
	Note            string            `json:"note"`
	Password        string            `json:"password"`
	Share           string            `json:"share"`
	URL             string            `json:"url"`
	Username        string            `json:"username"`
	CustomFields    map[string]string `json:"custom_fields"`
}

// Client is our Lastpass (lpass) wrapper client.
type Client struct {
	Username            string
	Password            string
	CredentialsProvided bool
	loginMutex          sync.Mutex
	loggedIn            bool
	// vaultMutex serializes lpass commands that modify the vault. lpass
	// processes share one local blob and one upload queue: concurrent
	// writes corrupt each other ("Could not unbase64 the given bytes").
	// Reads take the shared lock, so they still run in parallel with each
	// other but never while a write is in flight.
	vaultMutex sync.RWMutex
}

func (s *Secret) genCustomFields() {
	notes := make(map[string]string)
	if strings.HasPrefix(s.Note, "NoteType:") {
		splitted := strings.Split(s.Note, "\n")
		for _, split := range splitted {
			re := regexp.MustCompile(`:`)
			s := re.Split(split, 2)
			if s[0] == "Notes" {
				break
			}
			if len(s) == 2 {
				notes[s[0]] = s[1]
			}
		}
		// Fix for Notes with multiline. Always last in end of the string.
		n := strings.Split(s.Note, "\nNotes:")
		if len(n) == 2 {
			notes["Notes"] = n[1]
		}
	}
	s.CustomFields = notes
}

func (s *Secret) getTemplate() string {
	template := fmt.Sprintf(`Name: %s
URL: %s
Username: %s
Password: %s
Notes:    # Add notes below this line.
%s
`, s.Name, s.URL, s.Username, s.Password, s.Note)
	return template
}

func (c *Client) login() error {
	c.loginMutex.Lock()
	defer c.loginMutex.Unlock()

	if c.loggedIn {
		return nil
	}

	if !c.CredentialsProvided {
		return errors.New("LastPass provider not configured. Please provide username and password (eg: environment variables LASTPASS_USER and LASTPASS_PASSWORD)")
	}

	cmd := exec.Command("lpass", "status", "-q")
	err := cmd.Run()
	if err != nil {
		cmd := exec.Command("lpass", "login", c.Username)
		var inbuf, errbuf bytes.Buffer
		cmd.Env = os.Environ()
		cmd.Env = append(cmd.Env, "LPASS_DISABLE_PINENTRY=1")
		inbuf.Write([]byte(c.Password))
		cmd.Stdin = &inbuf
		cmd.Stderr = &errbuf
		err := cmd.Run()
		if err != nil {
			var err = errors.New(errbuf.String())
			return err
		}
	}

	c.loggedIn = true
	return nil
}
