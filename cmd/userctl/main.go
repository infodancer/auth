// Command userctl manages users in infodancer auth passwd files.
//
// Usage:
//
//	userctl add  <domain-dir> <username>   prompt for password and add user
//	userctl del  <domain-dir> <username>   remove user
//	userctl list <domain-dir>              list users and mailboxes
//	userctl verify <domain-dir> <username> verify user password
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"golang.org/x/term"

	"github.com/infodancer/auth/passwd"
)

func main() {
	if len(os.Args) < 3 {
		usage()
		os.Exit(1)
	}

	subcmd := os.Args[1]
	domainDir := os.Args[2]
	passwdPath := filepath.Join(domainDir, "passwd")

	var err error

	switch subcmd {
	case "add":
		if len(os.Args) < 4 {
			usage()
			os.Exit(1)
		}
		err = cmdAdd(passwdPath, os.Args[3])

	case "del":
		if len(os.Args) < 4 {
			usage()
			os.Exit(1)
		}
		err = cmdDel(passwdPath, os.Args[3])

	case "list":
		err = cmdList(passwdPath)

	case "verify":
		if len(os.Args) < 4 {
			usage()
			os.Exit(1)
		}
		err = cmdVerify(domainDir, os.Args[3])

	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", subcmd)
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func cmdAdd(passwdPath, username string) error {
	password, err := promptPassword("Password: ")
	if err != nil {
		return err
	}

	confirm, err := promptPassword("Confirm password: ")
	if err != nil {
		return err
	}

	if password != confirm {
		return fmt.Errorf("passwords do not match")
	}

	if err := passwd.AddUser(passwdPath, username, password); err != nil {
		return err
	}

	fmt.Printf("Added user %q\n", username)
	return nil
}

func cmdDel(passwdPath, username string) error {
	if err := passwd.DeleteUser(passwdPath, username); err != nil {
		return err
	}
	fmt.Printf("Deleted user %q\n", username)
	return nil
}

func cmdList(passwdPath string) error {
	users, err := passwd.ListUsers(passwdPath)
	if err != nil {
		return err
	}

	if len(users) == 0 {
		fmt.Println("no users")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "USERNAME\tMAILBOX")
	for _, u := range users {
		fmt.Fprintf(w, "%s\t%s\n", u.Username, u.Mailbox)
	}
	return w.Flush()
}

func cmdVerify(domainDir, username string) error {
	passwdPath := filepath.Join(domainDir, "passwd")
	keyDir := filepath.Join(domainDir, "keys")

	agent, err := passwd.NewAgent(passwdPath, keyDir)
	if err != nil {
		return fmt.Errorf("load passwd: %w", err)
	}
	defer func() { _ = agent.Close() }()

	password, err := promptPassword("Password: ")
	if err != nil {
		return err
	}

	session, err := agent.Authenticate(context.Background(), username, password)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	defer session.Clear()

	fmt.Printf("OK: %s (mailbox: %s)\n", session.User.Username, session.User.Mailbox)
	return nil
}

func promptPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr) // newline after hidden input
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return string(raw), nil
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  userctl add    <domain-dir> <username>   add a new user (prompts for password)
  userctl del    <domain-dir> <username>   remove a user
  userctl list   <domain-dir>              list users and mailboxes
  userctl verify <domain-dir> <username>   verify a user's password
`)
}
