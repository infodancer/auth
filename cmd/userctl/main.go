// Command userctl manages users in infodancer auth passwd files.
//
// Usage:
//
//	userctl [--domains <path>] add    <user@domain>   add user (prompts for password)
//	userctl [--domains <path>] del    <user@domain>   remove user
//	userctl [--domains <path>] list   <domain>        list users and mailboxes
//	userctl [--domains <path>] verify <user@domain>   verify user password
//
// The domains path can also be set via the INFODANCER_DOMAINS_PATH environment variable.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"golang.org/x/term"

	"github.com/infodancer/auth/passwd"
)

func main() {
	fs := flag.NewFlagSet("userctl", flag.ExitOnError)
	domainsPath := fs.String("domains", os.Getenv("INFODANCER_DOMAINS_PATH"), "path to domains directory")
	fs.Usage = usage

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(1)
	}

	args := fs.Args()
	if len(args) < 2 {
		usage()
		os.Exit(1)
	}

	if *domainsPath == "" {
		fmt.Fprintln(os.Stderr, "error: --domains path required (or set INFODANCER_DOMAINS_PATH)")
		os.Exit(1)
	}

	subcmd := args[0]
	target := args[1]

	var err error

	switch subcmd {
	case "add":
		var username, domainDir string
		username, domainDir, err = parseEmailTarget(*domainsPath, target)
		if err == nil {
			err = cmdAdd(filepath.Join(domainDir, "passwd"), username)
		}

	case "del":
		var username, domainDir string
		username, domainDir, err = parseEmailTarget(*domainsPath, target)
		if err == nil {
			err = cmdDel(filepath.Join(domainDir, "passwd"), username)
		}

	case "list":
		domainDir := filepath.Join(*domainsPath, target)
		err = cmdList(filepath.Join(domainDir, "passwd"))

	case "verify":
		var username, domainDir string
		username, domainDir, err = parseEmailTarget(*domainsPath, target)
		if err == nil {
			err = cmdVerify(domainDir, username)
		}

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

// parseEmailTarget splits user@domain and returns the username and domain directory path.
func parseEmailTarget(domainsPath, address string) (username, domainDir string, err error) {
	parts := strings.SplitN(address, "@", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid address %q: expected user@domain", address)
	}
	return parts[0], filepath.Join(domainsPath, parts[1]), nil
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
	if _, err := fmt.Fprintln(w, "USERNAME\tMAILBOX"); err != nil {
		return err
	}
	for _, u := range users {
		if _, err := fmt.Fprintf(w, "%s\t%s\n", u.Username, u.Mailbox); err != nil {
			return err
		}
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
  userctl [--domains <path>] add    <user@domain>   add user (prompts for password)
  userctl [--domains <path>] del    <user@domain>   remove user
  userctl [--domains <path>] list   <domain>        list users and mailboxes
  userctl [--domains <path>] verify <user@domain>   verify user password

The domains path can also be set via INFODANCER_DOMAINS_PATH.
`)
}
