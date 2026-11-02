package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ndreuu/go-gophkeeper/internal/client"
	"github.com/ndreuu/go-gophkeeper/internal/cryptoutil"
	"github.com/ndreuu/go-gophkeeper/internal/model"
	"golang.org/x/term"
)

var Version = "dev"

var BuildDate = "unknown"

const usage = `Usage: client [global flags] command [command flags] [ID]

Global flags: -config FILE -server-url HTTPS_URL -ca-file PEM -state-file FILE
Environment: GOPHKEEPER_CONFIG, GOPHKEEPER_SERVER_URL, GOPHKEEPER_CA_FILE,
             GOPHKEEPER_STATE_FILE (explicit flags override environment and JSON).

Commands:
  register -login NAME            Register; account password is entered twice
  login -login NAME               Authenticate and synchronize encrypted records
  logout                         Revoke the current session and remove its cache
  sync                           Synchronize the encrypted vault
  list                           Synchronize and decrypt entry summaries
  put [-file JSON]               Create an entry with a random ID
      [-id ID -revision N]       Update an entry using its last known revision
  get [-out FILE] ID              Decrypt JSON, or export a binary entry to FILE
  delete [-revision N] ID         Delete using the current or supplied revision
  version                        Show release version and build date
  help                           Show this help

Command flags must precede ID. Passwords are prompted without terminal echo.
When stdin is piped, each password occupies one line. For put without -file,
enter the master password (twice on first vault setup), then the secret JSON to EOF.
Account and master passwords are separate; master passwords never leave the client.
`

type runner struct {
	ctx         context.Context
	in          io.Reader
	reader      *bufio.Reader
	out, errOut io.Writer
	cfg         config
	api         *client.Client
	state       state
}

// Run executes one client command using injectable input and output streams.
// Prompts go to errOut, command results are JSON on out, and errors contain no passwords.
// Configuration precedence is defaults, JSON, environment, then explicit flags.
func Run(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer) (err error) {
	defer func() {
		if errors.Is(err, flag.ErrHelp) {
			err = nil
		}
	}()
	if in == nil || out == nil || errOut == nil {
		return errors.New("input and output streams are required")
	}
	if len(args) == 0 || (len(args) == 1 && args[0] == "help") {
		_, err := fmt.Fprint(out, usage)
		return err
	}
	if len(args) == 1 && args[0] == "version" {
		return json.NewEncoder(out).Encode(map[string]string{"version": Version, "build_date": BuildDate})
	}
	cfg, rest, err := parseConfig(args, errOut)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return errors.New("a command is required; run client help")
	}
	if rest[0] == "help" {
		_, err := fmt.Fprint(out, usage)
		return err
	}
	if rest[0] == "version" {
		return json.NewEncoder(out).Encode(map[string]string{"version": Version, "build_date": BuildDate})
	}
	api, err := client.New(cfg.ServerURL, cfg.CAFile)
	if err != nil {
		return err
	}
	r := runner{ctx: ctx, in: in, reader: bufio.NewReader(in), out: out, errOut: errOut, cfg: cfg, api: api}
	switch rest[0] {
	case "register", "login":
		return r.authenticate(rest[0], rest[1:])
	case "logout", "sync", "list", "put", "get", "delete":
		r.state, err = loadState(cfg)
		if err != nil {
			return err
		}
		r.api.SetToken(r.state.Token)
		if rest[0] != "logout" && !r.state.ExpiresAt.After(time.Now()) {
			return errors.New("session expired; log in again")
		}
	default:
		return fmt.Errorf("unknown command %q; run client help", rest[0])
	}
	switch rest[0] {
	case "logout":
		return r.logout(rest[1:])
	case "sync":
		return r.syncCommand(rest[1:])
	case "list":
		return r.list(rest[1:])
	case "put":
		return r.put(rest[1:])
	case "get":
		return r.get(rest[1:])
	case "delete":
		return r.delete(rest[1:])
	}
	return nil
}

func (r *runner) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(r.errOut)
	return fs
}

func (r *runner) password(prompt string) (string, error) {
	if _, err := fmt.Fprint(r.errOut, prompt); err != nil {
		return "", err
	}
	var data []byte
	if f, ok := r.in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		var err error
		data, err = term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(r.errOut)
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
	} else {
		line, err := r.reader.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			return "", errors.New("password must contain 8 to 1024 bytes")
		}
		if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
			return "", errors.New("read password: input ended")
		}
		data = []byte(strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r"))
	}
	if len(data) < 8 || len(data) > 1024 {
		return "", errors.New("password must contain 8 to 1024 bytes")
	}
	return string(data), nil
}

func (r *runner) authenticate(command string, args []string) error {
	fs := r.flags(command)
	login := fs.String("login", "", "account login")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *login == "" {
		return errors.New("use " + command + " -login NAME")
	}
	password, err := r.password("Account password: ")
	if err != nil {
		return err
	}
	if command == "register" {
		confirmation, err := r.password("Confirm account password: ")
		if err != nil {
			return err
		}
		if confirmation != password {
			return errors.New("account password confirmation does not match")
		}
	}
	credentials := model.Credentials{Login: *login, Password: password}
	var auth model.AuthResult
	if command == "register" {
		auth, err = r.api.Register(r.ctx, credentials)
	} else {
		auth, err = r.api.Login(r.ctx, credentials)
	}
	if err != nil {
		return err
	}
	if auth.Token == "" || len(auth.VaultSalt) != 16 || !auth.ExpiresAt.After(time.Now()) {
		return errors.New("server returned invalid session data")
	}
	r.state = state{Version: 1, ServerURL: r.cfg.ServerURL, Token: auth.Token, VaultSalt: auth.VaultSalt, ExpiresAt: auth.ExpiresAt, Records: []model.Record{}}
	r.api.SetToken(auth.Token)
	if err := saveState(r.cfg.StateFile, r.state); err != nil {
		_ = r.api.Logout(r.ctx)
		return err
	}
	if err := r.sync(); err != nil {
		return fmt.Errorf("authenticated, but synchronization failed: %w", err)
	}
	return r.print(map[string]any{"status": "authenticated", "entries": r.visibleCount(), "expires_at": auth.ExpiresAt})
}

func (r *runner) print(value any) error { return json.NewEncoder(r.out).Encode(value) }

func (r *runner) sync() error {
	records, err := r.api.List(r.ctx)
	if err != nil {
		return err
	}
	if records == nil {
		records = []model.Record{}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	r.state.Records = records
	return saveState(r.cfg.StateFile, r.state)
}

func (r *runner) syncCommand(args []string) error {
	if len(args) != 0 {
		return errors.New("sync takes no arguments")
	}
	if err := r.sync(); err != nil {
		return err
	}
	return r.print(map[string]any{"status": "synchronized", "entries": r.visibleCount()})
}

func (r *runner) logout(args []string) error {
	if len(args) != 0 {
		return errors.New("logout takes no arguments")
	}
	if err := r.api.Logout(r.ctx); err != nil && !errors.Is(err, model.ErrUnauthorized) {
		return err
	}
	if err := os.Remove(r.cfg.StateFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove session file: %w", err)
	}
	return r.print(map[string]string{"status": "logged out"})
}

func (r *runner) masterKey(confirm bool) ([]byte, error) {
	password, err := r.password("Master password: ")
	if err != nil {
		return nil, err
	}
	if confirm {
		again, err := r.password("Confirm master password: ")
		if err != nil {
			return nil, err
		}
		if again != password {
			return nil, errors.New("master password confirmation does not match")
		}
	}
	return cryptoutil.DeriveKey(password, r.state.VaultSalt)
}

func clearKey(key []byte) { clear(key) }

type summary struct {
	ID       string            `json:"id"`
	Revision int64             `json:"revision"`
	Kind     model.Kind        `json:"kind"`
	Title    string            `json:"title"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

func (r *runner) list(args []string) error {
	if len(args) != 0 {
		return errors.New("list takes no arguments")
	}
	if err := r.sync(); err != nil {
		return err
	}
	items := make([]summary, 0, len(r.state.Records))
	if len(r.state.Records) == 0 {
		return r.print(items)
	}
	key, err := r.masterKey(false)
	if err != nil {
		return err
	}
	defer clearKey(key)
	if verifier, ok := r.cachedVerifier(); ok {
		if err := checkVerifier(key, verifier); err != nil {
			return err
		}
	}
	for _, record := range r.state.Records {
		if record.ID == model.MasterVerifierID {
			continue
		}
		secret, err := cryptoutil.Decrypt(key, record.ID, record.Ciphertext)
		if err != nil {
			return errors.New("cannot decrypt vault; check the master password and encrypted data")
		}
		items = append(items, summary{ID: record.ID, Revision: record.Revision, Kind: secret.Kind, Title: secret.Title, Metadata: secret.Metadata})
	}
	return r.print(items)
}

func (r *runner) put(args []string) error {
	fs := r.flags("put")
	file := fs.String("file", "", "secret JSON input file; otherwise stdin after the password")
	id := fs.String("id", "", "existing record ID")
	revision := fs.Int64("revision", 0, "expected revision for an existing record")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("put accepts flags only")
	}
	if *id == model.MasterVerifierID {
		return errors.New("the vault key verifier is reserved and cannot be edited")
	}
	revisionSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "revision" {
			revisionSet = true
		}
	})
	if *id != "" && (!revisionSet || *revision < 1) {
		return errors.New("editing requires -id ID -revision N with the revision previously read from the server")
	}
	if *id == "" && revisionSet {
		return errors.New("revision is only accepted with an existing -id")
	}
	if err := r.sync(); err != nil {
		return err
	}
	var secret model.Secret
	if *file != "" {
		f, err := os.Open(*file)
		if err != nil {
			return fmt.Errorf("open secret JSON: %w", err)
		}
		err = decodeJSON(io.LimitReader(f, model.MaxCiphertextSize), &secret)
		f.Close()
		if err != nil {
			return fmt.Errorf("decode secret JSON: %w", err)
		}
		if err := cryptoutil.Validate(secret); err != nil {
			return err
		}
	}
	_, initialized := r.cachedVerifier()
	key, err := r.masterKey(!initialized && r.visibleCount() == 0)
	if err != nil {
		return err
	}
	defer clearKey(key)
	if *file == "" {
		fmt.Fprintln(r.errOut, "Secret JSON (finish with EOF):")
		if err := decodeJSON(io.LimitReader(r.reader, model.MaxCiphertextSize), &secret); err != nil {
			return fmt.Errorf("decode secret JSON: %w", err)
		}
	}
	if err := cryptoutil.Validate(secret); err != nil {
		return err
	}
	if err := r.ensureVerifier(key); err != nil {
		return err
	}
	if *id == "" {
		*id, err = cryptoutil.NewID()
		if err != nil {
			return err
		}
	}
	ciphertext, err := cryptoutil.Encrypt(key, *id, secret)
	if err != nil {
		return err
	}
	record, err := r.api.Put(r.ctx, *id, model.PutRequest{ExpectedRevision: *revision, Ciphertext: ciphertext})
	if errors.Is(err, model.ErrConflict) {
		return fmt.Errorf("entry changed on another client; sync, inspect the latest revision, and retry explicitly: %w", err)
	}
	if err != nil {
		return err
	}
	if err := r.sync(); err != nil {
		return fmt.Errorf("entry saved, but cache synchronization failed: %w", err)
	}
	return r.print(map[string]any{"id": record.ID, "revision": record.Revision})
}

func (r *runner) get(args []string) error {
	fs := r.flags("get")
	output := fs.String("out", "", "destination for binary bytes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("use get [-out FILE] ID")
	}
	if fs.Arg(0) == model.MasterVerifierID {
		return errors.New("the vault key verifier is reserved")
	}
	if err := r.sync(); err != nil {
		return err
	}
	record, err := r.findRecord(fs.Arg(0))
	if err != nil {
		return err
	}
	key, err := r.masterKey(false)
	if err != nil {
		return err
	}
	defer clearKey(key)
	if verifier, ok := r.cachedVerifier(); ok {
		if err := checkVerifier(key, verifier); err != nil {
			return err
		}
	}
	secret, err := cryptoutil.Decrypt(key, record.ID, record.Ciphertext)
	if err != nil {
		return errors.New("cannot decrypt entry; check the master password and encrypted data")
	}
	if *output != "" {
		if secret.Kind != model.KindBinary || secret.Binary == nil {
			return errors.New("-out requires a binary entry")
		}
		if err := exportPrivateFile(*output, bytes.NewReader(secret.Binary.Data)); err != nil {
			return err
		}
		return r.print(map[string]string{"id": record.ID, "path": *output})
	}
	return r.print(secret)
}

func (r *runner) findRecord(id string) (model.Record, error) {
	for _, record := range r.state.Records {
		if record.ID == id {
			return record, nil
		}
	}
	return model.Record{}, fmt.Errorf("entry %s: %w", id, model.ErrNotFound)
}

func (r *runner) delete(args []string) error {
	fs := r.flags("delete")
	revision := fs.Int64("revision", 0, "expected revision; defaults to the freshly fetched revision")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || *revision < 0 {
		return errors.New("use delete [-revision N] ID")
	}
	if fs.Arg(0) == model.MasterVerifierID {
		return errors.New("the vault key verifier is reserved and cannot be deleted")
	}
	if err := r.sync(); err != nil {
		return err
	}
	record, err := r.findRecord(fs.Arg(0))
	if err != nil {
		return err
	}
	if *revision == 0 {
		*revision = record.Revision
	}
	if err := r.api.Delete(r.ctx, record.ID, *revision); err != nil {
		if errors.Is(err, model.ErrConflict) {
			return fmt.Errorf("entry changed on another client; sync and inspect it before deleting: %w", err)
		}
		return err
	}
	if err := r.sync(); err != nil {
		return fmt.Errorf("entry deleted, but cache synchronization failed: %w", err)
	}
	return r.print(map[string]string{"status": "deleted", "id": record.ID})
}
