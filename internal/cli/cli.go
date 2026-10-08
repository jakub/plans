// Package cli implements the plans command-line interface.
package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/jakub/plans/internal/artifact"
	"github.com/jakub/plans/internal/auth"
	"github.com/jakub/plans/internal/client"
	"github.com/jakub/plans/internal/protocol"
	"github.com/jakub/plans/internal/version"
)

// Streams contains the CLI standard streams.
type Streams struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
}

// Dependencies contains replaceable process dependencies for tests.
type Dependencies struct {
	HTTPClient *http.Client
	Random     io.Reader
	Getenv     func(string) string
	// UserConfigDir locates the directory holding the plans/ configuration
	// files. It defaults to os.UserConfigDir: $XDG_CONFIG_HOME, else
	// ~/.config.
	UserConfigDir func() (string, error)
}

// Run executes the CLI and returns a process exit code.
func Run(ctx context.Context, arguments []string, streams Streams, dependencies Dependencies) int {
	streams = defaultStreams(streams)
	dependencies = defaultDependencies(dependencies)
	if len(arguments) == 0 {
		writeUsage(streams.Err)

		return 2
	}

	var err error
	switch arguments[0] {
	case "publish":
		err = runPublish(ctx, arguments[1:], streams, dependencies)
	case "delete":
		err = runDelete(ctx, arguments[1:], streams, dependencies)
	case "token":
		err = runToken(arguments[1:], streams, dependencies)
	case "version":
		err = writeLine(streams.Out, version.String())
	case "help", "-h", "--help":
		writeUsage(streams.Out)

		return 0
	default:
		err = fmt.Errorf("unknown command %q", arguments[0])
	}
	if err != nil {
		_, _ = fmt.Fprintf(streams.Err, "plans: %v\n", err)

		return 1
	}

	return 0
}

func runPublish(ctx context.Context, arguments []string, streams Streams, dependencies Dependencies) error {
	flags := flag.NewFlagSet("plans publish", flag.ContinueOnError)
	flags.SetOutput(streams.Err)
	apiURL := flags.String("api-url", "", apiURLUsage)
	tokenFile := flags.String("token-file", dependencies.Getenv("PLANS_TOKEN_FILE"), "file containing the upload token")
	ttl := flags.String("ttl", "", "artifact lifetime, such as 12h, 7d, or 2w")
	keep := flags.Bool("keep", false, "publish without expiration")
	jsonOutput := flags.Bool("json", false, "print the API response as JSON")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("usage: plans publish [--ttl 7d|--keep] [--json] FILE|-")
	}
	if *keep && *ttl != "" {
		return errors.New("--ttl and --keep cannot be used together")
	}
	if *keep {
		*ttl = "keep"
	}

	baseURL, err := resolveAPIURL(*apiURL, dependencies)
	if err != nil {
		return err
	}
	token, err := resolveToken(dependencies, *tokenFile)
	if err != nil {
		return err
	}
	apiClient, err := client.New(client.Config{BaseURL: baseURL, Token: token, HTTPClient: dependencies.HTTPClient})
	if err != nil {
		return err
	}
	response, err := publishInput(ctx, apiClient, flags.Arg(0), streams.In, *ttl)
	if err != nil {
		return err
	}
	if *jsonOutput {
		encoder := json.NewEncoder(streams.Out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(response); err != nil {
			return fmt.Errorf("write JSON output: %w", err)
		}

		return nil
	}
	if err := writeAttachmentNotice(streams.Err, response.Attachments); err != nil {
		return err
	}

	return writeLine(streams.Out, response.URL)
}

// writeAttachmentNotice names the media artifacts an HTML publish created
// alongside the plan. Each one is an independent artifact with its own
// capability URL, and the plan bundles them: deleting the plan deletes them
// too, so the listing tells the user what else a plan URL they share exposes
// and what deleting it takes down. It goes to stderr because stdout stays
// exactly one machine-readable plan URL. The URL precedes the reference so the
// columns stay parsable when a reference contains spaces.
func writeAttachmentNotice(writer io.Writer, attachments []publishAttachment) error {
	if len(attachments) == 0 {
		return nil
	}
	noun := "media artifacts"
	if len(attachments) == 1 {
		noun = "media artifact"
	}
	header := fmt.Sprintf("published %d %s alongside the plan; deleting the plan deletes them too:",
		len(attachments), noun)
	if err := writeLine(writer, header); err != nil {
		return err
	}
	for _, attachment := range attachments {
		if err := writeLine(writer, "  "+attachment.URL+"  "+attachment.Path); err != nil {
			return err
		}
	}

	return nil
}

func runDelete(ctx context.Context, arguments []string, streams Streams, dependencies Dependencies) error {
	flags := flag.NewFlagSet("plans delete", flag.ContinueOnError)
	flags.SetOutput(streams.Err)
	apiURL := flags.String("api-url", "", apiURLUsage)
	tokenFile := flags.String("token-file", dependencies.Getenv("PLANS_TOKEN_FILE"), "file containing the upload token")
	jsonOutput := flags.Bool("json", false, "print the result as JSON")
	operand, remaining := splitKeyOperand(arguments)
	if err := flags.Parse(remaining); err != nil {
		return err
	}
	switch {
	case operand == "" && flags.NArg() == 1:
		operand = flags.Arg(0)
	case operand == "" || flags.NArg() != 0:
		return errors.New("usage: plans delete [--json] KEY|URL")
	}
	key, err := capabilityKey(operand)
	if err != nil {
		return err
	}

	baseURL, err := resolveAPIURL(*apiURL, dependencies)
	if err != nil {
		return err
	}
	token, err := resolveToken(dependencies, *tokenFile)
	if err != nil {
		return err
	}
	apiClient, err := client.New(client.Config{BaseURL: baseURL, Token: token, HTTPClient: dependencies.HTTPClient})
	if err != nil {
		return err
	}
	deleted, deleteErr := apiClient.Delete(ctx, key)
	if deleteErr != nil && len(deleted.Deleted) == 0 {
		return deleteErr
	}
	// A deletion can fail after it has already removed the plan, and the plan
	// was the only record of its media. Whatever it did remove is reported
	// before the failure, in either output format, so the user learns which
	// keys are gone and which they still have to delete.
	if err := writeDeletion(streams.Out, deleted, *jsonOutput); err != nil {
		return err
	}
	if deleteErr != nil && len(deleted.Failed) > 0 {
		return fmt.Errorf("%w; still present, delete each directly: %s", deleteErr, strings.Join(deleted.Failed, " "))
	}

	return deleteErr
}

// writeDeletion prints what a deletion removed. A plan takes its bundled media
// with it, so one key in can be several keys out.
func writeDeletion(writer io.Writer, deleted protocol.DeleteResponse, jsonOutput bool) error {
	if jsonOutput {
		if err := json.NewEncoder(writer).Encode(deleted); err != nil {
			return fmt.Errorf("write JSON output: %w", err)
		}

		return nil
	}
	for _, removed := range deleted.Deleted {
		if err := writeLine(writer, "deleted "+removed); err != nil {
			return err
		}
	}

	return nil
}

func runToken(arguments []string, streams Streams, dependencies Dependencies) error {
	flags := flag.NewFlagSet("plans token", flag.ContinueOnError)
	flags.SetOutput(streams.Err)
	jsonOutput := flags.Bool("json", false, "print token material as JSON")
	writePath := flags.String("write", "", "write the raw token to a new mode-0600 file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: plans token [--json]")
	}
	token, digest, err := auth.GenerateToken(dependencies.Random)
	if err != nil {
		return err
	}
	digestHex := auth.DigestHex(digest)
	if *writePath != "" {
		if *jsonOutput {
			return errors.New("--json and --write cannot be used together")
		}
		if err := writeTokenFile(*writePath, token); err != nil {
			return err
		}
		if err := writeLine(streams.Out, "PLANS_TOKEN_FILE="+*writePath); err != nil {
			return err
		}

		return writeLine(streams.Out, "PLANS_UPLOAD_TOKEN_SHA256="+digestHex)
	}
	if *jsonOutput {
		encoder := json.NewEncoder(streams.Out)
		encoder.SetIndent("", "  ")

		return encoder.Encode(map[string]string{"token": token, "sha256": digestHex})
	}
	if err := writeLine(streams.Out, "PLANS_TOKEN="+token); err != nil {
		return err
	}

	return writeLine(streams.Out, "PLANS_UPLOAD_TOKEN_SHA256="+digestHex)
}

// publishAttachment reports one auto-published media file in --json output,
// keyed by the reference exactly as written in the plan document.
type publishAttachment struct {
	Path string `json:"path"`
	protocol.ArtifactResponse
}

// publishOutput is the publish command result: the plan artifact plus any
// auto-published attachments. The flat ArtifactResponse shape is preserved
// for existing consumers.
type publishOutput struct {
	protocol.ArtifactResponse
	Attachments []publishAttachment `json:"attachments,omitempty"`
}

// publishInput routes a publish argument: stdin is always HTML and published
// verbatim, files infer their media type from the extension before anything
// touches the network, and HTML files auto-publish their local media.
func publishInput(ctx context.Context, apiClient *client.Client, name string, stdin io.Reader, ttl string) (publishOutput, error) {
	if name == "-" {
		content, err := io.ReadAll(stdin)
		if err != nil {
			return publishOutput{}, fmt.Errorf("read stdin: %w", err)
		}
		response, err := apiClient.Publish(ctx, bytes.NewReader(content), client.PublishOptions{ContentType: "text/html", TTL: ttl})

		return publishOutput{ArtifactResponse: response}, err
	}

	contentType, err := contentTypeForPath(name)
	if err != nil {
		return publishOutput{}, err
	}
	if contentType == "text/html" {
		// Reading the filename explicitly supplied by the CLI user is intentional.
		content, readErr := os.ReadFile(name) //nolint:gosec
		if readErr != nil {
			return publishOutput{}, fmt.Errorf("read %s: %w", name, readErr)
		}

		return publishPlanWithAttachments(ctx, apiClient, name, content, ttl)
	}

	// Opening the filename explicitly supplied by the CLI user is intentional.
	file, err := os.Open(name) //nolint:gosec
	if err != nil {
		return publishOutput{}, fmt.Errorf("open %s: %w", name, err)
	}
	defer func() { _ = file.Close() }()
	response, err := apiClient.Publish(ctx, file, client.PublishOptions{ContentType: contentType, TTL: ttl})

	return publishOutput{ArtifactResponse: response}, err
}

// publishPlanWithAttachments publishes every local media file an HTML plan
// references, splices the returned capability URLs into the original bytes,
// and publishes the plan last. Every referenced file is preflighted before
// the first upload so a bad reference aborts with zero artifacts published,
// and any failure after the first upload rolls the published attachments back
// so a partial publish leaves nothing stranded.
func publishPlanWithAttachments(ctx context.Context, apiClient *client.Client, name string, document []byte, ttl string) (publishOutput, error) {
	refs, err := scanLocalRefs(document)
	if err != nil {
		return publishOutput{}, fmt.Errorf("scan %s for media references: %w", name, err)
	}

	opened, openedByRef, err := openLocalRefs(filepath.Dir(name), refs)
	defer closeLocalRefs(opened)
	if err != nil {
		return publishOutput{}, err
	}

	attachments := make([]publishAttachment, 0, len(opened))
	for _, attachment := range opened {
		response, publishErr := apiClient.Publish(ctx, attachment.file, client.PublishOptions{ContentType: attachment.contentType, TTL: ttl})
		if publishErr != nil {
			return publishOutput{}, rollbackAttachments(ctx, apiClient, attachments,
				fmt.Errorf("publish referenced media %q: %w", attachment.writtenAs, publishErr))
		}
		attachment.url = response.URL
		attachments = append(attachments, publishAttachment{Path: attachment.writtenAs, ArtifactResponse: response})
	}

	edits := make([]spliceEdit, 0, len(refs))
	for index, ref := range refs {
		edits = append(edits, spliceEdit{
			start:       ref.ValueStart,
			end:         ref.ValueEnd,
			replacement: openedByRef[index].url,
		})
	}
	spliced, err := spliceDocument(document, edits)
	if err != nil {
		return publishOutput{}, rollbackAttachments(ctx, apiClient, attachments, fmt.Errorf("splice %s: %w", name, err))
	}

	// The plan names its media, so the server bundles them with it: deleting
	// the plan deletes them from here on.
	bundled := make([]string, 0, len(attachments))
	for _, attachment := range attachments {
		bundled = append(bundled, attachment.Key)
	}
	response, err := apiClient.Publish(ctx, bytes.NewReader(spliced), client.PublishOptions{
		ContentType: "text/html",
		TTL:         ttl,
		Attachments: bundled,
	})
	if err != nil {
		return publishOutput{}, rollbackAttachments(ctx, apiClient, attachments, err)
	}

	return publishOutput{ArtifactResponse: response, Attachments: attachments}, nil
}

// rollbackAttachments deletes the attachments already published when a later
// step of the same publish fails, and returns the failure that caused it.
// Nobody but this process has seen those keys yet, so leaving them behind
// strands artifacts that are unreachable but still consume storage until they
// expire — or forever, with --keep. Deletion is best effort: keys that could
// not be removed are named in the returned error so the user can retry them
// by hand.
func rollbackAttachments(ctx context.Context, apiClient *client.Client, attachments []publishAttachment, cause error) error {
	var stranded []string
	for _, attachment := range attachments {
		if _, err := apiClient.Delete(ctx, attachment.Key); err != nil {
			stranded = append(stranded, attachment.Key)
		}
	}
	if len(stranded) == 0 {
		return cause
	}

	return fmt.Errorf("%w; could not clean up already-published media, delete manually: %s",
		cause, strings.Join(stranded, " "))
}

// localAttachment is one deduplicated media file a plan references, held open
// from validation through upload.
type localAttachment struct {
	// writtenAs is the reference exactly as the plan document wrote it.
	writtenAs   string
	contentType string
	file        *os.File
	url         string
}

// openLocalRefs opens every referenced media file through a root anchored at
// the plan directory, so no reference can reach outside it via .. or a
// symlink that leaves the tree. The handle that is validated is the handle
// that is uploaded, leaving no window to swap the path in between. Files are
// deduplicated by cleaned relative path in first-seen order; the second
// result maps each reference to its file. On error the caller still receives
// the files opened so far and must close them.
func openLocalRefs(baseDir string, refs []localRef) ([]*localAttachment, []*localAttachment, error) {
	if len(refs) == 0 {
		return nil, nil, nil
	}
	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return nil, nil, fmt.Errorf("open plan directory: %w", err)
	}
	defer func() { _ = root.Close() }()

	var opened []*localAttachment
	byPath := make(map[string]*localAttachment)
	byRef := make([]*localAttachment, len(refs))
	for index, ref := range refs {
		relative := filepath.Clean(filepath.FromSlash(ref.Path))
		if existing, seen := byPath[relative]; seen {
			byRef[index] = existing

			continue
		}
		contentType, typeErr := mediaContentTypeForPath(relative)
		if typeErr != nil {
			return opened, nil, fmt.Errorf("referenced media %q: %w", ref.Value, typeErr)
		}
		file, openErr := root.Open(relative)
		if openErr != nil {
			return opened, nil, fmt.Errorf("referenced media %q: %w", ref.Value, openErr)
		}
		attachment := &localAttachment{writtenAs: ref.Value, contentType: contentType, file: file}
		opened = append(opened, attachment)
		info, statErr := file.Stat()
		if statErr != nil {
			return opened, nil, fmt.Errorf("referenced media %q: %w", ref.Value, statErr)
		}
		if !info.Mode().IsRegular() {
			return opened, nil, fmt.Errorf("referenced media %q is not a regular file", ref.Value)
		}
		byPath[relative] = attachment
		byRef[index] = attachment
	}

	return opened, byRef, nil
}

func closeLocalRefs(attachments []*localAttachment) {
	for _, attachment := range attachments {
		_ = attachment.file.Close()
	}
}

// apiURLUsage documents --api-url and the sources consulted without it.
const apiURLUsage = "plans API base URL; without it, PLANS_API_URL, then the file $XDG_CONFIG_HOME/plans/api-url (default ~/.config/plans/api-url)"

// resolveAPIURL picks the API base URL from, in order, the --api-url flag, the
// PLANS_API_URL environment variable, and the one-line file plans/api-url in
// the user configuration directory. There is no built-in default: a CLI that
// silently uploaded to some origin the user never named would hand that origin
// their token and their artifact. The URL is validated here, before anything
// touches the network, and an error names the source it came from.
func resolveAPIURL(flagValue string, dependencies Dependencies) (string, error) {
	value, source := strings.TrimSpace(flagValue), "--api-url"
	if value == "" {
		value, source = strings.TrimSpace(dependencies.Getenv("PLANS_API_URL")), "PLANS_API_URL"
	}
	configFile := "$XDG_CONFIG_HOME/plans/api-url"
	if value == "" {
		configDirectory, err := dependencies.UserConfigDir()
		if err == nil {
			configFile = filepath.Join(configDirectory, "plans", "api-url")
			// Reading the API URL file from the user's own configuration directory is intentional.
			content, readErr := os.ReadFile(configFile) //nolint:gosec
			switch {
			case errors.Is(readErr, fs.ErrNotExist):
			case readErr != nil:
				return "", fmt.Errorf("read API URL file: %w", readErr)
			default:
				value, source = strings.TrimSpace(string(content)), configFile
				if value == "" {
					return "", fmt.Errorf("API URL file %s is empty", configFile)
				}
			}
		}
	}
	if value == "" {
		return "", fmt.Errorf("no plans API URL configured: pass --api-url, set PLANS_API_URL, or write the URL to %s", configFile)
	}
	if _, err := client.ParseBaseURL(value); err != nil {
		return "", fmt.Errorf("%s: %w", source, err)
	}

	return value, nil
}

func resolveToken(dependencies Dependencies, tokenFile string) (string, error) {
	if token := strings.TrimSpace(dependencies.Getenv("PLANS_TOKEN")); token != "" {
		return token, nil
	}
	if tokenFile == "" {
		configDirectory, err := dependencies.UserConfigDir()
		if err != nil {
			return "", errors.New("upload token is required; set PLANS_TOKEN or PLANS_TOKEN_FILE")
		}
		tokenFile = filepath.Join(configDirectory, "plans", "token")
	}
	// Reading the token filename explicitly configured by the CLI user is intentional.
	content, err := os.ReadFile(tokenFile) //nolint:gosec
	if err != nil {
		return "", fmt.Errorf("read upload token file: %w", err)
	}
	token := strings.TrimSpace(string(content))
	if token == "" {
		return "", errors.New("upload token file is empty")
	}

	return token, nil
}

func writeTokenFile(name, token string) error {
	parent := filepath.Dir(name)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create token directory: %w", err)
	}
	// The destination is explicitly selected by the CLI user and cannot overwrite a file.
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec
	if err != nil {
		return fmt.Errorf("create token file: %w", err)
	}
	writeErr := func() error {
		if _, err := fmt.Fprintln(file, token); err != nil {
			return err
		}

		return file.Sync()
	}()
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("write token file: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close token file: %w", closeErr)
	}

	return nil
}

// splitKeyOperand lifts a capability key out of the argument list before flag
// parsing, returning it with the arguments the flag set should still see. Keys
// are base64url, so about one in sixty-four begins with "-" and the flag
// package would otherwise reject it as an unknown flag. Only an exact
// capability key is lifted: a mistyped flag still reaches the parser and is
// still reported as unknown, and an explicit "--" terminator ends the scan
// because the flag package already treats everything past it as an operand.
func splitKeyOperand(arguments []string) (string, []string) {
	for index, argument := range arguments {
		if argument == "--" {
			break
		}
		if !strings.HasPrefix(argument, "-") || !artifact.ValidKey(argument) {
			continue
		}
		remaining := make([]string, 0, len(arguments)-1)
		remaining = append(remaining, arguments[:index]...)
		remaining = append(remaining, arguments[index+1:]...)

		return argument, remaining
	}

	return "", arguments
}

func capabilityKey(value string) (string, error) {
	if artifact.ValidKey(value) {
		return value, nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("artifact must be a valid capability key or URL")
	}
	key := path.Base(strings.TrimRight(parsed.Path, "/"))
	if !artifact.ValidKey(key) {
		return "", errors.New("artifact URL does not contain a valid capability key")
	}

	return key, nil
}

func defaultStreams(streams Streams) Streams {
	if streams.In == nil {
		streams.In = os.Stdin
	}
	if streams.Out == nil {
		streams.Out = os.Stdout
	}
	if streams.Err == nil {
		streams.Err = os.Stderr
	}

	return streams
}

func defaultDependencies(dependencies Dependencies) Dependencies {
	if dependencies.Random == nil {
		dependencies.Random = rand.Reader
	}
	if dependencies.Getenv == nil {
		dependencies.Getenv = os.Getenv
	}
	if dependencies.UserConfigDir == nil {
		dependencies.UserConfigDir = os.UserConfigDir
	}

	return dependencies
}

func writeLine(writer io.Writer, value string) error {
	if _, err := fmt.Fprintln(writer, value); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	return nil
}

func writeUsage(writer io.Writer) {
	_, _ = fmt.Fprintln(writer, `usage: plans COMMAND

Commands:
  publish FILE|-  upload an artifact (HTML, image, or video by extension)
  delete KEY|URL  delete an artifact; deleting a plan deletes its bundled media
  token           generate an upload token and server-side digest
  version         print build information`)
}
