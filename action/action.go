package action

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/crqra/go-action/pkg/action"
	"github.com/google/go-github/v42/github"
	"github.com/gregjones/httpcache"
	"github.com/reposaur/repo-audit-action/executor"
	"github.com/reposaur/reposaur/pkg/sdk"
	"github.com/reposaur/reposaur/pkg/util"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
)

var supportedEvents = []string{"push", "schedule", "workflow_dispatch"}

type RepoAuditAction struct {
	PolicyPaths string `action:"policy"`
	OutputDir   string `action:"output"`
	MaxErrors   int    `action:"max-errors"`
}

func (a *RepoAuditAction) Run() error {
	// Validate if event is supported
	if event := action.Context.EventName; !isSupportedEvent(event) {
		return fmt.Errorf("unsupported event '%s'. supported events are: %v", event, supportedEvents)
	}

	var (
		logger = zerolog.New(zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.Kitchen,
		})

		ctx         = logger.WithContext(context.Background())
		policyPaths = parsePolicyPaths(a.PolicyPaths)
	)

	outputDir, err := parseAndCreateOutputDir(a.OutputDir)
	if err != nil {
		return err
	}

	logger.Info().Msgf("Using policy paths: %v", policyPaths)
	logger.Info().Msgf("Using output dir: %s", &outputDir)

	// Initialize Reposaur
	var (
		client = createClient(ctx, os.Getenv("GITHUB_TOKEN"))
		opts   = []sdk.Option{
			sdk.WithLogger(logger),
			sdk.WithHTTPClient(client.Client()),
		}
	)

	rsr, err := sdk.New(ctx, policyPaths, opts...)
	if err != nil {
		return err
	}
	logger.Info().Msg("Reposaur SDK initialized")

	// Fetch organization repositories
	logger.Info().Msgf("Fetching all repositories for %s", action.Context.RepositoryOwner)

	repos, err := fetchAllRepos(ctx, client, action.Context.RepositoryOwner)
	if err != nil {
		return err
	}

	logger.Info().Msgf("Got %d repositories", len(repos))

	// Execute policies
	logger.Info().Msg("Starting policy execution")

	exec := executor.NewExecutor(rsr, client, outputDir)
	exec.SetErrorLimit(a.MaxErrors)

	result, err := exec.Execute(ctx, repos)
	if err != nil {
		return err
	}

	for _, err := range result.Errors {
		logger.Err(err).Send()
	}

	logger.Info().Msg("Finished policy execution")
	logger.Info().Msgf("Wrote %d reports to %s", result.TotalReportsWritten(), outputDir)
	logger.Info().Msgf("Uploaded %d reports to GHAS", result.TotalReportsUploaded())

	return nil
}

func Execute() {
	if err := action.Execute(&RepoAuditAction{}); err != nil {
		action.SetFailed(err, map[string]string{})
	}
}

func fetchAllRepos(ctx context.Context, client *github.Client, owner string) ([]*github.Repository, error) {
	return doFetchRepos(ctx, client, owner, 1, []*github.Repository{})
}

func doFetchRepos(ctx context.Context, client *github.Client, owner string, page int, allRepos []*github.Repository) ([]*github.Repository, error) {
	listOpts := github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{
			Page:    page,
			PerPage: 100,
		},
	}

	repos, resp, err := client.Repositories.ListByOrg(ctx, owner, &listOpts)
	if err != nil {
		return nil, err
	}

	allRepos = append(allRepos, repos...)

	if resp.NextPage == 0 {
		return allRepos, nil
	}

	return doFetchRepos(ctx, client, owner, resp.NextPage, allRepos)
}

func isSupportedEvent(event string) bool {
	for _, suppEvent := range supportedEvents {
		if suppEvent == event {
			return true
		}
	}
	return false
}

func createClient(ctx context.Context, token string) *github.Client {
	logger := zerolog.Ctx(ctx)

	ghTransport := &util.GitHubTransport{
		Logger:    *logger,
		Transport: http.DefaultTransport,
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{
		Transport: ghTransport,
	})

	tokenSource := oauth2.StaticTokenSource(
		&oauth2.Token{
			AccessToken: token,
		},
	)
	tokenTransport := oauth2.NewClient(ctx, tokenSource).Transport

	cacheTransport := httpcache.NewMemoryCacheTransport()
	cacheTransport.Transport = tokenTransport

	return github.NewClient(cacheTransport.Client())
}

func parsePolicyPaths(policyPaths string) []string {
	paths := strings.Split(policyPaths, "\n")

	if len(paths) == 1 && paths[0] == "" {
		return []string{action.Context.Workspace}
	}

	return paths
}

func parseAndCreateOutputDir(outputDir string) (string, error) {
	if outputDir == "" {
		outputDir = path.Join(action.Context.Workspace, ".reposaur")
	}

	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		if err := os.Mkdir(outputDir, 0o755); err != nil {
			return outputDir, err
		}
	}

	return outputDir, nil
}
