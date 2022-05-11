package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/crqra/go-action/pkg/action"
	"github.com/google/go-github/v42/github"
	"github.com/gregjones/httpcache"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/reposaur/reposaur/pkg/output"
	"github.com/reposaur/reposaur/pkg/sdk"
	"github.com/reposaur/reposaur/pkg/util"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
)

var supportedEvents = []string{"push", "schedule", "workflow_dispatch"}

type RepoAuditAction struct {
	PolicyPaths string `action:"policy-paths"`
	// Reports     string `action:"reports,output"`
	// Repos       string `action:"repos,output"`
}

func (a *RepoAuditAction) Run() error {
	var (
		logger = zerolog.New(zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.Kitchen,
		})

		ctx = logger.WithContext(context.Background())
	)

	// Validate if event is supported
	if event := action.Context.EventName; !isSupportedEvent(event) {
		return fmt.Errorf("unsupported event '%s'. supported events are: %v", event, supportedEvents)
	}

	// Validate policy paths provided
	policyPaths := strings.Split(a.PolicyPaths, "\n")
	if len(policyPaths) == 1 && policyPaths[0] == "" {
		logger.Warn().Msgf("No policy paths specified. Using '%s' as default", action.Context.Workspace)
		policyPaths = []string{action.Context.Workspace}
	} else {
		logger.Info().Msgf("Using policies from: %v", policyPaths)
	}

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
	if err := execute(ctx, rsr, client, repos); err != nil {
		return err
	}
	logger.Info().Msgf("Finished policy execution")

	return nil
}

func main() {
	if err := action.Execute(&RepoAuditAction{}); err != nil {
		action.SetFailed(err, map[string]string{})
	}
}

type repoReport struct {
	repo   *github.Repository
	report output.Report
}

func execute(ctx context.Context, rsr *sdk.Reposaur, client *github.Client, repos []*github.Repository) error {
	var (
		logger    = zerolog.Ctx(ctx)
		reportsCh = make(chan repoReport)
		reportsWg = sync.WaitGroup{}
	)

	reportsWg.Add(len(repos))

	for _, repo := range repos {
		go func(repo *github.Repository) {
			report, err := rsr.Check(ctx, "repository", repo)
			if err != nil {
				logger.Err(err).Send()
				return
			}

			sarifReport, err := output.NewSarifReport(report)
			if err != nil {
				logger.Err(err).Send()
				return
			}

			encodedSarif, err := encodeSarif(sarifReport)
			if err != nil {
				logger.Err(err).Send()
				return
			}

			sarifAnalysis := &github.SarifAnalysis{
				ToolName: github.String("Reposaur"),
				Ref:      github.String(fmt.Sprintf("refs/heads/%s", repo.GetDefaultBranch())),
				Sarif:    &encodedSarif,
			}

			id, _, err := client.CodeScanning.UploadSarif(ctx, repo.Owner.GetLogin(), repo.GetName(), sarifAnalysis)
			if err != nil {
				logger.Err(err).Send()
				return
			}

			logger.Info().Str("sarifID", id.GetID()).Str("sarifURL", id.GetURL()).Msg("Report uploaded")

			reportsCh <- repoReport{repo: repo, report: report}
		}(repo)
	}

	for report := range reportsCh {
		reportsWg.Done()

		logger.Info().Str("repo", report.repo.GetFullName()).Msg("reported")
	}

	reportsWg.Wait()

	return nil
}

func encodeSarif(sarif *sarif.Report) (string, error) {
	var (
		buf       = bytes.Buffer{}
		base64Enc = base64.NewEncoder(base64.RawStdEncoding, &buf)
		wr        = gzip.NewWriter(base64Enc)
		jsonEnc   = json.NewEncoder(wr)
	)

	if err := jsonEnc.Encode(sarif); err != nil {
		return "", err
	}

	wr.Close()
	base64Enc.Close()

	return buf.String(), nil
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
