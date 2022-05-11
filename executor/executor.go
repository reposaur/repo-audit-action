package executor

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"sync"

	"github.com/google/go-github/v42/github"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/reposaur/reposaur/pkg/output"
	"github.com/reposaur/reposaur/pkg/sdk"
	"github.com/rs/zerolog"
)

type Executor struct {
	rsr       *sdk.Reposaur
	client    *github.Client
	outDir    string
	maxErrors int
}

func NewExecutor(rsr *sdk.Reposaur, client *github.Client, outDir string) *Executor {
	return &Executor{
		rsr:       rsr,
		client:    client,
		outDir:    outDir,
		maxErrors: 0,
	}
}

func (exec *Executor) SetErrorLimit(limit int) {
	exec.maxErrors = limit
}

func (exec Executor) Execute(ctx context.Context, repos []*github.Repository) (*ExecutorResult, error) {
	if len(repos) == 0 {
		return nil, errors.New("no repositories to process")
	}

	var (
		errorsCh  = make(chan error)
		reportsCh = make(chan *ExecutorReport)
		reportsWg = sync.WaitGroup{}
		result    = &ExecutorResult{
			mux: &sync.Mutex{},
		}
	)

	reportsWg.Add(len(repos))

	// produce reports
	for _, repo := range repos {
		go func(repo *github.Repository) {
			report, err := exec.checkRepo(ctx, repo)
			if err != nil {
				errorsCh <- err
				reportsWg.Done()
				return
			}

			reportsCh <- report
		}(repo)
	}

	// consume reports
	go func() {
		for report := range reportsCh {
			result.Lock()
			result.Reports = append(result.Reports, report)
			result.Unlock()

			go func(report *ExecutorReport) {
				if err := exec.writeReport(ctx, report); err != nil {
					errorsCh <- err
				} else {
					report.Written = true
				}

				if err := exec.uploadReport(ctx, report); err != nil {
					errorsCh <- err
				} else {
					report.Uploaded = true
				}

				reportsWg.Done()
			}(report)
		}
	}()

	// consume errors
	go func() {
		for err := range errorsCh {
			result.Lock()
			result.Errors = append(result.Errors, err)
			result.Unlock()

			if exec.maxErrors != 0 && len(result.Errors) >= exec.maxErrors {
				for _, err := range result.Errors {
					zerolog.Ctx(ctx).Err(err).Send()
				}

				panic("too many errors")
			}
		}
	}()

	reportsWg.Wait()

	close(reportsCh)
	close(errorsCh)

	return result, nil
}

func (exec Executor) checkRepo(ctx context.Context, repo *github.Repository) (report *ExecutorReport, err error) {
	report = &ExecutorReport{
		Repo: repo,
	}

	logger := zerolog.Ctx(ctx).With().
		Str("repo", repo.GetFullName()).
		Logger()

	logger.Info().Msg("Executing policy")

	report.Report, err = exec.rsr.Check(ctx, "repository", repo)
	if err != nil {
		return nil, err
	}

	logger.Info().Msg("Done executing policy")

	report.SarifReport, err = output.NewSarifReport(report.Report)
	if err != nil {
		return nil, err
	}

	return report, err
}

func (exec Executor) writeReport(ctx context.Context, report *ExecutorReport) error {
	filename := path.Join(exec.outDir, strings.ToLower(report.Repo.GetName())+".sarif")
	logger := zerolog.Ctx(ctx).With().
		Str("repo", report.Repo.GetFullName()).
		Str("path", filename).
		Logger()

	logger.Info().Msg("Writing report to disk")

	err := report.SarifReport.WriteFile(filename)
	if err != nil {
		return err
	}

	logger.Info().Msg("Report written")

	return nil
}

func (exec Executor) uploadReport(ctx context.Context, report *ExecutorReport) error {
	if !hasGitHubAdvancedSecurityEnabled(report.Repo) {
		return nil
	}

	var (
		owner      = report.Repo.Owner.GetLogin()
		repo       = report.Repo.GetName()
		branchName = report.Repo.GetDefaultBranch()
		logger     = zerolog.Ctx(ctx).With().Str("repo", report.Repo.GetFullName()).Logger()
	)

	encodedSarif, err := encodeSarif(report.SarifReport)
	if err != nil {
		return err
	}

	branch, _, err := exec.client.Repositories.GetBranch(ctx, owner, repo, branchName, true)
	if err != nil {
		return err
	}

	var (
		branchRef     = fmt.Sprintf("refs/heads/%s", branch.GetName())
		sarifAnalysis = &github.SarifAnalysis{
			ToolName:  github.String("Reposaur"),
			Ref:       &branchRef,
			CommitSHA: branch.Commit.SHA,
			Sarif:     &encodedSarif,
		}
	)

	logger.Info().Msg("Uploading report to GHAS")

	id, resp, err := exec.client.CodeScanning.UploadSarif(ctx, owner, repo, sarifAnalysis)
	if err != nil {
		if resp.StatusCode == http.StatusAccepted {
			logger.Info().Msg("Report queued to be processed by GitHub")
			return nil
		}

		return err
	}

	logger.Info().Str("sarifID", id.GetID()).Str("sarifURL", id.GetURL()).Msg("Report uploaded")

	return nil
}

func encodeSarif(sarif *sarif.Report) (string, error) {
	var (
		buf     = bytes.Buffer{}
		b64Enc  = base64.NewEncoder(base64.RawStdEncoding, &buf)
		wr      = gzip.NewWriter(b64Enc)
		jsonEnc = json.NewEncoder(wr)
	)

	if err := jsonEnc.Encode(sarif); err != nil {
		return "", err
	}

	wr.Close()
	b64Enc.Close()

	return buf.String(), nil
}

func hasGitHubAdvancedSecurityEnabled(repo *github.Repository) bool {
	if repo.GetVisibility() == "public" {
		return true
	}

	if repo.GetArchived() {
		return false
	}

	if repo.SecurityAndAnalysis == nil {
		return false
	}

	if repo.SecurityAndAnalysis.AdvancedSecurity == nil {
		return false
	}

	return repo.SecurityAndAnalysis.AdvancedSecurity.GetStatus() == "enabled"
}
