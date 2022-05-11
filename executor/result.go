package executor

import (
	"sync"

	"github.com/google/go-github/v42/github"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/reposaur/reposaur/pkg/output"
)

type ExecutorReport struct {
	Repo        *github.Repository
	Report      output.Report
	SarifReport *sarif.Report
	Written     bool
	Uploaded    bool
}

type ExecutorResult struct {
	Reports []*ExecutorReport
	Errors  []error
	mux     *sync.Mutex
}

func (r *ExecutorResult) TotalReportsWritten() int {
	count := 0

	for _, report := range r.Reports {
		if report.Written {
			count++
		}
	}

	return count
}

func (r *ExecutorResult) TotalReportsUploaded() int {
	count := 0

	for _, report := range r.Reports {
		if report.Uploaded {
			count++
		}
	}

	return count
}

func (r *ExecutorResult) Lock() {
	r.mux.Lock()
}

func (r *ExecutorResult) Unlock() {
	r.mux.Unlock()
}
