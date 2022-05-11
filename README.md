# Repo Audit

A GitHub Action to audit all your organization's repositories using [Reposaur][reposaur].

# Features

* Automatically audit every repository in a GitHub Organization
* Write [custom policies][policy-docs] using the [Rego][rego] language
* Get reports in the Code Scanning alerts dashboard of your repository and
organization (only available for public repositories or with [GitHub Advanced Security][ghas] enabled)

# Usage

```yaml
- name: Audit
  uses: reposaur/repo-audit-action@main
  with:
    # Paths to policies or directory of policies (one path per line).
    # Default: ${{ github.workspace }}
    policy: ''

    # Path to the output directory to where SARIF reports will be written.
    # Default: ${{ github.workspace }}/.reposaur
    output: ''

    # Maximum amount of errors that Reposaur can encounter before
    # aborting policy execution. If the value is 0, execution will never
    # stop on errors.
    # Default: 0
    max-errors: ''
  env:
    # A GitHub Token that can list your organization's repositories
    # and upload SARIF reports to Code Scanning.
    GITHUB_TOKEN: ''
```

# Example

Since this action is meant to run for the whole organization, we usually create
a `policy` repository to hold both the workflow and our custom policies.
See [reposaur/policy][policy] for an example.

The example below will run on every `push` and everyday at 23h00 UTC. Alternatively,
it can also be triggered manually.

```yaml
name: Audit

on:
  push:
  schedule:
    - cron: 0 23 * * *
  workflow_dispatch:

jobs:
  audit:
    name: Audit
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v3
        with:
          repository: reposaur/policy

      - id: app-token
        name: Authenticate
        uses: getsentry/action-github-app-token@v1
        with:
          app_id: ${{ secrets.MY_SECURITY_APP_ID }}
          private_key: ${{ secrets.MY_SECURITY_APP_PRIVATE_KEY }}

      - name: Audit
        uses: reposaur/repo-audit-action@main
        env:
          GITHUB_TOKEN: ${{ steps.app-token.outputs.token }}
```

# Contributing

We appreciate every contribution, thanks for considering it!

- [Open an issue][issues] if you have a problem or found a bug
- [Open a Pull Request][pulls] if you have a suggestion, improvement or bug fix
- [Open a Discussion][discussions] if you have questions or want to discuss ideas

# License

This project is released under the [MIT License](LICENSE).

[issues]: https://github.com/reposaur/repo-audit-action/issues
[pulls]: https://github.com/reposaur/repo-audit-action/pulls
[discussions]: https://github.com/orgs/reposaur/discussions
[reposaur]: https://github.com/reposaur/reposaur
[rego]: https://www.openpolicyagent.org/docs/latest/policy-language/
[policy]: https://github.com/reposaur/policy
[policy-docs]: https://docs.reposaur.com/policy
[ghas]: https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security