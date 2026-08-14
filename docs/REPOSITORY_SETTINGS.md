# Required repository settings

These controls cannot be enforced by files in a branch alone. Apply them before promoting `01.01.00` to production.

## Main branch ruleset

Target: `main`

- require a pull request before merge
- require at least one approving review
- dismiss stale approvals when new commits are pushed
- require review of the latest push
- require conversation resolution
- require signed commits when all maintainers can comply
- require status checks from **Security validation** and **CodeQL**
- require branches to be up to date before merge
- block force pushes
- block branch deletion
- restrict bypass permissions to emergency maintainers

## Development branch

Target: `dev`

- block force pushes and deletion
- require **Security validation** and **CodeQL** before merging elsewhere
- allow direct maintainer pushes only when necessary for development

## GitHub Pages

- set deployment source to **GitHub Actions**
- keep HTTPS enforcement enabled
- use the `github-pages` environment
- restrict production deployment to `main`
- require environment approval when operationally appropriate

## Security features

Enable where available:

- private vulnerability reporting
- dependency graph
- Dependabot alerts
- Dependabot security updates
- Code scanning default setup or the committed CodeQL workflow
- secret scanning and push protection

## Merge and release policy

- prefer squash merge for a single auditable release commit
- delete merged development branches only after the release tag and rollback artifact are preserved
- create tag `vXX.XX.XX` only on the validated `main` commit whose `VERSION` matches
- retain the previous release artifact and checksum for rollback
