# renku-gateway-v2

## Contributing

1. Install [GO](https://go.dev/doc/install)
2. Install [golangci-lint](https://golangci-lint.run/usage/install/#local-installation)
3. Install golines `go install github.com/segmentio/golines@latest`
4. For VS Code: install "Run on Save" [externsion](https://marketplace.visualstudio.com/items?itemName=emeraldwalk.RunOnSave)

Useful commands:
- To lint: `golangci-lint run -v`
- To reformat long lines: `golines . -w --max-len=120 --base-formatter=gofmt` or
  to target a specific file replace `.` with the filename in the command

## Important references

[GitLab refresh tokens do not expire](https://gitlab.com/gitlab-org/gitlab/-/issues/340848#note_953496566)
