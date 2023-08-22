# aws-port-checker

[![GitHub Release](https://img.shields.io/github/release/rollwagen/apoch.svg?style=flat-square)](https://github.com/rollwagen/apoch/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/rollwagen/apoch.svg?style=flat-square)](https://pkg.go.dev/github.com/rollwagen/apoch)
[![Go Report Card](https://goreportcard.com/badge/github.com/rollwagen/apoch?style=flat-square)](https://goreportcard.com/report/github.com/rollwagen/apoch)
[![Powered By: GoReleaser](https://img.shields.io/badge/powered%20by-goreleaser-green.svg?style=flat-square)](https://github.com/goreleaser)
![CodeQL](https://github.com/rollwagen/apoch/workflows/CodeQL/badge.svg?style=flat-square)

**A**WS **Po**rt **Ch**ecker = `apoch`

Runs a port scan of all VPC public IPs found in AWS Config.

<img width="1054" alt="image" src="https://user-images.githubusercontent.com/7364201/233852722-13bb1a62-92d5-4c73-86d4-55208a62696d.png">

```text
Run a port scan of all VPC public IPs found in AWS ConfigService

Usage:
  apoch [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  run         Run a port scan of all VPC public IPs found in AWS ConfigService

Flags:
  -h, --help   help for apoch

Use "apoch [command] --help" for more information about a command.
```

## Install and run

### Brew

```sh
brew tap rollwagen/homebrew-tap
brew install rollwagen/tap/apoch
```

### Go

To run directly:

```sh
go run github.com/rollwagen/apoch@latest --help
```

## Build

```sh
git clone https://github.com/rollwagen/apoch
cd apoch
make build
```
