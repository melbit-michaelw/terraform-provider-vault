#!/bin/bash

die () {
    echo >&2 "$@"
    exit 1
}

[ "$#" -eq 1 ] || die "1 argument required, $# provided. Please specify version number in the form v10.0.0"

GOOS=linux GOARCH=amd64 go build -o bin/x86_64/terraform-provider-vault_$1
GOOS=darwin GOARCH=amd64 go build -o bin/darwin_amd64/terraform-provider-vault_$1
GOOS=windows GOARCH=amd64 go build -o bin/winx64/terraform-provider-vault_$1.exe