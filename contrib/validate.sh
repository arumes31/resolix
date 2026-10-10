#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tool_root="${RESOLIX_TOOL_DIR:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/resolix-quality-tools}"

golangci_lint_version="v2.14.0"
gosec_version="7b1b5cebe007d62fb58eacb90fc571112939ec30"
govulncheck_version="v1.7.0"
go_licenses_version="v2.0.1"
actionlint_version="v1.7.12"

usage() {
  echo "usage: $0 {all|core|lint|security|licenses|workflows|frontend}" >&2
  exit 2
}

install_go_tool() {
  local name="$1"
  local package="$2"
  local version="$3"
  local go_exe
  local install_dir="${tool_root}/${name}-${version}"
  local binary

  go_exe="$(go env GOEXE)"
  binary="${install_dir}/${name}${go_exe}"

  if [[ ! -x "${binary}" ]]; then
    mkdir -p "${install_dir}"
    echo "Installing ${package}@${version}" >&2
    GOBIN="${install_dir}" go install "${package}@${version}"
  fi

  printf '%s\n' "${binary}"
}

check_version_consistency() {
  local app_version
  local docker_version
  app_version="$(tr -d '[:space:]' < "${repo_root}/webgui/VERSION")"
  docker_version="$(sed -n 's/^ARG VERSION=//p' "${repo_root}/Dockerfile" | head -n 1)"

  if [[ ! "${app_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "webgui/VERSION must contain a stable semantic version (X.Y.Z)" >&2
    return 1
  fi
  if [[ "${docker_version}" != "${app_version}" ]]; then
    echo "Dockerfile version ${docker_version} does not match application version ${app_version}" >&2
    return 1
  fi
}

check_core() {
  local coverage_file
  local total

  check_version_consistency
  cd "${repo_root}/webgui"

  test -z "$(gofmt -l .)"
  go mod verify
  if [[ "$(go env GOOS)" == "windows" ]]; then
    go mod tidy
    git diff --exit-code -- go.mod go.sum
  else
    go mod tidy -diff
  fi
  go vet ./...
  go build ./...

  coverage_file="$(mktemp "${TMPDIR:-/tmp}/resolix-coverage.XXXXXX")"
  go test -race -coverprofile="${coverage_file}" -covermode=atomic ./...
  total="$(go tool cover -func="${coverage_file}" | awk '/^total:/ {gsub(/%/, "", $3); print $3}')"
  rm -f "${coverage_file}"
  awk -v total="${total}" 'BEGIN { if (total < 45) { printf "coverage %.1f%% is below 45%%\n", total; exit 1 } }'
}

check_lint() {
  local golangci_lint
  golangci_lint="$(install_go_tool \
    golangci-lint \
    github.com/golangci/golangci-lint/v2/cmd/golangci-lint \
    "${golangci_lint_version}")"
  cd "${repo_root}/webgui"
  "${golangci_lint}" run
}

check_security() {
  local gosec
  local govulncheck
  gosec="$(install_go_tool \
    gosec \
    github.com/securego/gosec/v2/cmd/gosec \
    "${gosec_version}")"
  govulncheck="$(install_go_tool \
    govulncheck \
    golang.org/x/vuln/cmd/govulncheck \
    "${govulncheck_version}")"
  cd "${repo_root}/webgui"
  "${govulncheck}" -test ./...
  "${gosec}" -quiet ./...
}

check_licenses() {
  local go_licenses
  go_licenses="$(install_go_tool \
    go-licenses \
    github.com/google/go-licenses/v2 \
    "${go_licenses_version}")"
  cd "${repo_root}/webgui"
  "${go_licenses}" check \
    --include_tests \
    --ignore=github.com/arumes31/resolix/webgui \
    ./...
}

check_workflows() {
  local actionlint
  actionlint="$(install_go_tool \
    actionlint \
    github.com/rhysd/actionlint/cmd/actionlint \
    "${actionlint_version}")"
  cd "${repo_root}"
  "${actionlint}" -no-color
}

check_frontend() {
  cd "${repo_root}/webgui"
  node --test test/dashboard_loader.test.js test/traffic_intensity.test.js
}

run_check() {
  case "$1" in
    core) check_core ;;
    lint) check_lint ;;
    security) check_security ;;
    licenses) check_licenses ;;
    workflows) check_workflows ;;
    frontend) check_frontend ;;
    *) usage ;;
  esac
}

case "${1:-all}" in
  all)
    for check in core lint security licenses workflows frontend; do
      echo "==> ${check}"
      run_check "${check}"
    done
    ;;
  core|lint|security|licenses|workflows|frontend)
    run_check "$1"
    ;;
  *)
    usage
    ;;
esac
