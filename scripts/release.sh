#!/usr/bin/env bash
# ==============================================================================
# Snapsec Agent Release Script
#
# Automates the release process for monorepo agents:
# 1. Selects agent & bumps version (patch, minor, major, or explicit)
# 2. Updates version in internal/config/config.go and documentation/examples
# 3. Validates Go code (go vet)
# 4. Creates a git commit and annotated tag: <agent>/v<version>
# 5. Pushes to origin to trigger the GitHub Actions GoReleaser workflow
#
# Usage:
#   ./scripts/release.sh [AGENT] [VERSION_OR_BUMP] [OPTIONS]
#
# Examples:
#   ./scripts/release.sh
#   ./scripts/release.sh snapsec-sensor patch
#   ./scripts/release.sh snapsec-sensor minor
#   ./scripts/release.sh snapsec-sensor 4.0.2
#   ./scripts/release.sh snapsec-sensor patch --push
#   ./scripts/release.sh snapsec-sensor patch --dry-run
# ==============================================================================

set -euo pipefail

# ANSI Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Helper output functions
info() { echo -e "${CYAN}==>${NC} ${BOLD}$*${NC}"; }
success() { echo -e "${GREEN}✔${NC} $*"; }
warn() { echo -e "${YELLOW}⚠${NC} $*"; }
error() { echo -e "${RED}✖ Error:${NC} $*" >&2; }
abort() { error "$*"; exit 1; }

# Locate repository root
if git rev-parse --show-toplevel >/dev/null 2>&1; then
  REPO_ROOT="$(git rev-parse --show-toplevel)"
else
  SOURCE="${BASH_SOURCE[0]}"
  while [ -h "$SOURCE" ]; do
    DIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"
    SOURCE="$(readlink "$SOURCE")"
    [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
  done
  SCRIPT_DIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"
  REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
fi
cd "$REPO_ROOT"

# Ensure git is installed and we are in a git repository
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  abort "Must be run inside a Git repository."
fi

# Print Help
show_help() {
  cat << EOF
Snapsec Agent Release Tool

Usage:
  ./release.sh [AGENT] [VERSION_OR_BUMP] [OPTIONS]

Arguments:
  AGENT              Agent directory to release (e.g., snapsec-sensor).
                     If omitted, prompts interactively.
  VERSION_OR_BUMP    Bump type (patch, minor, major) or explicit semver (e.g., 4.0.2, v4.0.2).
                     If omitted, prompts interactively.

Options:
  --push             Automatically push commit and release tag without prompting.
  --no-push          Create commit and tag locally without pushing.
  --dry-run, -d      Simulate changes and print actions without modifying files, committing, or pushing.
  --help, -h         Show this help message.

Examples:
  ./release.sh
  ./release.sh snapsec-sensor patch
  ./release.sh snapsec-sensor 4.0.2 --push
  ./release.sh snapsec-sensor minor --dry-run
EOF
}

# Parse Options & Flags
AGENT=""
VERSION_ARG=""
AUTO_PUSH=""
DRY_RUN=false

POSITIONAL_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --push)
      AUTO_PUSH=true
      shift
      ;;
    --no-push)
      AUTO_PUSH=false
      shift
      ;;
    --dry-run|-d)
      DRY_RUN=true
      shift
      ;;
    --help|-h)
      show_help
      exit 0
      ;;
    -*)
      abort "Unknown option: $1 (run with --help for usage)"
      ;;
    *)
      POSITIONAL_ARGS+=("$1")
      shift
      ;;
  esac
done

if [[ ${#POSITIONAL_ARGS[@]} -ge 1 ]]; then
  AGENT="${POSITIONAL_ARGS[0]}"
fi
if [[ ${#POSITIONAL_ARGS[@]} -ge 2 ]]; then
  VERSION_ARG="${POSITIONAL_ARGS[1]}"
fi

# ------------------------------------------------------------------------------
# 1. Agent Selection & Discovery
# ------------------------------------------------------------------------------
discover_agents() {
  find . -maxdepth 2 -name ".goreleaser.yaml" -exec dirname {} \; | sed 's|^\./||' | sort -u
}

if [[ -z "$AGENT" ]]; then
  mapfile -t AVAILABLE_AGENTS < <(discover_agents)

  if [[ ${#AVAILABLE_AGENTS[@]} -eq 0 ]]; then
    abort "No agents found containing a .goreleaser.yaml configuration."
  elif [[ ${#AVAILABLE_AGENTS[@]} -eq 1 ]]; then
    AGENT="${AVAILABLE_AGENTS[0]}"
    info "Discovered single agent: ${BOLD}${AGENT}${NC}"
  else
    echo -e "\n${BOLD}Select an agent to release:${NC}"
    for i in "${!AVAILABLE_AGENTS[@]}"; do
      echo -e "  $((i+1))) ${AVAILABLE_AGENTS[$i]}"
    done
    read -rp "Enter choice [1-${#AVAILABLE_AGENTS[@]}]: " AGENT_CHOICE
    if ! [[ "$AGENT_CHOICE" =~ ^[0-9]+$ ]] || [ "$AGENT_CHOICE" -lt 1 ] || [ "$AGENT_CHOICE" -gt "${#AVAILABLE_AGENTS[@]}" ]; then
      abort "Invalid agent selection."
    fi
    AGENT="${AVAILABLE_AGENTS[$((AGENT_CHOICE-1))]}"
  fi
fi

if [[ ! -d "$AGENT" ]]; then
  abort "Agent directory '${AGENT}' does not exist."
fi

# ------------------------------------------------------------------------------
# 2. Determine Current Version
# ------------------------------------------------------------------------------
CONFIG_GO="${AGENT}/internal/config/config.go"
CURRENT_CONFIG_VER=""
if [[ -f "$CONFIG_GO" ]]; then
  CURRENT_CONFIG_VER=$(grep -E 'var[[:space:]]+Version[[:space:]]*=' "$CONFIG_GO" | sed -E 's/.*"([^"]+)".*/\1/' || true)
fi

# Check latest git tag for this agent
LATEST_TAG=$(git tag -l "${AGENT}/v*" | sed "s|^${AGENT}/v||" | sort -V | tail -n 1 || true)

# Determine the effective current version (highest of config and latest git tag)
CURRENT_VER="1.0.0"
if [[ -n "$CURRENT_CONFIG_VER" && -n "$LATEST_TAG" ]]; then
  CURRENT_VER=$(printf '%s\n%s\n' "$CURRENT_CONFIG_VER" "$LATEST_TAG" | sort -V | tail -n 1)
elif [[ -n "$LATEST_TAG" ]]; then
  CURRENT_VER="$LATEST_TAG"
elif [[ -n "$CURRENT_CONFIG_VER" ]]; then
  CURRENT_VER="$CURRENT_CONFIG_VER"
fi
CURRENT_VER="${CURRENT_VER#v}"

# ------------------------------------------------------------------------------
# 3. Calculate Target Version
# ------------------------------------------------------------------------------
calculate_bump() {
  local ver="$1"
  local type="$2"
  ver="${ver#v}"
  local major minor patch
  IFS='.' read -r major minor patch <<< "$ver"
  major="${major:-0}"
  minor="${minor:-0}"
  patch="${patch:-0}"

  case "$type" in
    major)
      echo "$((major + 1)).0.0"
      ;;
    minor)
      echo "${major}.$((minor + 1)).0"
      ;;
    patch)
      echo "${major}.${minor}.$((patch + 1))"
      ;;
    *)
      return 1
      ;;
  esac
}

PATCH_VER=$(calculate_bump "$CURRENT_VER" patch)
MINOR_VER=$(calculate_bump "$CURRENT_VER" minor)
MAJOR_VER=$(calculate_bump "$CURRENT_VER" major)

NEW_VERSION=""
if [[ -n "$VERSION_ARG" ]]; then
  case "$VERSION_ARG" in
    patch) NEW_VERSION="$PATCH_VER" ;;
    minor) NEW_VERSION="$MINOR_VER" ;;
    major) NEW_VERSION="$MAJOR_VER" ;;
    *)
      # Explicit version specified
      NEW_VERSION="${VERSION_ARG#v}"
      ;;
  esac
else
  echo -e "\nAgent: ${BOLD}${AGENT}${NC}"
  echo -e "Current Version: ${YELLOW}${CURRENT_VER}${NC}"
  echo -e "Select version bump:"
  echo -e "  1) patch -> ${BOLD}${PATCH_VER}${NC}"
  echo -e "  2) minor -> ${BOLD}${MINOR_VER}${NC}"
  echo -e "  3) major -> ${BOLD}${MAJOR_VER}${NC}"
  echo -e "  4) custom version string"
  read -rp "Enter choice [1-4] (default: 1): " BUMP_CHOICE
  BUMP_CHOICE="${BUMP_CHOICE:-1}"

  case "$BUMP_CHOICE" in
    1) NEW_VERSION="$PATCH_VER" ;;
    2) NEW_VERSION="$MINOR_VER" ;;
    3) NEW_VERSION="$MAJOR_VER" ;;
    4)
      read -rp "Enter version (e.g. 4.0.2): " CUSTOM_VER
      CUSTOM_VER="${CUSTOM_VER#v}"
      if [[ -z "$CUSTOM_VER" ]]; then
        abort "Version cannot be empty."
      fi
      NEW_VERSION="$CUSTOM_VER"
      ;;
    *)
      abort "Invalid selection."
      ;;
  esac
fi

# Validate SemVer pattern (X.Y.Z[-prerelease])
if ! [[ "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+.*$ ]]; then
  abort "Invalid version format '${NEW_VERSION}'. Must follow SemVer (e.g. 1.2.3)."
fi

TARGET_TAG="${AGENT}/v${NEW_VERSION}"

# ------------------------------------------------------------------------------
# 4. Safety Checks
# ------------------------------------------------------------------------------
info "Preparing release: ${BOLD}${AGENT}${NC} -> ${GREEN}v${NEW_VERSION}${NC} (Tag: ${CYAN}${TARGET_TAG}${NC})"

# Check if tag already exists locally or remotely
if git rev-parse "$TARGET_TAG" >/dev/null 2>&1; then
  abort "Tag '${TARGET_TAG}' already exists locally. Please bump to a newer version or delete the existing tag."
fi

if git ls-remote --tags origin "$TARGET_TAG" | grep -q "$TARGET_TAG"; then
  abort "Tag '${TARGET_TAG}' already exists on remote origin. Please bump to a newer version."
fi

# Check git status for uncommitted changes
if ! git diff-index --quiet HEAD --; then
  warn "Working directory has uncommitted changes:"
  git status --short
  if [[ "$DRY_RUN" == false ]]; then
    read -rp "Do you want to proceed and include these changes? [y/N]: " PROCEED_DIRTY
    if [[ ! "$PROCEED_DIRTY" =~ ^[Yy]$ ]]; then
      abort "Aborted by user due to uncommitted changes."
    fi
  fi
fi

if [[ "$DRY_RUN" == true ]]; then
  info "[DRY-RUN] Would update:"
  echo "  - ${CONFIG_GO} (var Version = \"${NEW_VERSION}\")"
  echo "  - Any example configs / READMEs in ${AGENT}"
  echo "  - Run 'go vet ./...' in ${AGENT}"
  echo "  - Commit: chore(${AGENT}): bump version to v${NEW_VERSION}"
  echo "  - Create annotated tag: ${TARGET_TAG}"
  echo "  - Push commit and tag to origin"
  success "[DRY-RUN] Validation completed successfully. No changes made."
  exit 0
fi

# ------------------------------------------------------------------------------
# 5. Update Version Files
# ------------------------------------------------------------------------------
FILES_TO_STAGE=()

if [[ -f "$CONFIG_GO" ]]; then
  info "Updating version in ${CONFIG_GO}..."
  sed -i -E "s/var Version = \"[^\"]+\"/var Version = \"${NEW_VERSION}\"/" "$CONFIG_GO"
  FILES_TO_STAGE+=("$CONFIG_GO")
  success "Updated ${CONFIG_GO}"
fi

# Update example configuration files if present
EXAMPLE_CONFIG="${AGENT}/${AGENT}.yaml.example"
if [[ -f "$EXAMPLE_CONFIG" ]]; then
  sed -i -E "s/(version: \")[^\"]+(\")/\1${NEW_VERSION}\2/" "$EXAMPLE_CONFIG"
  FILES_TO_STAGE+=("$EXAMPLE_CONFIG")
  success "Updated ${EXAMPLE_CONFIG}"
fi

AGENT_README="${AGENT}/README.md"
if [[ -f "$AGENT_README" ]]; then
  sed -i -E "s/(version: \")[0-9]+\.[0-9]+\.[0-9]+(\")/\1${NEW_VERSION}\2/g" "$AGENT_README"
  FILES_TO_STAGE+=("$AGENT_README")
  success "Updated ${AGENT_README}"
fi

# ------------------------------------------------------------------------------
# 6. Verify Agent Code Quality
# ------------------------------------------------------------------------------
info "Running code verification ('go vet ./...') in ${AGENT}..."
(
  cd "$AGENT"
  go vet ./...
)
success "Code verification passed."

# ------------------------------------------------------------------------------
# 7. Git Commit & Tag
# ------------------------------------------------------------------------------
info "Staging version bump and creating Git tag..."
for f in "${FILES_TO_STAGE[@]}"; do
  git add "$f"
done

# If there are tracked modified files or untracked fixes in agent directory, prompt or stage
COMMIT_MSG="chore(${AGENT}): bump version to v${NEW_VERSION}"

# Commit if any staged changes exist
if ! git diff --cached --quiet; then
  git commit -m "$COMMIT_MSG"
  success "Created commit: ${COMMIT_MSG}"
else
  warn "No files changed to commit for version bump."
fi

# Create annotated tag
git tag -a "$TARGET_TAG" -m "Release ${AGENT} v${NEW_VERSION}"
success "Created annotated tag: ${BOLD}${TARGET_TAG}${NC}"

# ------------------------------------------------------------------------------
# 8. Push to Origin
# ------------------------------------------------------------------------------
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)

SHOULD_PUSH=false
if [[ "$AUTO_PUSH" == true ]]; then
  SHOULD_PUSH=true
elif [[ "$AUTO_PUSH" == false ]]; then
  SHOULD_PUSH=false
else
  echo ""
  read -rp "Push branch '${CURRENT_BRANCH}' and tag '${TARGET_TAG}' to origin? [Y/n]: " CONFIRM_PUSH
  CONFIRM_PUSH="${CONFIRM_PUSH:-Y}"
  if [[ "$CONFIRM_PUSH" =~ ^[Yy]$ ]]; then
    SHOULD_PUSH=true
  fi
fi

if [[ "$SHOULD_PUSH" == true ]]; then
  info "Pushing commit on branch '${CURRENT_BRANCH}' to origin..."
  git push origin "$CURRENT_BRANCH"
  info "Pushing tag '${TARGET_TAG}' to origin..."
  git push origin "$TARGET_TAG"
  success "Successfully pushed branch and tag to origin!"
  echo ""
  echo -e "${GREEN}${BOLD}Release workflow triggered!${NC}"
  echo -e "GitHub Actions will build and release ${BOLD}${AGENT} v${NEW_VERSION}${NC}."
else
  warn "Tag was created locally but NOT pushed."
  echo -e "When ready to trigger the release, run:"
  echo -e "  ${BOLD}git push origin ${CURRENT_BRANCH}${NC}"
  echo -e "  ${BOLD}git push origin ${TARGET_TAG}${NC}"
fi
