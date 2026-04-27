#!/bin/bash
set -euo pipefail

# Release script for STYLiTE Orbit dashboard
# Usage: ./release.sh [major|minor|patch]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Default to patch if no argument provided
BUMP_TYPE="${1:-patch}"

if [[ ! "$BUMP_TYPE" =~ ^(major|minor|patch)$ ]]; then
    echo "Error: Invalid bump type '$BUMP_TYPE'. Must be major, minor, or patch."
    exit 1
fi

# Check for uncommitted changes
if ! git diff-index --quiet HEAD --; then
    echo "Error: You have uncommitted changes. Please commit or stash them first."
    exit 1
fi

# Read current version
if [[ ! -f VERSION ]]; then
    echo "Error: VERSION file not found."
    exit 1
fi

CURRENT_VERSION=$(cat VERSION | tr -d '\n\r ')
if [[ ! "$CURRENT_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Invalid version format in VERSION file: '$CURRENT_VERSION'"
    exit 1
fi

# Parse version components
IFS='.' read -r -a VERSION_PARTS <<< "$CURRENT_VERSION"
MAJOR="${VERSION_PARTS[0]}"
MINOR="${VERSION_PARTS[1]}"
PATCH="${VERSION_PARTS[2]}"

# Increment version
case "$BUMP_TYPE" in
    major)
        MAJOR=$((MAJOR + 1))
        MINOR=0
        PATCH=0
        ;;
    minor)
        MINOR=$((MINOR + 1))
        PATCH=0
        ;;
    patch)
        PATCH=$((PATCH + 1))
        ;;
esac

NEW_VERSION="${MAJOR}.${MINOR}.${PATCH}"
TAG_NAME="${NEW_VERSION}"

echo "Current version: $CURRENT_VERSION"
echo "New version: $NEW_VERSION"
echo "Bump type: $BUMP_TYPE"
echo ""

# Update CHANGELOG.md
if [[ ! -f CHANGELOG.md ]]; then
    echo "Error: CHANGELOG.md not found."
    exit 1
fi

TODAY=$(date +%Y-%m-%d)

# Check if [Unreleased] section exists
if ! grep -q "^## \[Unreleased\]" CHANGELOG.md; then
    echo "Warning: [Unreleased] section not found in CHANGELOG.md"
    echo "Adding it now..."
    if [[ "$(uname)" == "Darwin" ]]; then
        sed -i '' '7a\
\
## [Unreleased]
' CHANGELOG.md
    else
        sed -i '7a\\n## [Unreleased]' CHANGELOG.md
    fi
fi

# Insert new version section after [Unreleased]
if [[ "$(uname)" == "Darwin" ]]; then
    sed -i '' "/^## \[Unreleased\]/a\\
\\
## [$NEW_VERSION] - $TODAY
" CHANGELOG.md
else
    sed -i "/^## \[Unreleased\]/a\\\n## [$NEW_VERSION] - $TODAY" CHANGELOG.md
fi

# Update VERSION file
echo -n "$NEW_VERSION" > VERSION

echo "✓ Updated CHANGELOG.md"
echo "✓ Updated VERSION file"
echo ""

# Show the Version and CHANGELOG.md changes
echo "Version and CHANGELOG.md changes:"
git --no-pager diff VERSION CHANGELOG.md
echo ""

# Prompt for confirmation
read -p "Proceed with commit, tag, and push? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted. Changes have been made to VERSION and CHANGELOG.md."
    echo "You can review them and commit manually if needed."
    exit 0
fi

# Commit changes
git add VERSION CHANGELOG.md
git commit -m "chore: bump version to $NEW_VERSION"

# Create annotated tag
git tag -a "$TAG_NAME" -m "Release $NEW_VERSION"

echo "✓ Committed changes"
echo "✓ Created tag $TAG_NAME"
echo ""

# Push branch and tag
echo "Pushing to origin..."
git push origin HEAD
git push origin "$TAG_NAME"

echo "✓ Pushed branch and tag to origin"
echo ""

# Display Docker image URLs
echo "Docker images that will be built:"
echo "  - docker.io/styliteag/dashboard:$NEW_VERSION"
echo "  - docker.io/styliteag/dashboard:latest"
echo "  - ghcr.io/styliteag/dashboard:$NEW_VERSION"
echo "  - ghcr.io/styliteag/dashboard:latest"
echo ""
echo "Release $NEW_VERSION completed successfully!"
