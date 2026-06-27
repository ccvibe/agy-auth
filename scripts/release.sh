#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Starting release process ===${NC}"

# 1. Check current branch
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" != "main" ]; then
    echo -e "${RED}Error: You are not on the 'main' branch (current: $CURRENT_BRANCH). Please switch to 'main' first.${NC}"
    exit 1
fi

# 2. Run cargo test
echo -e "${BLUE}Running cargo test...${NC}"
if ! cargo test; then
    echo -e "${RED}Error: cargo test failed. Aborting release.${NC}"
    exit 1
fi
echo -e "${GREEN}Cargo tests passed!${NC}"

# 3. Run cargo build
echo -e "${BLUE}Running cargo build...${NC}"
if ! cargo build; then
    echo -e "${RED}Error: cargo build failed. Aborting release.${NC}"
    exit 1
fi
echo -e "${GREEN}Cargo build succeeded!${NC}"

# 4. Bump version in package.json
echo -e "${BLUE}Bumping patch version in package.json...${NC}"
NEW_VERSION=$(node -e "
  const fs = require('fs');
  const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  const parts = pkg.version.split('.');
  parts[2] = String(Number(parts[2]) + 1);
  const newV = parts.join('.');
  pkg.version = newV;
  if (pkg.optionalDependencies) {
    for (const key of Object.keys(pkg.optionalDependencies)) {
      pkg.optionalDependencies[key] = '^' + newV;
    }
  }
  fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2) + '\n', 'utf8');
  console.log(newV);
")

echo -e "${GREEN}Version bumped to v${NEW_VERSION}${NC}"

# 5. Commit changes
echo -e "${BLUE}Committing changes...${NC}"
git add .
git commit -m "chore: release v${NEW_VERSION}"
echo -e "${GREEN}Committed successfully.${NC}"

# 6. Create Tag
echo -e "${BLUE}Creating git tag v${NEW_VERSION}...${NC}"
git tag "v${NEW_VERSION}"
echo -e "${GREEN}Tag v${NEW_VERSION} created.${NC}"

# 7. Push to remote
echo -e "${BLUE}Pushing code and tag to remote repository...${NC}"
git push origin main
git push origin "v${NEW_VERSION}"

echo -e "${GREEN}=== Release v${NEW_VERSION} published successfully! ===${NC}"
