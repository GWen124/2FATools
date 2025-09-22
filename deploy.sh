#!/bin/sh
set -e

echo "Deploying to GitHub..."

if [ -z "$(git config user.name)" ]; then
  git config user.name "auto-deploy"
fi
if [ -z "$(git config user.email)" ]; then
  git config user.email "auto@deploy.local"
fi

git add -A
if git diff --cached --quiet; then
  echo "No changes to commit."
else
  git commit -m "chore: deploy $(date '+%Y-%m-%d %H:%M:%S')"
fi

echo "Push to origin main"
git branch -M main || true
git push -u origin main

echo "Enable GitHub Pages: Settings > Pages > Deploy from a branch > main / (root)"
