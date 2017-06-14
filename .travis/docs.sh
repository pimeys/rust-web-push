#!/bin/bash

set -o errexit

shopt -s globstar

cargo doc --no-deps

git clone --branch gh-pages "https://$TOKEN@github.com/${TRAVIS_REPO_SLUG}.git" deploy_docs > /dev/null 2>&1
cd deploy_docs

git config user.name "Julius de Bruijn"
git config user.email "julius.debruijn@360dialog.com"

rm -rf master
mv ../target/doc ./master
echo "<meta http-equiv=refresh content=0;url=web_push/index.html>" > ./master/index.html

git add -A .
git commit -m "rebuild pages at ${TRAVIS_COMMIT}"

echo
echo "Pushing docs..."
git push --quiet origin gh-pages > /dev/null 2>&1
echo
echo "Docs published."
echo
