#!/bin/bash

set -o errexit

shopt -s globstar

cargo doc --no-deps

REPO=`git config remote.origin.url`
SSH_REPO=${REPO/https:\/\/github.com\//git@github.com:}
SHA=`git rev-parse --verify HEAD`

git clone --branch gh-pages $REPO deploy_docs
cd deploy_docs

git config user.name "Julius de Bruijn"
git config user.email "julius.debruijn@360dialog.com"

rm -rf master
mv ../target/doc ./master
echo "<meta http-equiv=refresh content=0;url=web_push/index.html>" > ./master/index.html

git add -A .
git commit -m "rebuild pages at ${TRAVIS_COMMIT}"

ENCRYPTED_KEY_VAR="encrypted_${ENCRYPTION_LABEL}_key"
ENCRYPTED_IV_VAR="encrypted_${ENCRYPTION_LABEL}_iv"
ENCRYPTED_KEY=${!ENCRYPTED_KEY_VAR}
ENCRYPTED_IV=${!ENCRYPTED_IV_VAR}

openssl aes-256-cbc -K $ENCRYPTED_KEY -iv $ENCRYPTED_IV -in github_travis_ecdsa.enc -out github_travis_ecdsa -d
chmod 600 deploy_key
eval `ssh-agent -s`
ssh-add deploy_key

echo
echo "Pushing docs..."
git push $SSH_REPO gh-pages
echo
echo "Docs published."
echo
