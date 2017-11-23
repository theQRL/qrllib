#!/usr/bin/env bash
ls -lh
# Travis only clones the master branch, so I have to clone everything again to make sure I can switch branches.
mkdir merging_dir
git clone ${GIT_HTTPS_REPO} merging_dir/qrllib
cd merging_dir/qrllib
git remote -v
git branch -a

git checkout --track origin/xenial
mkdir ../xenial
cp -r results/* ../xenial/

git checkout --track origin/stretch
mkdir ../stretch
cp -r results/* ../stretch/

git checkout --track origin/gh-pages
rm -rf * .gitignore .travis.yml
mv  ../xenial ../stretch .

git add .
git commit -m "qrllib release debs"
echo "Git PUSHING"
git push ${GIT_HTTPS_REPO_AUTHED} HEAD:gh-pages -f
