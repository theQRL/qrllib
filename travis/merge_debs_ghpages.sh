#!/usr/bin/env bash

# Travis only clones the master branch, so I have to clone everything again to make sure I can switch branches.
mkdir working_dir
git clone https://github.com/randomshinichi/qrllib.git working_dir/qrllib
cd working_dir/qrllib
git remote -v
git branch -a

git checkout --track origin/xenial
cp -r built/* ..

git checkout --track origin/stretch
cp -r built/* ..

git checkout --track origin/gh-pages
rm -rf * .gitignore .travis.yml
cp -r ../xenial ../stretch .

git add .
git commit -m "qrllib release debs"
git push https://randomshinichi:$GITHUB_TOKEN@github.com/randomshinichi/qrllib.git HEAD:gh-pages -f
