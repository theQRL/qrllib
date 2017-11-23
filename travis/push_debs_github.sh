set -e
echo "PUSHING TO GITHUB PAGES"
if [ `git rev-parse --quiet --verify ${PLATFORM}` > /dev/null ]
then
    echo "Branch ${PLATFORM} already exists, deleting"
    git branch -D ${PLATFORM}
fi
git checkout --orphan ${PLATFORM}
git rm -rf .
git add results/
git commit -m "pyqrllib ${PLATFORM} release"

git push https://randomshinichi:${GITHUB_TOKEN}@github.com/randomshinichi/qrllib.git HEAD:${PLATFORM} -f
