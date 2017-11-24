echo "PUSHING TO GITHUB PAGES"
if [ `git branch --list ${PLATFORM} `]
then
    echo "Branch ${PLATFORM} already exists, deleting"
fi
git checkout --orphan ${PLATFORM}
git rm -rf .
git add results/
git commit -m "pyqrllib ${PLATFORM} release"
git push https://randomshinichi:$GITHUB_TOKEN@github.com/randomshinichi/qrllib.git HEAD:${PLATFORM} -f
