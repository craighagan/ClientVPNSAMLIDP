mv .git .git.save


git init
git remote add origin git@github.com:craighagan/ClientVPNSAMLIDP.git

git branch main
git checkout main

git add *
git commit -am 'message'

git push -f origin master


