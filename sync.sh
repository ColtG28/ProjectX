#!/bin/bash

# Type: ''./sync.sh' to commit

# Set a default commit message or ask for one
MESSAGE=${1:-"Auto commit"}

git add .
git commit -m "$MESSAGE"
git push

