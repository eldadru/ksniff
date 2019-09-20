#!/bin/bash

THIS_BRANCH_VERSION=$(cat VERSION)
if [[ $(git tag -l "$THIS_BRANCH_VERSION") ]]; then
    echo "[-] Version $THIS_BRANCH_VERSION is already tagged, please increase plugin version"
    exit 1
else
    echo "[-] Version $THIS_BRANCH_VERSION is not tagged yet."
    exit 0
fi