#!/bin/bash

WORKDIR=$(echo $PWD | sed 's/\/.circleci//')
docker build -t ${ECR_CENTRAL_REPOSITORY}/${ECR_REPO_NAME} .
mkdir -p ${WORKDIR}/docker-cache
docker save -o ${WORKDIR}/docker-cache/built-image.tar ${ECR_CENTRAL_REPOSITORY}/${ECR_REPO_NAME}

