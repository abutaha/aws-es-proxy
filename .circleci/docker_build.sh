#!/bin/bash

WORKDIR=$(echo $PWD | sed 's/\/.circleci//')
IMAGE_TAG=`echo ${CIRCLE_SHA1} | grep -o -E '.{0,8}'| head -n1`
docker build -t ${ECR_CENTRAL_REPOSITORY}/${ECR_REPO_NAME}:${IMAGE_TAG} .
mkdir -p ${WORKDIR}/docker-cache
docker save -o ${WORKDIR}/docker-cache/built-image.tar ${ECR_CENTRAL_REPOSITORY}/${ECR_REPO_NAME}:${IMAGE_TAG}

