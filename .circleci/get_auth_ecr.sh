#!/bin/bash

WORKDIR=$(echo $PWD | sed 's/\/.circleci//')
$(aws ecr get-login --registry-ids 387984977604 --no-include-email --region eu-west-1)
IMAGE_TAG=`echo ${CIRCLE_SHA1} | grep -o -E '.{0,8}'| head -n1`
if ! [ -z ${CIRCLE_TAG} ]; then IMAGE_TAG=`echo ${CIRCLE_TAG}`; fi
docker build -t ${ECR_REPOSITORY}/${ECR_REPO_NAME}:${IMAGE_TAG} .
docker push ${ECR_REPOSITORY}/${ECR_REPO_NAME}:${IMAGE_TAG}
