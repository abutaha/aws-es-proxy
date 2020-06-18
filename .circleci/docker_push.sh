#!/bin/bash

WORKDIR=$(echo $PWD | sed 's/\/.circleci//')
pip install --user awscli
export PATH="$(python -m site --user-base)/bin:${PATH}"
$(aws ecr get-login --registry-ids 387984977604 --no-include-email --region eu-west-1)
docker load < ${WORKDIR}/docker-cache/built-image.tar
IMAGE_TAG=`docker image ls | grep "${ECR_CENTRAL_REPOSITORY}/${ECR_REPO_NAME}" | awk '{print $2}'`
docker push ${ECR_CENTRAL_REPOSITORY}/${ECR_REPO_NAME}:${IMAGE_TAG}
