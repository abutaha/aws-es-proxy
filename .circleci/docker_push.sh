#!/bin/bash

WORKDIR=$(echo $PWD | sed 's/\/.circleci//')
pip install --user awscli
export PATH="$(python -m site --user-base)/bin:${PATH}"
$(aws ecr get-login --registry-ids 387984977604 --no-include-email --region eu-west-1)
docker load < ${WORKDIR}/docker-cache/built-image.tar
[[ ! -z ${CIRCLE_TAG} ]] || { echo "No git tag in this pipeline exiting ...."; exit 0; }
docker tag ${ECR_CENTRAL_REPOSITORY}/${ECR_REPO_NAME} ${ECR_CENTRAL_REPOSITORY}/${ECR_REPO_NAME}:${CIRCLE_TAG}
docker push ${ECR_CENTRAL_REPOSITORY}/${ECR_REPO_NAME}:${CIRCLE_TAG}
