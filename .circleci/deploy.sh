#!/bin/bash

if [ -f /tmp/envs ]; then
  source /tmp/envs
else
  IMAGE_TAG=`echo ${CIRCLE_SHA1} | grep -o -E '.{0,8}'| head -n1`
fi

WORKDIR=$(echo $PWD | sed 's/\/.circleci//')
YARA_REGION="emea"
AWS_REGION="eu-central-1"

sudo chown -R 1000:1000 ${WORKDIR}
$(aws ecr get-login --registry-ids 387984977604 --no-include-email --region eu-west-1)
docker pull 387984977604.dkr.ecr.eu-west-1.amazonaws.com/${CIRCLE_CI_HELM_SCRIPTS_IMAGE}

docker run --add-host kubernetes.default.svc:127.0.0.1 --env ECR_CENTRAL_REPOSITORY=${ECR_CENTRAL_REPOSITORY} --env ECR_REPO_NAME=${ECR_REPO_NAME} --env IMAGE_TAG=${IMAGE_TAG} --env API_HOST=${KUBE_API_ADDR} --env BASTION_HOST=${BASTION_HOST} --env YARA_REGION="${YARA_REGION}" --env ENVIRONMENT="${ENVIRONMENT}" --env AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID} --env AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY} --env AWS_REGION="${AWS_REGION}" --env KUBECFG_64=${KUBECONFIG} --env HELMFILE_LOCATION="/home/app/infra/helmfile.yaml" --volume ${WORKDIR}/infra:/home/app/infra 387984977604.dkr.ecr.eu-west-1.amazonaws.com/${CIRCLE_CI_HELM_SCRIPTS_IMAGE} --deploy=true
