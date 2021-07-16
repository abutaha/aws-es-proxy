#!/usr/bin/env groovy
pipeline {
    agent {
        kubernetes {
            label "jenkins-pods-${UUID.randomUUID().toString()}"
            defaultContainer 'jnlp'
            yamlFile '.ci/pod.yaml'
        }
    }

    environment {
        LABEL = "jenkins-pods-${UUID.randomUUID().toString()}"
        DOCKER_REPOSITORY = "772592230491.dkr.ecr.eu-west-1.amazonaws.com"
        DOCKER_TAG = "${env.TAG_NAME ?: env.GIT_COMMIT}"
        SLACK_CHANNEL = "#backend-builds"
    }

    options {
        timestamps()
    }

    stages {
        stage("Build") {
            steps {
                container('docker') {
                    sh """
                        for arch in amd64 arm64  ; do
                            docker build -t aws-es-proxy:${env.DOCKER_TAG}-\${arch} .
                        done
                    """
                }
            }
        }

        stage("Push") {
            when {
                anyOf {
                    buildingTag()
                    branch "master"
                }
            }

            steps {
                container('docker') {
                    script {
                        docker.withRegistry("https://${DOCKER_REPOSITORY}", 'ecr:eu-west-1:ecr-credentials') {
                            sh """
                                for arch in amd64 arm64  ; do
                                    docker tag aws-es-proxy:${env.DOCKER_TAG} ${DOCKER_REPOSITORY}/aws-es-proxy:${env.DOCKER_TAG}-\${arch}
                                    docker push ${DOCKER_REPOSITORY}/aws-es-proxy:${env.DOCKER_TAG}-\${arch}
                                done 

                                echo "Creating manifest"
                                docker manifest create ${DOCKER_REPOSITORY}/${DOCKER_IMAGE}:${env.DOCKER_TAG} ${DOCKER_REPOSITORY}/${DOCKER_IMAGE}:${env.DOCKER_TAG}-amd64 ${DOCKER_REPOSITORY}/${DOCKER_IMAGE}:${env.DOCKER_TAG}-arm64
                                docker manifest push ${DOCKER_REPOSITORY}/${DOCKER_IMAGE}:${env.DOCKER_TAG}
                            """
                        }
                    }
                }
            }
        }
    }
}