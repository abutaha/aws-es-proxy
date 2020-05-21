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
                container('go') {
                    sh "CGO_ENABLED=0 GOOS=linux go build -o aws-es-proxy"
                }
            }
        }

        stage("Build") {
            steps {
                container('docker') {
                    sh "docker build -t aws-es-proxy:${env.DOCKER_TAG} ."
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
                            sh "docker tag aws-es-proxy:${env.DOCKER_TAG} ${DOCKER_REPOSITORY}/aws-es-proxy:${env.DOCKER_TAG}"
                            sh "docker push ${DOCKER_REPOSITORY}/aws-es-proxy:${env.DOCKER_TAG}"
                        }
                    }
                }
            }
        }
    }
}