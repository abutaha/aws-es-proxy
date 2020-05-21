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
                    sh "docker build -t aws-es-proxy:${env.DOCKER_TAG} ."
                }
            }
        }
    }
}