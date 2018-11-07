standardPipeline {
    
  standardNode {
    checkoutStage {}

    def imageMap = dockerBuildStage {
      buildArgs = '--pull'
      push = false
      cleanup = false
    }

    if (isMasterBranch()) {
      def version = "${env.BUILD_ID}"
      autoPublishStage {
        getCurrentVer = {
          version
        }
        getPublishedVer = {
          "0"
        }
        postTag = {
          imageName = repoName()
          imageId = imageMap[imageName]
          imageReleaseTag = "${dockerRegistry()}/${imageName}:${version}"
          imageLatestTag = "${dockerRegistry()}/${imageName}:latest"
          dockerCmd "tag '${imageId}' '${imageReleaseTag}'"
          dockerCmd "tag '${imageId}' '${imageLatestTag}'"
          dockerCmd "push '${imageReleaseTag}'"
          dockerCmd "push '${imageLatestTag}'"
        }
      }
    }
  }
}
