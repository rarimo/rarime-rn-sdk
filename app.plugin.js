const { withProjectBuildGradle } = require('@expo/config-plugins')

const withRnNoir = config => {
  return withProjectBuildGradle(config, config => {
    const buildGradle = config.modResults.contents

    // TODO: Need to figure out how to share this snippet for other aar libraries
    const flatDirSnippet = `
allprojects {
    repositories {
        flatDir {
            dirs project(':rarimo-rn-sdk').projectDir.absolutePath + '/libs'
        }
    }
}
`

    // Only add if not already present
    if (!buildGradle.includes("project(':rarimo-rn-sdk').projectDir.absolutePath + '/libs'")) {
      config.modResults.contents = buildGradle + flatDirSnippet
    }

    return config
  })
}

module.exports = withRnNoir
