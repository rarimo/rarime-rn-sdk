const { withProjectBuildGradle } = require('@expo/config-plugins')

const withRnNoir = config => {
  return withProjectBuildGradle(config, config => {
    const buildGradle = config.modResults.contents

    // TODO: Need to figure out how to share this snippet for other aar libraries
    const flatDirSnippet = `
allprojects {
    repositories {
        flatDir {
            // Point directly to the local module's AARs without requiring a Gradle project include
            dirs new File(rootDir, '../../android/libs')
        }
    }
}
`

      // Replace any legacy references to project(':rarimo-rn-sdk') with a direct path
      const problematic = "project(':rarimo-rn-sdk').projectDir.absolutePath + '/libs'"
      const replacement = "new File(rootDir, '../../android/libs')"

      let newContents = buildGradle
      if (newContents.includes(problematic)) {
          newContents = newContents.split(problematic).join(replacement)
      }

      // Only add our snippet if not already present
      if (!newContents.includes("../../android/libs") && !newContents.includes(replacement)) {
          newContents = newContents + flatDirSnippet
    }

      config.modResults.contents = newContents

    return config
  })
}

module.exports = withRnNoir
