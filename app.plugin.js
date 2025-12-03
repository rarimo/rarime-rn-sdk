const { withProjectBuildGradle, withSettingsGradle } = require('@expo/config-plugins')

const withRnNoir = config => {
  // Update project build.gradle
  config = withProjectBuildGradle(config, config => {
    let buildGradle = config.modResults.contents

    const localAarFile = "new File(rootDir, '../../android/libs')"
    const nodeModulesAar = '"$rootDir/../node_modules/@rarimo/rarime-rn-sdk/android/libs"'

    // More robust flatDir snippet insertion (include both local and node_modules locations)
    const flatDirEntries = `
      flatDir {
        // Prefer local project libs, also allow resolution from node_modules
        dirs ${localAarFile}
        dirs ${nodeModulesAar}
      }
  `

    const flatDirSnippet = `allprojects {\n    repositories {\n${flatDirEntries}    }\n}\n`

    // Replace various legacy references to project(':rarimo-rn-sdk') + '/libs'
    const problematicRegex = /project\(':rarimo-rn-sdk'\)\.projectDir(?:\.absolutePath|\.path)?\s*\+\s*['"]\/libs['"]/g

    if (problematicRegex.test(buildGradle)) {
      buildGradle = buildGradle.replace(problematicRegex, localAarFile)
    }

    // If there is an allprojects -> repositories block, inject flatDir there (if missing)
    const repositoriesBlockRegex = /(allprojects\s*\{[\s\S]*?repositories\s*\{)([\s\S]*?)(\}\s*\})/m
    if (repositoriesBlockRegex.test(buildGradle)) {
      buildGradle = buildGradle.replace(repositoriesBlockRegex, (match, p1, p2, p3) => {
        // If any candidate dirs are already present, skip injection
        if (p2.includes("android/libs") || p2.includes(localAarFile) || p2.includes(nodeModulesAar)) {
          return match
        }
        return `${p1}\n${flatDirEntries}${p2}${p3}`
      })
    } else if (!buildGradle.includes("android/libs") && !buildGradle.includes(localAarFile) && !buildGradle.includes(nodeModulesAar)) {
      // Fallback: append a small allprojects snippet if no repositories block found
      buildGradle = buildGradle + '\n' + flatDirSnippet
    }

    config.modResults.contents = buildGradle
    return config
  })

  // Also update settings.gradle in case the host app uses newer Gradle settings structure
  config = withSettingsGradle(config, config => {
    let settings = config.modResults.contents || ''

    // Some projects use dependencyResolutionManagement in settings.gradle; try to add a flatDir entry
    if (!settings.includes("../../android/libs") && !settings.includes("android/libs")) {
      // Attempt to add a top-level include for flatDir-style repositories by appending a comment
      settings = settings + `\n// Added by withRnNoir: allow local AARs from ../..\n`
    }

    config.modResults.contents = settings
    return config
  })

  return config
}

module.exports = withRnNoir
