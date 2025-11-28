module.exports = (api) => {
  api.cache(true)
  return {
    presets: [
      ['babel-preset-expo', {
        jsxRuntime: 'automatic',
       
      }],
      
    ],
    plugins: [
      [
        'module-resolver',
        {
          root: ['./'],
          alias: {

            // 'crypto': 'crypto-browserify',
            // 'stream': 'readable-stream',
            '@iden3/js-crypto': '@iden3/js-crypto/dist/browser/esm/index.js',
          },
          extensions: [
            '.ios.ts',
            '.android.ts',
            '.ts',
            '.ios.tsx',
            '.android.tsx',
            '.tsx',
            '.jsx',
            '.js',
            '.json',
          ],
        },
      ],
      
    ],
  }
}
