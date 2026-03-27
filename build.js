const obfuscator = require('javascript-obfuscator')
const fs = require('fs')
const path = require('path')
const inputPath = path.join(__dirname, 'src', 'embed.js')
const outputPath = path.join(__dirname, 'dist', 'embed.min.js')
if (!fs.existsSync(path.dirname(outputPath))) {
  fs.mkdirSync(path.dirname(outputPath))
}
const sourceCode = fs.readFileSync(inputPath, 'utf8')
console.log('Obfuscating embed.js...')
const obfuscated = obfuscator.obfuscate(sourceCode, {
  compact: true,
  controlFlowFlattening: true,
  controlFlowFlatteningThreshold: 0.75,
  deadCodeInjection: true,
  deadCodeInjectionThreshold: 0.4,
  debugProtection: false, 
  debugProtectionInterval: 0,
  disableConsoleOutput: false, 
  identifierNamesGenerator: 'hexadecimal',
  log: false,
  numbersToExpressions: true,
  renameGlobals: false,
  selfDefending: true,
  simplify: true,
  splitStrings: true,
  splitStringsChunkLength: 10,
  stringArray: true,
  stringArrayCallsTransform: true,
  stringArrayEncoding: ['base64', 'rc4'],
  stringArrayIndexShift: true,
  stringArrayRotate: true,
  stringArrayShuffle: true,
  stringArrayWrappersCount: 2,
  stringArrayWrappersChainedCalls: true,
  stringArrayWrappersParametersMaxCount: 4,
  stringArrayWrappersType: 'function',
  stringArrayThreshold: 0.8,
  transformObjectKeys: true,
  unicodeEscapeSequence: false
})
fs.writeFileSync(outputPath, obfuscated.getObfuscatedCode())
console.log(`Successfully created ${outputPath} (${(obfuscated.getObfuscatedCode().length / 1024).toFixed(2)} KB)`)
