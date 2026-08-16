import js from '@eslint/js'
import boundaries from 'eslint-plugin-boundaries'
import vue from 'eslint-plugin-vue'
import globals from 'globals'
import tseslint from 'typescript-eslint'

const fsdElements = [
  { type: 'app', pattern: 'apps/*/src/app/**' },
  { type: 'app', pattern: 'apps/*/src/*.ts' },
  { type: 'app', pattern: 'apps/*/src/*.d.ts' },
  { type: 'pages', pattern: 'apps/*/src/pages/*/**', capture: ['slice'] },
  { type: 'widgets', pattern: 'apps/*/src/widgets/*/**', capture: ['slice'] },
  { type: 'features', pattern: 'apps/*/src/features/*/**', capture: ['slice'] },
  { type: 'entities', pattern: 'apps/*/src/entities/*/**', capture: ['slice'] },
  { type: 'shared', pattern: 'apps/*/src/shared/**' },
  { type: 'package', pattern: 'packages/*/**', capture: ['package'] },
]

export default tseslint.config(
  {
    ignores: [
      '**/dist/**',
      '**/node_modules/**',
      '**/target/**',
      'upstream/**',
      'outputs/**',
      'apps/**/src-tauri/gen/**',
      'scripts/**/*.py',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  ...vue.configs['flat/recommended'],
  {
    files: ['apps/**/*.ts', 'apps/**/*.vue', 'packages/**/*.ts', 'packages/**/*.vue'],
    languageOptions: {
      globals: globals.browser,
      parserOptions: {
        parser: tseslint.parser,
      },
    },
    plugins: {
      boundaries,
    },
    settings: {
      'boundaries/elements': fsdElements,
      'boundaries/include': ['apps/*/src/**', 'packages/*/**'],
    },
    rules: {
      'boundaries/element-types': [
        'error',
        {
          default: 'disallow',
          rules: [
            { from: 'app', allow: ['pages', 'widgets', 'features', 'entities', 'shared', 'package'] },
            { from: 'pages', allow: ['widgets', 'features', 'entities', 'shared', 'package'] },
            { from: 'widgets', allow: ['features', 'entities', 'shared', 'package'] },
            { from: 'features', allow: ['entities', 'shared', 'package'] },
            { from: 'entities', allow: ['shared', 'package'] },
            { from: 'shared', allow: ['package'] },
            { from: 'package', allow: ['package'] },
          ],
        },
      ],
      'boundaries/no-private': 'error',
      'boundaries/no-unknown-files': 'error',
      'vue/multi-word-component-names': 'off',
      'vue/require-default-prop': 'off',
    },
  },
  {
    files: ['apps/*/src/main.ts', 'apps/*/src/env.d.ts'],
    rules: {
      'boundaries/no-unknown-files': 'off',
    },
  },
)
