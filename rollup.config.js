import rollupTypescript from 'rollup-plugin-typescript2'
import { terser } from 'rollup-plugin-terser'
import RollupPluginNodeResolve from '@rollup/plugin-node-resolve'
import RollupPluginCommonjs from '@rollup/plugin-commonjs'
import nodePolyfills from 'rollup-plugin-polyfill-node'
import rust from '@wasm-tool/rollup-plugin-rust'

export default {
  input: 'src/index.js',
  output: [
    {
      name: 'gm-crypto',
      file: 'dist/index.js',
      format: 'umd',
      plugins: [terser()]
    },
    {
      name: 'gm-crypto',
      file: 'dist/index.esm.js',
      format: 'es',
      plugins: [terser()]
    },
    {
      name: 'gm-crypto',
      file: 'dist/index.modern.js',
      format: 'es',
      plugins: [terser()]
    },
    {
      name: 'gm-crypto',
      file: 'dist/index.commonjs.js',
      format: 'commonjs',
      plugins: [terser()]
    },
    {
      name: 'gm-crypto',
      file: 'dist/index.umd.js',
      format: 'umd',
      plugins: [terser()]
    }
  ],
  plugins: [
    rust({
      inlineWasm: true
    }),
    rollupTypescript(),
    RollupPluginCommonjs(),
    nodePolyfills(),
    RollupPluginNodeResolve()
  ]
}
