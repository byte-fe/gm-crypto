import toArrayBuffer from 'to-arraybuffer'
import { Buffer } from 'buffer' // 兼容浏览器环境
import WASMManager from './utils'

// 两种分组模式
const ECB = 1
const CBC = 2

// SM4 相关常量
export const constants = { ECB, CBC }

// 十六进制表示的加密密钥和初始化向量 iv
const REG_EXP_KEY = /^[0-9a-f]{32}$/i

export const encrypt = async (data, key, options) => {
  let { mode, iv, inputEncoding, outputEncoding } = options || {}

  // 输入参数校验 `string` | `ArrayBuffer` | `Buffer`
  if (typeof data === 'string') {
    data = Buffer.from(data, inputEncoding || 'utf8')
  } else if (data instanceof ArrayBuffer) {
    data = Buffer.from(data)
  }
  if (!Buffer.isBuffer(data)) {
    throw new TypeError(
      `Expected "string" | "Buffer" | "ArrayBuffer" but received "${Object.prototype.toString.call(
        data
      )}"`
    )
  }

  // 十六进制表示的密钥
  if (!REG_EXP_KEY.test(key)) {
    throw new TypeError('Invalid value of cipher `key`')
  }
  key = Buffer.from(key, 'hex')

  // CBC 分组必须制定 iv
  if (mode === CBC && !REG_EXP_KEY.test(iv)) {
    throw new TypeError('Invalid value of `iv` option')
  }
  iv = mode === CBC ? Buffer.from(iv, 'hex') : null

  const gm_wasm = await WASMManager.getInstance()

  const res =
    mode === CBC
      ? gm_wasm.sm4_encrypt_cbc(key, iv, data)
      : gm_wasm.sm4_encrypt_ecb(key, data)

  const buff = Buffer.from(res)

  return outputEncoding ? buff.toString(outputEncoding) : toArrayBuffer(buff)
}

export const decrypt = async (data, key, options) => {
  let { mode, iv, inputEncoding, outputEncoding } = options || {}

  // 输入参数校验 `string` | `ArrayBuffer` | `Buffer`
  if (typeof data === 'string') {
    data = Buffer.from(data, inputEncoding)
  } else if (data instanceof ArrayBuffer) {
    data = Buffer.from(data)
  }
  if (!Buffer.isBuffer(data)) {
    throw new TypeError(
      `Expected "string" | "Buffer" | "ArrayBuffer" but received "${Object.prototype.toString.call(
        data
      )}"`
    )
  }

  // 十六进制表示的密钥
  if (!REG_EXP_KEY.test(key)) {
    throw new TypeError('Invalid value of cipher `key`')
  }

  key = Buffer.from(key, 'hex')

  // CBC 分组必须制定 iv
  if (mode === CBC && !REG_EXP_KEY.test(iv)) {
    throw new TypeError('Invalid value of `iv` option')
  }

  iv = mode === CBC ? Buffer.from(iv, 'hex') : null

  const gm_wasm = await WASMManager.getInstance()

  const res =
    mode === CBC
      ? gm_wasm.sm4_decrypt_cbc(key, iv, data)
      : gm_wasm.sm4_decrypt_ecb(key, data)

  const buff = Buffer.from(res)

  return outputEncoding ? buff.toString(outputEncoding) : toArrayBuffer(buff)
}
