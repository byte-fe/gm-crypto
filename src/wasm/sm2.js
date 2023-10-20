import toArrayBuffer from 'to-arraybuffer'
import { Buffer } from 'buffer' // 兼容浏览器环境
import WASMManager from './utils'

export const C1C2C3 = 0
export const C1C3C2 = 1
export const PC = '04'

export const generateKeyPair = async (needPC = true) => {
  const gm_wasm = await WASMManager.getInstance()
  const kp = gm_wasm.sm2_gen_keypair()
  return {
    privateKey: kp.private_key,
    publicKey: (needPC ? PC : '') + kp.public_key
  }
}

export const encrypt = async (data, publicKey, options) => {
  const { mode = C1C3C2, inputEncoding, outputEncoding, pc } = options || {}

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

  const gm_wasm = await WASMManager.getInstance()

  const res = Buffer.from(
    mode === C1C2C3
      ? gm_wasm.sm2_encrypt_c1c2c3(publicKey, new Uint8Array(data.buffer))
      : gm_wasm.sm2_encrypt_c1c3c2(publicKey, new Uint8Array(data.buffer))
  )

  const buff = pc === 1 ? Buffer.concat([Buffer.from('04', 'hex'), res]) : res

  return outputEncoding ? buff.toString(outputEncoding) : toArrayBuffer(buff)
}

export const decrypt = async (data, privateKey, options) => {
  const { mode = C1C3C2, inputEncoding, outputEncoding, pc } = options || {}

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

  const gm_wasm = await WASMManager.getInstance()

  const res =
    mode === C1C2C3
      ? gm_wasm.sm2_decrypt_c1c2c3(privateKey, new Uint8Array(data.buffer))
      : gm_wasm.sm2_decrypt_c1c3c2(privateKey, new Uint8Array(data.buffer))

  const buff = Buffer.from(res)

  return outputEncoding ? buff.toString(outputEncoding) : toArrayBuffer(buff)
}

export const constants = { C1C2C3, C1C3C2, PC }
