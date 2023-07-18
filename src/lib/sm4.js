import toArrayBuffer from 'to-arraybuffer'
import { Buffer } from 'buffer' // 兼容浏览器环境
import { leftShift } from './utils'

// 两种分组模式
const ECB = 1
const CBC = 2

// SM4 相关常量
export const constants = { ECB, CBC }

// S 盒（非线性变换）
const SBOX_TABLE = [
  [
    0xd6,
    0x90,
    0xe9,
    0xfe,
    0xcc,
    0xe1,
    0x3d,
    0xb7,
    0x16,
    0xb6,
    0x14,
    0xc2,
    0x28,
    0xfb,
    0x2c,
    0x05
  ],
  [
    0x2b,
    0x67,
    0x9a,
    0x76,
    0x2a,
    0xbe,
    0x04,
    0xc3,
    0xaa,
    0x44,
    0x13,
    0x26,
    0x49,
    0x86,
    0x06,
    0x99
  ],
  [
    0x9c,
    0x42,
    0x50,
    0xf4,
    0x91,
    0xef,
    0x98,
    0x7a,
    0x33,
    0x54,
    0x0b,
    0x43,
    0xed,
    0xcf,
    0xac,
    0x62
  ],
  [
    0xe4,
    0xb3,
    0x1c,
    0xa9,
    0xc9,
    0x08,
    0xe8,
    0x95,
    0x80,
    0xdf,
    0x94,
    0xfa,
    0x75,
    0x8f,
    0x3f,
    0xa6
  ],
  [
    0x47,
    0x07,
    0xa7,
    0xfc,
    0xf3,
    0x73,
    0x17,
    0xba,
    0x83,
    0x59,
    0x3c,
    0x19,
    0xe6,
    0x85,
    0x4f,
    0xa8
  ],
  [
    0x68,
    0x6b,
    0x81,
    0xb2,
    0x71,
    0x64,
    0xda,
    0x8b,
    0xf8,
    0xeb,
    0x0f,
    0x4b,
    0x70,
    0x56,
    0x9d,
    0x35
  ],
  [
    0x1e,
    0x24,
    0x0e,
    0x5e,
    0x63,
    0x58,
    0xd1,
    0xa2,
    0x25,
    0x22,
    0x7c,
    0x3b,
    0x01,
    0x21,
    0x78,
    0x87
  ],
  [
    0xd4,
    0x00,
    0x46,
    0x57,
    0x9f,
    0xd3,
    0x27,
    0x52,
    0x4c,
    0x36,
    0x02,
    0xe7,
    0xa0,
    0xc4,
    0xc8,
    0x9e
  ],
  [
    0xea,
    0xbf,
    0x8a,
    0xd2,
    0x40,
    0xc7,
    0x38,
    0xb5,
    0xa3,
    0xf7,
    0xf2,
    0xce,
    0xf9,
    0x61,
    0x15,
    0xa1
  ],
  [
    0xe0,
    0xae,
    0x5d,
    0xa4,
    0x9b,
    0x34,
    0x1a,
    0x55,
    0xad,
    0x93,
    0x32,
    0x30,
    0xf5,
    0x8c,
    0xb1,
    0xe3
  ],
  [
    0x1d,
    0xf6,
    0xe2,
    0x2e,
    0x82,
    0x66,
    0xca,
    0x60,
    0xc0,
    0x29,
    0x23,
    0xab,
    0x0d,
    0x53,
    0x4e,
    0x6f
  ],
  [
    0xd5,
    0xdb,
    0x37,
    0x45,
    0xde,
    0xfd,
    0x8e,
    0x2f,
    0x03,
    0xff,
    0x6a,
    0x72,
    0x6d,
    0x6c,
    0x5b,
    0x51
  ],
  [
    0x8d,
    0x1b,
    0xaf,
    0x92,
    0xbb,
    0xdd,
    0xbc,
    0x7f,
    0x11,
    0xd9,
    0x5c,
    0x41,
    0x1f,
    0x10,
    0x5a,
    0xd8
  ],
  [
    0x0a,
    0xc1,
    0x31,
    0x88,
    0xa5,
    0xcd,
    0x7b,
    0xbd,
    0x2d,
    0x74,
    0xd0,
    0x12,
    0xb8,
    0xe5,
    0xb4,
    0xb0
  ],
  [
    0x89,
    0x69,
    0x97,
    0x4a,
    0x0c,
    0x96,
    0x77,
    0x7e,
    0x65,
    0xb9,
    0xf1,
    0x09,
    0xc5,
    0x6e,
    0xc6,
    0x84
  ],
  [
    0x18,
    0xf0,
    0x7d,
    0xec,
    0x3a,
    0xdc,
    0x4d,
    0x20,
    0x79,
    0xee,
    0x5f,
    0x3e,
    0xd7,
    0xcb,
    0x39,
    0x48
  ]
]

/**
 * 密钥扩展算法
 * - FK: 系统参数
 * - CK: 固定参数
 */
const FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
const CK = [
  0x00070e15,
  0x1c232a31,
  0x383f464d,
  0x545b6269,
  0x70777e85,
  0x8c939aa1,
  0xa8afb6bd,
  0xc4cbd2d9,
  0xe0e7eef5,
  0xfc030a11,
  0x181f262d,
  0x343b4249,
  0x50575e65,
  0x6c737a81,
  0x888f969d,
  0xa4abb2b9,
  0xc0c7ced5,
  0xdce3eaf1,
  0xf8ff060d,
  0x141b2229,
  0x30373e45,
  0x4c535a61,
  0x686f767d,
  0x848b9299,
  0xa0a7aeb5,
  0xbcc3cad1,
  0xd8dfe6ed,
  0xf4fb0209,
  0x10171e25,
  0x2c333a41,
  0x484f565d,
  0x646b7279
]

// 分组大小
const BLOCK_SIZE = 16 // 16 bytes
// 十六进制表示的加密密钥和初始化向量 iv
const REG_EXP_KEY = /^[0-9a-f]{32}$/i

// 非线性变换 τ(.)
const Tau = (a) => {
  const b1 = SBOX_TABLE[(a & 0xf0000000) >>> 28][(a & 0x0f000000) >>> 24]
  const b2 = SBOX_TABLE[(a & 0x00f00000) >>> 20][(a & 0x000f0000) >>> 16]
  const b3 = SBOX_TABLE[(a & 0x0000f000) >>> 12][(a & 0x00000f00) >>> 8]
  const b4 = SBOX_TABLE[(a & 0x000000f0) >>> 4][(a & 0x0000000f) >>> 0]
  return (b1 << 24) | (b2 << 16) | (b3 << 8) | (b4 << 0)
}

// 线性变换 L(B) = B xor (B <<< 2) xor (B <<< 10) xor (B <<< 18) xor (B <<< 24)
const L = (B) =>
  B ^ leftShift(B, 2) ^ leftShift(B, 10) ^ leftShift(B, 18) ^ leftShift(B, 24)

// 合成置换 T(A) = L(τ(A))
const T = (A) => L(Tau(A))

// 线性变换 L'(B) = B xor (B <<< 13) xor (B <<< 23)
const Li = (B) => B ^ leftShift(B, 13) ^ leftShift(B, 23)

// 合成置换 T'(A) = L'(τ(A))
const Ti = (A) => Li(Tau(A))

// 密钥扩展算法
const extendKeys = (MK) => {
  const K = new Array(36)
  K[0] = MK[0] ^ FK[0]
  K[1] = MK[1] ^ FK[1]
  K[2] = MK[2] ^ FK[2]
  K[3] = MK[3] ^ FK[3]

  const rk = new Array(32)
  for (let i = 0; i < 32; i++) {
    K[i + 4] = K[i] ^ Ti(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i])
    rk[i] = K[i + 4]
  }

  return rk
}

// 分组加密
const encryptBlock = (X, MK) => {
  const rk = extendKeys(MK)

  for (let i = 0; i < 32; i++) {
    X[i + 4] = X[i] ^ T(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i])
  }

  return [X[35], X[34], X[33], X[32]]
}

// 分组解密
const decryptBlock = (X, MK) => {
  const rk = extendKeys(MK).reverse()

  for (let i = 0; i < 32; i++) {
    X[i + 4] = X[i] ^ T(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i])
  }

  return [X[35], X[34], X[33], X[32]]
}

// 填充
const padding = (data, paddingType) => {
  // 判断 paddingType，默认是 pkcs#7 （传 pkcs#5 也会走 pkcs#7 填充）, 'zero' ｜ 'none' | 'null' 填充 0
  if (paddingType === 'zero' || paddingType === 'none' || paddingType === 'null') {
    const paddingSize = BLOCK_SIZE - (data.length % BLOCK_SIZE)
    const paddingBuff = Buffer.alloc(paddingSize, 0)
    return Buffer.concat([data, paddingBuff], data.length + paddingSize)
  } else if (paddingType === 'pkcs#7' || paddingType === 'pkcs#5') {
    return pkcs7Padding(data)
  }
}

// 分组填充 https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7
const pkcs7Padding = (data) => {
  const paddingSize = BLOCK_SIZE - (data.length % BLOCK_SIZE)
  const paddingBuff = Buffer.alloc(paddingSize, paddingSize)
  return Buffer.concat([data, paddingBuff], data.length + paddingSize)
}

// Block Buffer => Int32 Array
const toInt32Array = (block) => [
  block.readInt32BE(0),
  block.readInt32BE(4),
  block.readInt32BE(8),
  block.readInt32BE(12)
]

//  Int32 Array => Block Buffer
const toCipcherBlock = (array) => {
  const block = Buffer.alloc(16)
  for (let i = 0; i < 4; i++) {
    block.writeInt32BE(array[i], i * 4)
  }
  return block
}

const _encrypt = (data, key, iv, paddingType, outputEncoding) => {
  // 初始化向量转换
  iv && (iv = toInt32Array(iv))
  // 密钥转换
  key = toInt32Array(key)
  // 分组填充
  data = padding(data, paddingType)

  // 分组加密结果
  const blocks = []
  // 分组数(每组 16 字节)
  const num = data.length / BLOCK_SIZE

  for (let i = 0; i < num; i++) {
    if (iv) {
      const offset = i * BLOCK_SIZE
      const plainBlock = [
        iv[0] ^ data.readInt32BE(offset),
        iv[1] ^ data.readInt32BE(offset + 4),
        iv[2] ^ data.readInt32BE(offset + 8),
        iv[3] ^ data.readInt32BE(offset + 12)
      ]
      const cipherBlock = encryptBlock(plainBlock, key)
      blocks.push(toCipcherBlock(cipherBlock))
      iv = cipherBlock.slice(0) // 将本次密文作为下一次加密的 iv
    } else {
      const offset = i * BLOCK_SIZE
      const plainBlock = [
        data.readInt32BE(offset),
        data.readInt32BE(offset + 4),
        data.readInt32BE(offset + 8),
        data.readInt32BE(offset + 12)
      ]
      const cipherBlock = encryptBlock(plainBlock, key)
      blocks.push(toCipcherBlock(cipherBlock))
    }
  }

  const buff = Buffer.concat(blocks, data.length)
  return outputEncoding ? buff.toString(outputEncoding) : toArrayBuffer(buff)
}

const _decrypt = (data, key, iv, outputEncoding) => {
  // 初始化向量转换
  iv && (iv = toInt32Array(iv))
  // 密钥转换
  key = toInt32Array(key)

  // 分组解密结果
  const blocks = []
  // 按每组 16 字节分组后得到的总分组数
  const num = data.length / BLOCK_SIZE

  if (iv) {
    for (let i = num - 1; i >= 0; i--) {
      const offset = i * BLOCK_SIZE

      let vector
      if (i > 0) {
        vector = [
          data.readInt32BE(offset - BLOCK_SIZE),
          data.readInt32BE(offset - BLOCK_SIZE + 4),
          data.readInt32BE(offset - BLOCK_SIZE + 8),
          data.readInt32BE(offset - BLOCK_SIZE + 12)
        ]
      } else {
        vector = iv
      }

      const cipherBlock = [
        data.readInt32BE(offset),
        data.readInt32BE(offset + 4),
        data.readInt32BE(offset + 8),
        data.readInt32BE(offset + 12)
      ]
      const [b0, b1, b2, b3] = decryptBlock(cipherBlock, key)
      const plainBlock = [
        b0 ^ vector[0],
        b1 ^ vector[1],
        b2 ^ vector[2],
        b3 ^ vector[3]
      ]

      blocks.unshift(toCipcherBlock(plainBlock))
    }
  } else {
    for (let i = 0; i < num; i++) {
      const offset = i * BLOCK_SIZE
      const cipherBlock = [
        data.readInt32BE(offset),
        data.readInt32BE(offset + 4),
        data.readInt32BE(offset + 8),
        data.readInt32BE(offset + 12)
      ]
      const plainBlock = decryptBlock(cipherBlock, key)
      blocks.push(toCipcherBlock(plainBlock))
    }
  }

  // 移除分组填充
  const buff = Buffer.concat(
    blocks,
    data.length - blocks[blocks.length - 1][BLOCK_SIZE - 1]
  )
  return outputEncoding ? buff.toString(outputEncoding) : toArrayBuffer(buff)
}

export const encrypt = (data, key, options) => {
  let { mode, iv, paddingType = 'pkcs#7', inputEncoding, outputEncoding } = options || {}

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

  return _encrypt(data, key, iv, paddingType, outputEncoding)
}

export const decrypt = (data, key, options) => {
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

  return _decrypt(data, key, iv, outputEncoding)
}
