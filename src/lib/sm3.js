import toArrayBuffer from 'to-arraybuffer'
import { Buffer } from 'buffer' // 兼容浏览器环境
import { leftShift } from './utils'

// 官方文档以比特作为操作单位，此处以字节作为操作单位。
const padding = (buf) => {
  // 首字节 0b10000000 填充
  const p1 = Buffer.alloc(1, 0x80)

  // 取值 "0" 的 k 比特填充
  let k = buf.length % 64 // 64 * 8 === 512
  k = k >= 56 ? 64 - (k % 56) - 1 : 56 - k - 1 // 56 * 8 === 448
  const p2 = Buffer.alloc(k, 0)

  // 64 比特(8 字节)的消息长度填充
  const p3 = Buffer.alloc(8)
  const size = buf.length * 8 // 不超过 2^53 -1
  p3.writeUInt32BE(Math.floor(size / 2 ** 32), 0) // 高 32 位
  p3.writeUInt32BE(size % 2 ** 32, 4) // 低 32 位

  return Buffer.concat([buf, p1, p2, p3], buf.length + 1 + k + 8)
}

const T = (j) => (j < 16 ? 0x79cc4519 : 0x7a879d8a)
const FF = (X, Y, Z, j) => (j < 16 ? X ^ Y ^ Z : (X & Y) | (X & Z) | (Y & Z))
const GG = (X, Y, Z, j) => (j < 16 ? X ^ Y ^ Z : (X & Y) | (~X & Z))
const P0 = (X) => X ^ leftShift(X, 9) ^ leftShift(X, 17)
const P1 = (X) => X ^ leftShift(X, 15) ^ leftShift(X, 23)

// 消息扩展(512-bits): 16 个字 => 132 个字
const extendFn = (Bi) => {
  const W = new Array(132)

  // 将消息分组 B(i) 划分为 16 个字 W0, W1, · · · , W15
  Bi.forEach((v, i) => {
    W[i] = v
  })

  /**
    FOR j=16 TO 67
      Wj ← P1(Wj−16 ⊕ Wj−9 ⊕ (Wj−3 ≪ 15)) ⊕ (Wj−13 ≪ 7) ⊕ Wj−6
    ENDFOR
  */
  for (let j = 16; j < 68; j++) {
    W[j] =
      P1(W[j - 16] ^ W[j - 9] ^ leftShift(W[j - 3], 15)) ^
      leftShift(W[j - 13], 7) ^
      W[j - 6]
  }

  /**
    FOR j=0 TO 63
      W′j = Wj ⊕ Wj+4
    ENDFOR
  */
  for (let j = 0; j < 64; j++) {
    W[j + 68] = W[j] ^ W[j + 4]
  }

  return W
}

// 压缩函数
// - Vi => 8  个字(256-bits)
// - Bi => 16 个字(512-bits)
const CF = (Vi, Bi, i) => {
  const W = extendFn(Bi) // 消息扩展, 返回 132 个字

  let [A, B, C, D, E, F, G, H] = Vi
  let SS1, SS2, TT1, TT2

  for (let j = 0; j < 64; j++) {
    SS1 = leftShift(leftShift(A, 12) + E + leftShift(T(j), j), 7)
    SS2 = SS1 ^ leftShift(A, 12)
    TT1 = FF(A, B, C, j) + D + SS2 + W[j + 68]
    TT2 = GG(E, F, G, j) + H + SS1 + W[j]
    D = C
    C = leftShift(B, 9)
    B = A
    A = TT1
    H = G
    G = leftShift(F, 19)
    F = E
    E = P0(TT2)
  }

  return [
    A ^ Vi[0],
    B ^ Vi[1],
    C ^ Vi[2],
    D ^ Vi[3],
    E ^ Vi[4],
    F ^ Vi[5],
    G ^ Vi[6],
    H ^ Vi[7]
  ]
}

export const digest = (data, inputEncoding, outputEncoding) => {
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

  data = padding(data) // 数据填充
  const n = data.length / 64 // 512 比特对应 64 字节

  const B = new Array(n)
  for (let i = 0; i < n; i++) {
    B[i] = new Array(16)
    for (let j = 0; j < 16; j++) {
      const offset = i * 64 + j * 4
      B[i][j] = data.readUInt32BE(offset)
    }
  }

  const V = new Array(n)
  V[0] = [
    0x7380166f,
    0x4914b2b9,
    0x172442d7,
    0xda8a0600,
    0xa96f30bc,
    0x163138aa,
    0xe38dee4d,
    0xb0fb0e4e
  ]

  // 迭代压缩
  for (let i = 0; i < n; i++) {
    V[i + 1] = CF(V[i], B[i], i)
  }

  const hash = Buffer.alloc(32)
  V[n].forEach((i32, j) => hash.writeInt32BE(i32, j * 4))

  return outputEncoding ? hash.toString(outputEncoding) : toArrayBuffer(hash)
}
