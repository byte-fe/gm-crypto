/* eslint-disable no-use-before-define */
const { Buffer } = require('buffer') // 支持 Node.js & Browser
const { BigInteger, SecureRandom } = require('jsbn')
const toArrayBuffer = require('to-arraybuffer')

const { ECCurveFp } = require('./ec')
const { C1C2C3, C1C3C2, PC } = require('./const')
const { leftPad } = require('../utils')
const SM3 = require('../sm3')

const rng = new SecureRandom()
const { curve, G, n } = (() => {
  // p: 大于 3 的素数
  const p = new BigInteger(
    'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
    16
  )
  // a，b: Fq 中的元素，它们定义 Fq 上的一条椭圆曲线 E
  const a = new BigInteger(
    'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
    16
  )
  const b = new BigInteger(
    '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
    16
  )
  const curve = new ECCurveFp(p, a, b)

  // 椭圆曲线的一个基点，其阶为素数
  const gxHex =
    '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7'
  const gyHex =
    'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0'
  const G = curve.decodePointHex(PC + gxHex + gyHex)

  // 基点 G 的阶
  const n = new BigInteger(
    'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
    16
  )

  return { curve, G, n }
})()

/**
 * 生成密钥对
 * a) 用随机数发生器产生整数 d ∈ [1,n−2]
 * b) G 为基点，计算点 P = (xP,yP) = [d]G
 * c) 密钥对是 (d,P)，其中 d 为私钥，P 为公钥
 */
const generateKeyPair = () => {
  // a) 用随机数发生器产生整数 d ∈ [1,n−2]
  const d = new BigInteger(n.bitLength(), rng)
    .mod(n.subtract(new BigInteger('2')))
    .add(BigInteger.ONE)

  const privateKey = leftPad(d.toString(16), 64)

  // b) G 为基点，计算点 P = (xP,yP) = [d]G
  const P = G.multiply(d)
  const Px = leftPad(P.getX().toBigInteger().toString(16), 64)
  const Py = leftPad(P.getY().toBigInteger().toString(16), 64)
  const publicKey = PC + Px + Py

  // 密钥对是 (d,P)，其中 d 为私钥，P 为公钥
  return { privateKey, publicKey }
}

/**
 * 密钥派生函数
 * a) 初始化一个 32 比特构成的计数器 ct=0x00000001
 * b) 对 i 从 1 到 ⌈klen/v⌉ 执行
 *   b.1) 计算 Hai=Hv(Z ∥ ct)
 *   b.2) ct++；
 * c) 若 klen/v 是整数，令 Ha!⌈klen/v⌉ = Ha⌈klen/v⌉，否则令 Ha!⌈klen/v⌉ 为 Ha⌈klen/v⌉ 最左边的 (klen − (v × ⌊klen/v⌋)) 比特
 * d) 令K = Ha1||Ha2|| · · · ||Ha⌈klen/v⌉−1||Ha!⌈klen/v⌉
 */
function KDF(Z, klen) {
  const list = []
  const times = Math.ceil(klen / 32)
  const mod = klen % 32

  for (let i = 1; i <= times; i++) {
    const ct = Buffer.allocUnsafe(4)
    ct.writeUInt32BE(i)

    const hash = SM3.digest(Buffer.concat([Z, ct]))
    // Fix: 浏览器端 Buffer.concat 实现有问题，处理不了 list 总长度超过 klen 的情况
    list.push(
      i === times && mod ? Buffer.from(hash).slice(0, mod) : Buffer.from(hash)
    )
  }

  return Buffer.concat(list, klen)
}

/**
 * 设需要发送的消息为比特串 M，klen 为 M 的比特长度。
 * 为了对明文 M 进行加密，作为加密者的用户 A 应实现以下运算步骤：
 *   A1：用随机数发生器产生随机数 k∈[1,n-1]
 *   A2：计算椭圆曲线点 C1=[k]G=(x1,y1)
 *   A3：计算椭圆曲线点 S=[h]PB，若 S 是无穷远点，则报错并退出
 *   A4：计算椭圆曲线点 [k]PB=(x2,y2)
 *   A5：计算 t=KDF(x2 ∥ y2, klen)，若 t 为全 0 比特串，则返回 A1
 *   A6：计算 C2 = M ⊕ t；
 *   A7：计算 C3 = Hash(x2 ∥ M ∥ y2)；
 *   A8：输出密文 C = C1 ∥ C2 ∥ C3 or C1 ∥ C3 ∥ C2
 */
function encrypt(data, publicKey, options) {
  const { mode = C1C3C2, inputEncoding, outputEncoding } = options || {}

  // 明文消息类型校验 `string` | `ArrayBuffer` | `Buffer`
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

  // 随机数 k∈[1,n-1]
  const k = new BigInteger(n.bitLength(), rng)
    .mod(n.subtract(BigInteger.ONE))
    .add(BigInteger.ONE)

  // C1 = [k]G = (x1,y1)
  const point1 = G.multiply(k)
  const x1 = leftPad(point1.getX().toBigInteger().toString(16), 64)
  const y1 = leftPad(point1.getY().toBigInteger().toString(16), 64)
  const C1 = x1 + y1

  // TODO: 计算椭圆曲线点 S=[h]PB，若 S 是无穷远点，则报错并退出

  // [k]PB = (x2,y2)
  const point2 = curve.decodePointHex(publicKey).multiply(k)
  const x2 = leftPad(point2.getX().toBigInteger().toString(16), 64)
  const y2 = leftPad(point2.getY().toBigInteger().toString(16), 64)

  // t = KDF(x2 ∥ y2, klen)，若 t 为全 0 比特串，则返回 A1
  const t = KDF(Buffer.from(x2 + y2, 'hex'), data.length)

  // C2 = M ⊕ t
  const C2 = leftPad(
    new BigInteger(data.toString('hex'), 16)
      .xor(new BigInteger(t.toString('hex'), 16))
      .toString(16),
    data.length * 2
  )

  // C3 = Hash(x2 ∥ M ∥ y2)
  const C3 = SM3.digest(x2 + data.toString('hex') + y2, 'hex', 'hex')

  const buff = Buffer.from(mode === C1C2C3 ? C1 + C2 + C3 : C1 + C3 + C2, 'hex')
  return outputEncoding ? buff.toString(outputEncoding) : toArrayBuffer(buff)
}

/**
 * 设 klen 为密文中 C2 的比特长度
 * 为了对密文 C= C1 ∥ C2 ∥ C3 进行解密，作为解密者的用户B应实现以下运算步骤：
 * B1：从 C 中取出比特串 C1，转换为椭圆曲线上的点
 * B2：计算椭圆曲线点 S=[h]C1，若 S 是无穷远点，则报错并退出；
 * B3：计算 [dB]C1=(x2,y2)，将坐标 x2、y2 的数据类型转换为比特串；
 * B4：计算 t=KDF(x2 ∥ y2, klen)，若 t 为全 0 比特串，则报错并退出；
 * B5：从 C 中取出比特串 C2，计算 M′ = C2 ⊕ t；
 * B6：计算 u = Hash(x2 ∥ M′ ∥ y2)，从 C 中取出比特串 C3，若u ̸= C3，则报错并退出；
 * B7：输出明文M′
 */
function decrypt(data, privateKey, options) {
  const { mode = C1C3C2, inputEncoding, outputEncoding } = options || {}

  // 密文数据类型校验 `string` | `ArrayBuffer` | `Buffer`
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

  const unit = 32

  // 从 C 中取出比特串 C1，转换为椭圆曲线上的点
  const x1 = data.slice(0, unit).toString('hex')
  const y1 = data.slice(unit, 2 * unit).toString('hex')
  const point1 = curve.decodePointHex(PC + x1 + y1)

  // TODO: 计算椭圆曲线点 S=[h]C1，若 S 是无穷远点，则报错并退出；

  // [dB]C1 = (x2,y2)
  const point2 = point1.multiply(new BigInteger(privateKey, 16))
  const x2 = leftPad(point2.getX().toBigInteger().toString(16), 64)
  const y2 = leftPad(point2.getY().toBigInteger().toString(16), 64)

  // 根据拼接模式拆分数据 C2, C3
  let C3 = data.slice(2 * unit, 3 * unit)
  let C2 = data.slice(3 * unit)

  if (mode === C1C2C3) {
    C3 = data.slice(data.length - unit)
    C2 = data.slice(2 * unit, data.length - unit)
  }

  // t = KDF(x2 ∥ y2, klen)，若 t 为全 0 比特串，则返回 A1
  const t = KDF(Buffer.from(x2 + y2, 'hex'), C2.length)

  // M′ = C2 ⊕ t
  const M = new BigInteger(C2.toString('hex'), 16)
    .xor(new BigInteger(t.toString('hex'), 16))
    .toString(16)

  // 计算 u = Hash(x2 ∥ M′ ∥ y2)
  const u = SM3.digest(x2 + M + y2, 'hex', 'hex')

  // 合法性校验
  const verified = u === C3.toString('hex')

  const buff = verified ? Buffer.from(M, 'hex') : Buffer.alloc(0)
  return outputEncoding ? buff.toString(outputEncoding) : toArrayBuffer(buff)
}

module.exports = {
  constants: {
    C1C2C3,
    C1C3C2
  },
  generateKeyPair,
  encrypt,
  decrypt
}
