const test = require('ava')
const toArrayBuffer = require('to-arraybuffer')
const { SM2 } = require('../')
const { C1C2C3, C1C3C2 } = SM2.constants

const { publicKey, privateKey } = SM2.generateKeyPair()
const data = 'SM2 椭圆曲线公钥密码算法'

test('Generates a key pair', (t) => {
  t.plan(2)

  t.is(Buffer.from(privateKey, 'hex').length, 32)
  t.is(Buffer.from(publicKey, 'hex').length, 65)
})

test('C1C3C2', (t) => {
  t.plan(3)

  let cipherData, plainData

  // hex
  cipherData = SM2.encrypt(data, publicKey, {
    inputEncoding: 'utf8',
    outputEncoding: 'hex'
  })
  plainData = SM2.decrypt(cipherData, privateKey, {
    inputEncoding: 'hex',
    outputEncoding: 'utf8'
  })
  t.is(plainData, data)

  // base64
  cipherData = SM2.encrypt(data, publicKey, {
    inputEncoding: 'utf8',
    outputEncoding: 'base64'
  })
  plainData = SM2.decrypt(cipherData, privateKey, {
    inputEncoding: 'base64',
    outputEncoding: 'utf8'
  })
  t.is(plainData, data)

  // ArrayBuffer
  cipherData = SM2.encrypt(data, publicKey, {
    inputEncoding: 'utf8'
  })
  plainData = SM2.decrypt(cipherData, privateKey, {
    outputEncoding: 'utf8'
  })
  t.is(plainData, data)
})

test('C1C2C3', (t) => {
  t.plan(3)

  let cipherData, plainData

  // hex
  cipherData = SM2.encrypt(data, publicKey, {
    mode: C1C2C3,
    inputEncoding: 'utf8',
    outputEncoding: 'hex'
  })
  plainData = SM2.decrypt(cipherData, privateKey, {
    mode: C1C2C3,
    inputEncoding: 'hex',
    outputEncoding: 'utf8'
  })
  t.is(plainData, data)

  // base64
  cipherData = SM2.encrypt(data, publicKey, {
    mode: C1C2C3,
    inputEncoding: 'utf8',
    outputEncoding: 'base64'
  })
  plainData = SM2.decrypt(cipherData, privateKey, {
    mode: C1C2C3,
    inputEncoding: 'base64',
    outputEncoding: 'utf8'
  })
  t.is(plainData, data)

  // ArrayBuffer
  cipherData = SM2.encrypt(data, publicKey, {
    mode: C1C2C3,
    inputEncoding: 'utf8'
  })
  plainData = SM2.decrypt(cipherData, privateKey, {
    mode: C1C2C3,
    outputEncoding: 'utf8'
  })
  t.is(plainData, data)
})

test('Boundary conditions', (t) => {
  t.plan(3)

  let cipherData, plainData

  // No options
  cipherData = SM2.encrypt(data, publicKey)
  plainData = SM2.decrypt(cipherData, privateKey)
  t.is(Buffer.from(plainData).toString('utf8'), data)

  // ArrayBuffer
  cipherData = SM2.encrypt(toArrayBuffer(Buffer.from(data)), publicKey)
  plainData = SM2.decrypt(Buffer.from(cipherData), privateKey, {
    inputEncoding: 'hex',
    outputEncoding: 'utf8'
  })
  t.is(plainData, data)

  // Invalid value of `C3`
  cipherData = SM2.encrypt(toArrayBuffer(Buffer.from(data)), publicKey)
  cipherData = Buffer.from(cipherData)
  const c3FirstByte = cipherData[64]
  cipherData.writeUInt8(c3FirstByte > 0 ? c3FirstByte - 1 : 1, 64)
  plainData = SM2.decrypt(cipherData, privateKey)
  t.is(plainData.byteLength, 0)
})

test('Validate type of cipher data', (t) => {
  t.plan(6)

  // Number
  t.throws(
    () => {
      SM2.decrypt(123, privateKey, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Array
  t.throws(
    () => {
      SM2.decrypt([1, 2, 3], privateKey, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Object
  t.throws(
    () => {
      SM2.decrypt({ a: 123 }, privateKey, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Falsy values
  t.throws(
    () => {
      SM2.decrypt(null, privateKey, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM2.decrypt(undefined, privateKey, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM2.decrypt(NaN, privateKey, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
})

test('Validate type of plain data', (t) => {
  t.plan(6)

  // Number
  t.throws(
    () => {
      SM2.encrypt(123, publicKey, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Array
  t.throws(
    () => {
      SM2.encrypt([1, 2, 3], publicKey, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Object
  t.throws(
    () => {
      SM2.encrypt({ a: 123 }, publicKey, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Falsy values
  t.throws(
    () => {
      SM2.encrypt(null, publicKey, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM2.encrypt(undefined, publicKey, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM2.encrypt(NaN, publicKey, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
})
