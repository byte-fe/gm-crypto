const test = require('ava')
const { SM2_WASM, SM2 } = require('../dist')
const toArrayBuffer = require('to-arraybuffer')
const { C1C2C3, C1C3C2 } = SM2_WASM.constants
const data = 'SM2 椭圆曲线公钥密码算法'

test('Generates a key pair', async (t) => {
  t.plan(2)

  const { publicKey, privateKey } = await SM2_WASM.generateKeyPair()

  t.is(Buffer.from(privateKey, 'hex').length, 32)
  t.is(Buffer.from(publicKey, 'hex').length, 65)
})

test('C1C3C2', async (t) => {
  t.plan(3)

  let cipherData, plainData

  const { publicKey, privateKey } = await SM2_WASM.generateKeyPair()
  // hex
  cipherData = await SM2_WASM.encrypt(data, publicKey, {
    inputEncoding: 'utf8',
    outputEncoding: 'hex'
  })
  plainData = await SM2_WASM.decrypt(cipherData, privateKey, {
    inputEncoding: 'hex',
    outputEncoding: 'utf8'
  })
  t.is(plainData, data)

  // base64
  cipherData = await SM2_WASM.encrypt(data, publicKey, {
    inputEncoding: 'utf8',
    outputEncoding: 'base64'
  })
  plainData = await SM2_WASM.decrypt(cipherData, privateKey, {
    inputEncoding: 'base64',
    outputEncoding: 'utf8'
  })
  t.is(plainData, data)

  // ArrayBuffer
  cipherData = await SM2_WASM.encrypt(data, publicKey, {
    inputEncoding: 'utf8'
  })
  plainData = await SM2_WASM.decrypt(cipherData, privateKey, {
    outputEncoding: 'utf8'
  })
  t.is(plainData, data)
})

test('C1C2C3', async (t) => {
  t.plan(3)

  let cipherData, plainData
  const { publicKey, privateKey } = await SM2_WASM.generateKeyPair()

  // hex
  cipherData = await SM2_WASM.encrypt(data, publicKey, {
    mode: C1C2C3,
    inputEncoding: 'utf8',
    outputEncoding: 'hex'
  })
  plainData = await SM2_WASM.decrypt(cipherData, privateKey, {
    mode: C1C2C3,
    inputEncoding: 'hex',
    outputEncoding: 'utf8'
  })
  t.is(plainData, data)

  // base64
  cipherData = await SM2_WASM.encrypt(data, publicKey, {
    mode: C1C2C3,
    inputEncoding: 'utf8',
    outputEncoding: 'base64'
  })
  plainData = await SM2_WASM.decrypt(cipherData, privateKey, {
    mode: C1C2C3,
    inputEncoding: 'base64',
    outputEncoding: 'utf8'
  })
  t.is(plainData, data)

  // ArrayBuffer
  cipherData = await SM2_WASM.encrypt(data, publicKey, {
    mode: C1C2C3,
    inputEncoding: 'utf8'
  })
  plainData = await SM2_WASM.decrypt(cipherData, privateKey, {
    mode: C1C2C3,
    outputEncoding: 'utf8'
  })
  t.is(plainData, data)
})

test('Boundary conditions', async (t) => {
  t.plan(2)

  let cipherData, plainData
  const { publicKey, privateKey } = await SM2_WASM.generateKeyPair()

  // No options
  cipherData = await SM2_WASM.encrypt(data, publicKey)
  plainData = await SM2_WASM.decrypt(cipherData, privateKey)
  t.is(Buffer.from(plainData).toString('utf8'), data)

  // ArrayBuffer
  cipherData = await SM2_WASM.encrypt(
    toArrayBuffer(Buffer.from(data)),
    publicKey
  )
  plainData = await SM2_WASM.decrypt(Buffer.from(cipherData), privateKey, {
    inputEncoding: 'hex',
    outputEncoding: 'utf8'
  })
  t.is(plainData, data)
})

test('Validate type of cipher data', async (t) => {
  t.plan(6)
  const { publicKey, privateKey } = await SM2_WASM.generateKeyPair()

  // Number
  await t.throwsAsync(
    async () => {
      await SM2_WASM.decrypt(123, privateKey, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Array
  await t.throwsAsync(
    async () => {
      await SM2_WASM.decrypt([1, 2, 3], privateKey, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Object
  await t.throwsAsync(
    async () => {
      await SM2_WASM.decrypt({ a: 123 }, privateKey, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Falsy values
  await t.throwsAsync(
    async () => {
      await SM2_WASM.decrypt(null, privateKey, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM2_WASM.decrypt(undefined, privateKey, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM2_WASM.decrypt(NaN, privateKey, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
})

test('Validate type of plain data', async (t) => {
  t.plan(6)

  const { publicKey, privateKey } = await SM2_WASM.generateKeyPair()
  // Number
  await t.throwsAsync(
    async () => {
      await SM2_WASM.encrypt(123, publicKey, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Array
  await t.throwsAsync(
    async () => {
      await SM2_WASM.encrypt([1, 2, 3], publicKey, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Object
  await t.throwsAsync(
    async () => {
      await SM2_WASM.encrypt({ a: 123 }, publicKey, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Falsy values
  await t.throwsAsync(
    async () => {
      await SM2_WASM.encrypt(null, publicKey, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM2_WASM.encrypt(undefined, publicKey, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM2_WASM.encrypt(NaN, publicKey, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
})

test('C1 with PC', async (t) => {
  //   t.plan(2)

  let cipherData, plainData
  const { publicKey, privateKey } = await SM2_WASM.generateKeyPair(false)

  // hex
  cipherData = await SM2_WASM.encrypt(data, publicKey, {
    inputEncoding: 'utf8',
    outputEncoding: 'hex'
  })

  plainData = await SM2_WASM.decrypt(cipherData, privateKey, {
    inputEncoding: 'hex',
    outputEncoding: 'utf8',
    pc: 1
  })
  t.is(plainData, data)

  // base64
  cipherData = await SM2_WASM.encrypt(data, publicKey, {
    inputEncoding: 'utf8',
    outputEncoding: 'hex',
    pc: 1
  })
  plainData = await SM2_WASM.decrypt(cipherData.substr(2), privateKey, {
    inputEncoding: 'hex',
    outputEncoding: 'utf8'
  })
  t.is(plainData, data)
})

test('wasm with js', async (t) => {
  t.plan(3)

  let cipherData, plainData
  const { publicKey, privateKey } = SM2.generateKeyPair()

  // hex
  cipherData = await SM2_WASM.encrypt(data, publicKey, {
    inputEncoding: 'utf8',
    outputEncoding: 'hex'
  })

  plainData = await SM2_WASM.decrypt(cipherData, privateKey, {
    inputEncoding: 'hex',
    outputEncoding: 'utf8',
    pc: 1
  })
  t.is(plainData, data)

  // base64
  cipherData = await SM2_WASM.encrypt(data, publicKey, {
    inputEncoding: 'utf8',
    outputEncoding: 'hex',
    pc: 1
  })
  plainData = await SM2_WASM.decrypt(cipherData.substr(2), privateKey, {
    inputEncoding: 'hex',
    outputEncoding: 'utf8'
  })
  t.is(plainData, data)

  // hex
  cipherData = SM2.encrypt(data, publicKey, {
    inputEncoding: 'utf8',
    outputEncoding: 'hex'
  })

  plainData = await SM2_WASM.decrypt(cipherData, privateKey, {
    inputEncoding: 'hex',
    outputEncoding: 'utf8',
    pc: 1
  })
  t.is(plainData, data)
})
