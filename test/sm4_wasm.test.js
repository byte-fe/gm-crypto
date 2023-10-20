const test = require('ava')
const toArrayBuffer = require('to-arraybuffer')
const { SM4_WASM, SM4 } = require('../dist/')

const { ECB, CBC } = SM4_WASM.constants

const key = '0123456789abcdeffedcba9876543210'
const iv = '0123456789abcdeffedcba9876543210'

// Plain message
const data = '无线局域网产品使用的 SMS4 密码算法'

// Expected values
const ecb_expected = Buffer.from(
  'BufAF2TAkzvYB8+zEtMPpOB3zY/FU9h3gwvuQd19gI14VTLV4KWh5Oi5MDznV4A6ACqKTvqGPMrQJKwDALtA0g==',
  'base64'
)
const cbc_expected = Buffer.from(
  'pQYnXOwYouPXvCgJhaWDJsmPv146JNT6OE/Fiz7iO/ZF0blARNa1lUxWoJuJ3ewlSh1wi6lKXc9eIuYr7ZADqA==',
  'base64'
)

test('Validate type of iv', async (t) => {
  t.plan(16)

  // Number
  await t.throwsAsync(
    async () => {
      await SM4_WASM.encrypt(data, key, {
        mode: CBC,
        iv: 123,
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM4_WASM.decrypt(data, key, {
        mode: CBC,
        iv: 123,
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Array
  await t.throwsAsync(
    async () => {
      await SM4_WASM.encrypt(data, key, {
        mode: CBC,
        iv: [1, 2, 3],
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM4_WASM.decrypt(data, key, {
        mode: CBC,
        iv: [1, 2, 3],
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Falsy values
  await t.throwsAsync(
    async () => {
      await SM4_WASM.encrypt(data, key, {
        mode: CBC,
        iv: undefined,
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM4_WASM.encrypt(data, key, {
        mode: CBC,
        iv: null,
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM4_WASM.encrypt(data, key, {
        mode: CBC,
        iv: NaN,
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM4_WASM.decrypt(data, key, {
        mode: CBC,
        iv: undefined,
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM4_WASM.decrypt(data, key, {
        mode: CBC,
        iv: null,
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM4_WASM.decrypt(data, key, {
        mode: CBC,
        iv: NaN,
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Invalid hexadecimal string
  await t.throwsAsync(
    async () => {
      await SM4_WASM.encrypt(data, key, {
        mode: CBC,
        iv: iv.slice(5),
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  await t.throwsAsync(
    async () => {
      await SM4_WASM.encrypt(data, key, {
        mode: CBC,
        iv: iv.repeat(5),
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM4_WASM.encrypt(data, key, {
        mode: CBC,
        iv: iv + 'xxx',
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM4_WASM.decrypt(data, key, {
        mode: CBC,
        iv: iv.slice(5),
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM4_WASM.decrypt(data, key, {
        mode: CBC,
        iv: iv.repeat(5),
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  await t.throwsAsync(
    async () => {
      await SM4_WASM.decrypt(data, key, {
        mode: CBC,
        iv: iv + 'xxx',
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
})

test('Validate type of cipher key', async (t) => {
  t.plan(16)

  // Number
  await t.throwsAsync(
    async () => {
      await SM4_WASM.encrypt(data, 123, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM4_WASM.decrypt(data, 123, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Array
  await t.throwsAsync(
    async () => {
      await SM4_WASM.encrypt(data, [1, 2, 3], {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM4_WASM.decrypt(data, [1, 2, 3], {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Falsy values
  await t.throwsAsync(
    async () => {
      await SM4_WASM.encrypt(data, undefined, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM4_WASM.encrypt(data, null, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM4_WASM.encrypt(data, NaN, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM4_WASM.decrypt(data, undefined, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM4_WASM.decrypt(data, null, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM4_WASM.decrypt(data, NaN, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Invalid hexadecimal string
  await t.throwsAsync(
    async () => {
      await SM4_WASM.encrypt(data, key.slice(5), {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM4_WASM.encrypt(data, key.repeat(5), {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM4_WASM.encrypt(data, key + 'xxx', {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM4_WASM.decrypt(data, key.slice(5), {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM4_WASM.decrypt(data, key.repeat(5), {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM4_WASM.decrypt(data, key + 'xxx', {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
})

test('Validate type of plain data', async (t) => {
  t.plan(5)

  // Number
  await t.throwsAsync(
    async () => {
      await SM4_WASM.encrypt(123, key, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Array
  await t.throwsAsync(
    async () => {
      await SM4_WASM.encrypt([1, 2, 3], key, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Falsy values
  await t.throwsAsync(
    async () => {
      await SM4_WASM.encrypt(undefined, key, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM4_WASM.encrypt(null, key, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM4_WASM.encrypt(NaN, key, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
})

test('Validate type of cipher data', async (t) => {
  t.plan(5)

  // Number
  await t.throwsAsync(
    async () => {
      await SM4_WASM.decrypt(123, key, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Array
  await t.throwsAsync(
    async () => {
      await SM4_WASM.decrypt([1, 2, 3], key, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Falsy values
  await t.throwsAsync(
    async () => {
      await SM4_WASM.decrypt(undefined, key, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM4_WASM.decrypt(null, key, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  await t.throwsAsync(
    async () => {
      await SM4_WASM.decrypt(NaN, key, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
})

test('ECB', async (t) => {
  t.plan(8)

  let cipherData, plainData

  // Official example
  t.is(
    (
      await SM4_WASM.encrypt(
        '0123456789abcdeffedcba9876543210',
        '0123456789abcdeffedcba9876543210',
        {
          inputEncoding: 'hex',
          outputEncoding: 'hex'
        }
      )
    ).substring(0, 32),
    '681edf34d206965e86b3e94f536e4246'
  )

  // hex
  cipherData = await SM4_WASM.encrypt(data, key, {
    outputEncoding: 'hex'
  })
  plainData = await SM4_WASM.decrypt(cipherData, key, {
    inputEncoding: 'hex',
    outputEncoding: 'utf8'
  })
  t.is(cipherData, ecb_expected.toString('hex'))
  t.is(plainData, data)

  // base64
  cipherData = await SM4_WASM.encrypt(data, key, {
    outputEncoding: 'base64'
  })
  plainData = await SM4_WASM.decrypt(cipherData, key, {
    inputEncoding: 'base64',
    outputEncoding: 'utf8'
  })
  t.is(cipherData, ecb_expected.toString('base64'))
  t.is(plainData, data)

  // ArrayBuffer
  cipherData = await SM4_WASM.encrypt(
    toArrayBuffer(Buffer.from(data, 'utf8')),
    key
  )
  plainData = await SM4_WASM.decrypt(cipherData, key)
  t.true(cipherData instanceof ArrayBuffer)
  t.true(plainData instanceof ArrayBuffer)
  t.is(Buffer.from(plainData).toString('utf8'), data)
})

test('CBC', async (t) => {
  t.plan(7)

  let cipherData, plainData

  // hex
  cipherData = await SM4_WASM.encrypt(data, key, {
    mode: CBC,
    iv,
    outputEncoding: 'hex'
  })
  plainData = await SM4_WASM.decrypt(cipherData, key, {
    mode: CBC,
    iv,
    inputEncoding: 'hex',
    outputEncoding: 'utf8'
  })
  t.is(cipherData, cbc_expected.toString('hex'))
  t.is(plainData, data)

  // base64
  cipherData = await SM4_WASM.encrypt(data, key, {
    mode: CBC,
    iv,
    outputEncoding: 'base64'
  })
  plainData = await SM4_WASM.decrypt(cipherData, key, {
    mode: CBC,
    iv,
    inputEncoding: 'base64',
    outputEncoding: 'utf8'
  })
  t.is(cipherData, cbc_expected.toString('base64'))
  t.is(plainData, data)

  // ArrayBuffer
  cipherData = await SM4_WASM.encrypt(data, key, {
    mode: CBC,
    iv
  })
  plainData = await SM4_WASM.decrypt(cipherData, key, {
    mode: CBC,
    iv,
    outputEncoding: 'utf8'
  })
  t.true(cipherData instanceof ArrayBuffer)
  t.is(plainData, data)
  plainData = await SM4_WASM.decrypt(cipherData, key, {
    mode: CBC,
    iv
  })
  t.true(plainData instanceof ArrayBuffer)
})
