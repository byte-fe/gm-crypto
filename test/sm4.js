const test = require('ava')
const toArrayBuffer = require('to-arraybuffer')
const { SM4 } = require('../')

const { ECB, CBC } = SM4.constants

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

test('Validate type of iv', (t) => {
  t.plan(16)

  // Number
  t.throws(
    () => {
      SM4.encrypt(data, key, {
        mode: CBC,
        iv: 123,
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM4.decrypt(data, key, {
        mode: CBC,
        iv: 123,
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Array
  t.throws(
    () => {
      SM4.encrypt(data, key, {
        mode: CBC,
        iv: [1, 2, 3],
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM4.decrypt(data, key, {
        mode: CBC,
        iv: [1, 2, 3],
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Falsy values
  t.throws(
    () => {
      SM4.encrypt(data, key, {
        mode: CBC,
        iv: undefined,
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM4.encrypt(data, key, {
        mode: CBC,
        iv: null,
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM4.encrypt(data, key, {
        mode: CBC,
        iv: NaN,
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM4.decrypt(data, key, {
        mode: CBC,
        iv: undefined,
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM4.decrypt(data, key, {
        mode: CBC,
        iv: null,
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM4.decrypt(data, key, {
        mode: CBC,
        iv: NaN,
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Invalid hexadecimal string
  t.throws(
    () => {
      SM4.encrypt(data, key, {
        mode: CBC,
        iv: iv.slice(5),
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  t.throws(
    () => {
      SM4.encrypt(data, key, {
        mode: CBC,
        iv: iv.repeat(5),
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM4.encrypt(data, key, {
        mode: CBC,
        iv: iv + 'xxx',
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM4.decrypt(data, key, {
        mode: CBC,
        iv: iv.slice(5),
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM4.decrypt(data, key, {
        mode: CBC,
        iv: iv.repeat(5),
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  t.throws(
    () => {
      SM4.decrypt(data, key, {
        mode: CBC,
        iv: iv + 'xxx',
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
})

test('Validate type of cipher key', (t) => {
  t.plan(16)

  // Number
  t.throws(
    () => {
      SM4.encrypt(data, 123, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM4.decrypt(data, 123, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Array
  t.throws(
    () => {
      SM4.encrypt(data, [1, 2, 3], {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM4.decrypt(data, [1, 2, 3], {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Falsy values
  t.throws(
    () => {
      SM4.encrypt(data, undefined, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM4.encrypt(data, null, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM4.encrypt(data, NaN, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM4.decrypt(data, undefined, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM4.decrypt(data, null, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM4.decrypt(data, NaN, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Invalid hexadecimal string
  t.throws(
    () => {
      SM4.encrypt(data, key.slice(5), {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM4.encrypt(data, key.repeat(5), {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM4.encrypt(data, key + 'xxx', {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM4.decrypt(data, key.slice(5), {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM4.decrypt(data, key.repeat(5), {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM4.decrypt(data, key + 'xxx', {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
})

test('Validate type of plain data', (t) => {
  t.plan(5)

  // Number
  t.throws(
    () => {
      SM4.encrypt(123, key, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Array
  t.throws(
    () => {
      SM4.encrypt([1, 2, 3], key, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Falsy values
  t.throws(
    () => {
      SM4.encrypt(undefined, key, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM4.encrypt(null, key, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM4.encrypt(NaN, key, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
})

test('Validate type of cipher data', (t) => {
  t.plan(5)

  // Number
  t.throws(
    () => {
      SM4.decrypt(123, key, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Array
  t.throws(
    () => {
      SM4.decrypt([1, 2, 3], key, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )

  // Falsy values
  t.throws(
    () => {
      SM4.decrypt(undefined, key, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM4.decrypt(null, key, {
        inputEncoding: 'utf8',
        outputEncoding: 'base64'
      })
    },
    { instanceOf: TypeError }
  )
  t.throws(
    () => {
      SM4.decrypt(NaN, key, {
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
    SM4.encrypt(
      '0123456789abcdeffedcba9876543210',
      '0123456789abcdeffedcba9876543210',
      {
        inputEncoding: 'hex',
        outputEncoding: 'hex'
      }
    ).substring(0, 32),
    '681edf34d206965e86b3e94f536e4246'
  )

  // hex
  cipherData = SM4.encrypt(data, key, {
    outputEncoding: 'hex'
  })
  plainData = SM4.decrypt(cipherData, key, {
    inputEncoding: 'hex',
    outputEncoding: 'utf8'
  })
  t.is(cipherData, ecb_expected.toString('hex'))
  t.is(plainData, data)

  // base64
  cipherData = SM4.encrypt(data, key, {
    outputEncoding: 'base64'
  })
  plainData = SM4.decrypt(cipherData, key, {
    inputEncoding: 'base64',
    outputEncoding: 'utf8'
  })
  t.is(cipherData, ecb_expected.toString('base64'))
  t.is(plainData, data)

  // ArrayBuffer
  cipherData = SM4.encrypt(toArrayBuffer(Buffer.from(data, 'utf8')), key)
  plainData = SM4.decrypt(cipherData, key)
  t.true(cipherData instanceof ArrayBuffer)
  t.true(plainData instanceof ArrayBuffer)
  t.is(Buffer.from(plainData).toString('utf8'), data)
})

test('CBC', async (t) => {
  t.plan(7)

  let cipherData, plainData

  // hex
  cipherData = SM4.encrypt(data, key, {
    mode: CBC,
    iv,
    outputEncoding: 'hex'
  })
  plainData = SM4.decrypt(cipherData, key, {
    mode: CBC,
    iv,
    inputEncoding: 'hex',
    outputEncoding: 'utf8'
  })
  t.is(cipherData, cbc_expected.toString('hex'))
  t.is(plainData, data)

  // base64
  cipherData = SM4.encrypt(data, key, {
    mode: CBC,
    iv,
    outputEncoding: 'base64'
  })
  plainData = SM4.decrypt(cipherData, key, {
    mode: CBC,
    iv,
    inputEncoding: 'base64',
    outputEncoding: 'utf8'
  })
  t.is(cipherData, cbc_expected.toString('base64'))
  t.is(plainData, data)

  // ArrayBuffer
  cipherData = SM4.encrypt(data, key, {
    mode: CBC,
    iv
  })
  plainData = SM4.decrypt(cipherData, key, {
    mode: CBC,
    iv,
    outputEncoding: 'utf8'
  })
  t.true(cipherData instanceof ArrayBuffer)
  t.is(plainData, data)
  plainData = SM4.decrypt(cipherData, key, {
    mode: CBC,
    iv
  })
  t.true(plainData instanceof ArrayBuffer)
})
