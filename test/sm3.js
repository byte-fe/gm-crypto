const test = require('ava')
const toArrayBuffer = require('to-arraybuffer')
const { SM3 } = require('../dist/')

test('Validate unsupported types', (t) => {
  t.plan(4)

  t.throws(
    () => {
      SM3.digest(123)
    },
    { instanceOf: TypeError }
  )

  t.throws(
    () => {
      SM3.digest(true)
    },
    { instanceOf: TypeError }
  )

  t.throws(
    () => {
      SM3.digest([1, 2, 3])
    },
    { instanceOf: TypeError }
  )

  t.throws(
    () => {
      SM3.digest(null)
    },
    { instanceOf: TypeError }
  )
})

test('Calculates digest values', async (t) => {
  t.plan(7)

  // Official exmaples
  t.is(
    SM3.digest('abc', 'utf8', 'hex'),
    '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'
  )
  t.is(
    SM3.digest(
      '61626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364',
      'hex',
      'hex'
    ),
    'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732'
  )

  // base64 input
  t.is(
    SM3.digest('YWJj', 'base64', 'hex'),
    '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'
  )

  // Buffer input
  t.is(
    SM3.digest(Buffer.from('abc'), '', 'base64'),
    'Zsfw9GLu7dnR8tRr3BDk4kFnxIdc8veiKX2gK49LqOA='
  )

  // ArrayBuffer input
  t.is(
    SM3.digest(toArrayBuffer(Buffer.from('abc')), 'x', 'base64'),
    'Zsfw9GLu7dnR8tRr3BDk4kFnxIdc8veiKX2gK49LqOA='
  )

  // ArrayBuffer output
  const arraybuffer = SM3.digest(
    Buffer.from(
      'YWJjZGFiY2RhYmNkYWJjZGFiY2RhYmNkYWJjZGFiY2RhYmNkYWJjZGFiY2RhYmNkYWJjZGFiY2RhYmNkYWJjZA==',
      'base64'
    )
  )
  t.true(arraybuffer instanceof ArrayBuffer)
  t.is(
    Buffer.compare(
      Buffer.from(arraybuffer),
      Buffer.from('3r6f+SJ1uKE4YEiJwY5aTW/bcOU4fldlKT3Lo5wMVzI=', 'base64')
    ),
    0
  )
})

test('Input size exceeds 56 bytes', async (t) => {
  t.plan(1)
  t.is(
    SM3.digest(
      'hello world!hello world!hello world!hello world!hello worl', // Buffer.alloc(58, 'hello world!', 'utf8')
      '',
      'base64'
    ),
    'PLP9zs97R3Knzfb9AC5rs4oa573F8wxapycMP1b8sKE='
  )
})
