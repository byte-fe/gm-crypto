const { performance, PerformanceObserver } = require('perf_hooks')

const { SM2_WASM, SM2, SM3_WASM, SM3, SM4_WASM, SM4 } = require('../dist/')

let data = 'abenchmark'

for (let i = 0; i < 5 * 1024; i++) {
  data += 'abenchmark'
}

const performanceObserver = new PerformanceObserver((entryList) => {
  for (const entry of entryList.getEntries()) {
    console.log(`${entry.name}: ${entry.duration} ms`)
  }
})

performanceObserver.observe({ entryTypes: ['function'] })

const { publicKey, privateKey } = SM2.generateKeyPair()

const sm4Key = '0123456789abcdeffedcba9876543210'

const jsSM3Digest = () => {
  for (let i = 0; i < 1000; i++) {
    SM3.digest(
      '61626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364',
      'hex',
      'hex'
    )
  }
}
const wasmSM3Digest = async () => {
  for (let i = 0; i < 1000; i++) {
    await SM3_WASM.digest(
      '61626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364',
      'hex',
      'hex'
    )
  }
}

const jsSM2EncryptAndDecrypt = () => {
  for (let i = 0; i < 10; i++) {
    cipherData = SM2.encrypt(data, publicKey, {
      inputEncoding: 'utf8',
      outputEncoding: 'hex'
    })
    SM2.decrypt(cipherData, privateKey, {
      inputEncoding: 'hex',
      outputEncoding: 'utf8'
    })
  }
}
const wasmSM2EncryptAndDecrypt = async () => {
  for (let i = 0; i < 10; i++) {
    cipherData = await SM2_WASM.encrypt(data, publicKey, {
      inputEncoding: 'utf8',
      outputEncoding: 'hex'
    })
    await SM2_WASM.decrypt(cipherData, privateKey, {
      inputEncoding: 'hex',
      outputEncoding: 'utf8'
    })
  }
}

const jsSM4EncryptAndDecrypt = () => {
  for (let i = 0; i < 10; i++) {
    cipherData = SM4.encrypt(data, sm4Key, {
      inputEncoding: 'utf8',
      outputEncoding: 'hex'
    })
    SM4.decrypt(cipherData, sm4Key, {
      inputEncoding: 'hex',
      outputEncoding: 'utf8'
    })
  }
}
const wasmSM4EncryptAndDecrypt = async () => {
  for (let i = 0; i < 10; i++) {
    cipherData = await SM4_WASM.encrypt(data, sm4Key, {
      inputEncoding: 'utf8',
      outputEncoding: 'hex'
    })
    await SM4_WASM.decrypt(cipherData, sm4Key, {
      inputEncoding: 'hex',
      outputEncoding: 'utf8'
    })
  }
}

performance.timerify(jsSM2EncryptAndDecrypt)()
performance.timerify(wasmSM2EncryptAndDecrypt)()

performance.timerify(jsSM3Digest)()
performance.timerify(wasmSM3Digest)()

performance.timerify(jsSM4EncryptAndDecrypt)()
performance.timerify(wasmSM4EncryptAndDecrypt)()
