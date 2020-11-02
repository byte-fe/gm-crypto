// 32 位整数无符号循环左移
const leftShift = (a, n) => {
  n = n % 32
  return (a << n) | (a >>> (32 - n))
}

// 补全 16 进制字符串
const leftPad = (str, num) => {
  const padding = num - str.length
  return (padding > 0 ? '0'.repeat(padding) : '') + str
}

module.exports = {
  leftShift,
  leftPad
}
