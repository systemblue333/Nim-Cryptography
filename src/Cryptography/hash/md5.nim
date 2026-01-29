import strutils
import sequtils
import ../../../../Utility/src/Utility/codeutils/indexutils
import ../../../../Utility/src/Utility/codeutils/bits
import ../../../../Utility/src/Utility/codeutils/errorutils
import ../../../../Utility/src/Utility/dataformat/dataformat

# s specifies the per-round shift amounts
const s: array[64, uint32] =  [
  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
]

# precomputed table
const `K`: array[64, uint32] = [
  0xd76aa478'u32, 0xe8c7b756'u32, 0x242070db'u32, 0xc1bdceee'u32,
  0xf57c0faf'u32, 0x4787c62a'u32, 0xa8304613'u32, 0xfd469501'u32,
  0x698098d8'u32, 0x8b44f7af'u32, 0xffff5bb1'u32, 0x895cd7be'u32,
  0x6b901122'u32, 0xfd987193'u32, 0xa679438e'u32, 0x49b40821'u32,
  0xf61e2562'u32, 0xc040b340'u32, 0x265e5a51'u32, 0xe9b6c7aa'u32,
  0xd62f105d'u32, 0x02441453'u32, 0xd8a1e681'u32, 0xe7d3fbc8'u32,
  0x21e1cde6'u32, 0xc33707d6'u32, 0xf4d50d87'u32, 0x455a14ed'u32,
  0xa9e3e905'u32, 0xfcefa3f8'u32, 0x676f02d9'u32, 0x8d2a4c8a'u32,
  0xfffa3942'u32, 0x8771f681'u32, 0x6d9d6122'u32, 0xfde5380c'u32,
  0xa4beea44'u32, 0x4bdecfa9'u32, 0xf6bb4b60'u32, 0xbebfbc70'u32,
  0x289b7ec6'u32, 0xeaa127fa'u32, 0xd4ef3085'u32, 0x04881d05'u32,
  0xd9d4d039'u32, 0xe6db99e5'u32, 0x1fa27cf8'u32, 0xc4ac5665'u32,
  0xf4292244'u32, 0x432aff97'u32, 0xab9423a7'u32, 0xfc93a039'u32,
  0x655b59c3'u32, 0x8f0ccc92'u32, 0xffeff47d'u32, 0x85845dd1'u32,
  0x6fa87e4f'u32, 0xfe2ce6e0'u32, 0xa3014314'u32, 0x4e0811a1'u32,
  0xf7537e82'u32, 0xbd3af235'u32, 0x2ad7d2bb'u32, 0xeb86d391'u32
]

template md5OneC(msg: lent openArray[uint8]): array[16, uint8] =
  var output: array[16, uint8]
  # Initialize variables
  var a0: uint32 = 0x67452301'u32
  var b0: uint32 = 0xefcdab89'u32
  var c0: uint32 = 0x98badcfe'u32
  var d0: uint32 = 0x10325476'u32

  let bitLen: uint64 = uint64(msg.len) * 8
  var buffer: array[64, uint8]
  var msgIndex: int = 0
  var paddingStarted = false
  var lengthAppended = false

  while not lengthAppended:
    var bufferIndex: int = 0
    for i in 0 ..< 64: buffer[i] = 0
    while bufferIndex < 64:
      if msgIndex < msg.len:
        buffer[bufferIndex] = msg[msgIndex]
        msgIndex.inc
        bufferIndex.inc
      elif not paddingStarted:
        buffer[bufferIndex] = 0x80'u8
        paddingStarted = true
        bufferIndex.inc
      elif not lengthAppended:
        if bufferIndex <= 56:
          if bufferIndex == 56:
            buffer[bufferIndex + 0] = uint8((bitLen shr (8 * 0)) and 0xFF'u64)
            buffer[bufferIndex + 1] = uint8((bitLen shr (8 * 1)) and 0xFF'u64)
            buffer[bufferIndex + 2] = uint8((bitLen shr (8 * 2)) and 0xFF'u64)
            buffer[bufferIndex + 3] = uint8((bitLen shr (8 * 3)) and 0xFF'u64)
            buffer[bufferIndex + 4] = uint8((bitLen shr (8 * 4)) and 0xFF'u64)
            buffer[bufferIndex + 5] = uint8((bitLen shr (8 * 5)) and 0xFF'u64)
            buffer[bufferIndex + 6] = uint8((bitLen shr (8 * 6)) and 0xFF'u64)
            buffer[bufferIndex + 7] = uint8((bitLen shr (8 * 7)) and 0xFF'u64)
            lengthAppended = true
            bufferIndex = 64
          else:
            buffer[bufferIndex] = 0x00'u8
            bufferIndex.inc
      else:
        bufferIndex.inc

    var M: array[16, uint32]
    for j in 0 ..< 16:
      M[j] = uint32(buffer[j * 4]) or
      (uint32(buffer[j * 4 + 1]) shl 8) or
      (uint32(buffer[j * 4 + 2]) shl 16) or
      (uint32(buffer[j * 4 + 3]) shl 24)

    var A: uint32 = a0
    var B: uint32 = b0
    var C: uint32 = c0
    var D: uint32 = d0

    for i in 0..63:
      var F: uint32
      var g: int
      if i <= 15:
        F = (B and C) or ((not B) and D)
        g = i
      elif i <= 31:
        F = (D and B) or ((not D) and C)
        g = (5 * i + 1) mod 16
      elif i <= 47:
        F = B xor C xor D
        g = (3 * i + 5) mod 16
      else:
        F = C xor (B or (not D))
        g = (7 * i) mod 16

      let temp = F + A + K[i] + M[g]
      A = D
      D = C
      C = B
      B = B + leftRotate(temp, s[i])

    a0 += A
    b0 += B
    c0 += C
    d0 += D

  var res = [a0, b0, c0, d0]
  for i in 0..3:
    output[i*4]   = uint8(res[i] and 0xff)
    output[i*4+1] = uint8((res[i] shr 8) and 0xff)
    output[i*4+2] = uint8((res[i] shr 16) and 0xff)
    output[i*4+3] = uint8((res[i] shr 24) and 0xff)

  output

const
  Bits*: int = sizeof(int) * 8

when Bits == 64:
  type
    MD5Ctx* = object
      state*: array[4, uint32]
      count*: uint64
      buffer*: array[64, uint8]
else:
  type
    MD5Ctx* = object
      state*: array[4, uint32]
      count*: array[2, uint32]
      buffer*: array[64, uint8]

const
  S11: uint32 = 7
  S12: uint32 = 12
  S13: uint32 = 17
  S14: uint32 = 22
  S21: uint32 = 5
  S22: uint32 = 9
  S23: uint32 = 14
  S24: uint32 = 20
  S31: uint32 = 4
  S32: uint32 = 11
  S33: uint32 = 16
  S34: uint32 = 23
  S41: uint32 = 6
  S42: uint32 = 10
  S43: uint32 = 15
  S44: uint32 = 21
  Padding: array[64, uint8] = (block:
    var p: array[64, uint8]
    p[0] = 0x80'u8
    for i in 1 ..< 64:
      p[i] = 0x00'u8
    p
  )

template F(x, y, z: uint32): uint32 =
  (x and y) or ((not x) and z)

template G(x, y, z: uint32): uint32 =
  (x and z) or (y and (not z))

template H(x, y, z: uint32): uint32 =
  x xor y xor z

template I(x, y, z: uint32): uint32 =
  y xor (x or (not z))

template FF(a, b, c, d, x: var uint32, s, ac: uint32): void =
  a += F(b, c, d) + x + ac
  a = leftRotate(a, s)
  a += b

template GG(a, b, c, d, x: var uint32, s, ac: uint32): void =
  a += G(b, c, d) + x + ac
  a = leftRotate(a, s)
  a += b

template HH(a, b, c, d, x: var uint32, s, ac: uint32): void =
  a += H(b, c, d) + x + ac
  a = leftRotate(a, s)
  a += b

template II(a, b, c, d, x: var uint32, s, ac: uint32): void =
  a += I(b, c, d) + x + ac
  a = leftRotate(a, s)
  a += b

template md5Transform(state: var array[4, uint32], `block`: lent array[64, uint8]): void =
  var a = state[0]
  var b = state[1]
  var c = state[2]
  var d = state[3]
  var myBlock: array[16, uint32]

  decodeLE(`block`, myBlock)

  FF(a, b, c, d, myBlock[0], 7'u32, 0xD76AA478'u32)
  FF(d, a, b, c, myBlock[1], 12'u32, 0xE8C7B756'u32)
  FF(c, d, a, b, myBlock[2], 17'u32, 0x242070DB'u32)
  FF(b, c, d, a, myBlock[3], 22'u32, 0xC1BDCEEE'u32)
  FF(a, b, c, d, myBlock[4], 7'u32, 0xF57C0FAF'u32)
  FF(d, a, b, c, myBlock[5], 12'u32, 0x4787C62A'u32)
  FF(c, d, a, b, myBlock[6], 17'u32, 0xA8304613'u32)
  FF(b, c, d, a, myBlock[7], 22'u32, 0xFD469501'u32)
  FF(a, b, c, d, myBlock[8], 7'u32, 0x698098D8'u32)
  FF(d, a, b, c, myBlock[9], 12'u32, 0x8B44F7AF'u32)
  FF(c, d, a, b, myBlock[10], 17'u32, 0xFFFF5BB1'u32)
  FF(b, c, d, a, myBlock[11], 22'u32, 0x895CD7BE'u32)
  FF(a, b, c, d, myBlock[12], 7'u32, 0x6B901122'u32)
  FF(d, a, b, c, myBlock[13], 12'u32, 0xFD987193'u32)
  FF(c, d, a, b, myBlock[14], 17'u32, 0xA679438E'u32)
  FF(b, c, d, a, myBlock[15], 22'u32, 0x49B40821'u32)
  GG(a, b, c, d, myBlock[1], 5'u32, 0xF61E2562'u32)
  GG(d, a, b, c, myBlock[6], 9'u32, 0xC040B340'u32)
  GG(c, d, a, b, myBlock[11], 14'u32, 0x265E5A51'u32)
  GG(b, c, d, a, myBlock[0], 20'u32, 0xE9B6C7AA'u32)
  GG(a, b, c, d, myBlock[5], 5'u32, 0xD62F105D'u32)
  GG(d, a, b, c, myBlock[10], 9'u32, 0x02441453'u32)
  GG(c, d, a, b, myBlock[15], 14'u32, 0xD8A1E681'u32)
  GG(b, c, d, a, myBlock[4], 20'u32, 0xE7D3FBC8'u32)
  GG(a, b, c, d, myBlock[9], 5'u32, 0x21E1CDE6'u32)
  GG(d, a, b, c, myBlock[14], 9'u32, 0xC33707D6'u32)
  GG(c, d, a, b, myBlock[3], 14'u32, 0xF4D50D87'u32)
  GG(b, c, d, a, myBlock[8], 20'u32, 0x455A14ED'u32)
  GG(a, b, c, d, myBlock[13], 5'u32, 0xA9E3E905'u32)
  GG(d, a, b, c, myBlock[2], 9'u32, 0xFCEFA3F8'u32)
  GG(c, d, a, b, myBlock[7], 14'u32, 0x676F02D9'u32)
  GG(b, c, d, a, myBlock[12], 20'u32, 0x8D2A4C8A'u32)
  HH(a, b, c, d, myBlock[5], 4'u32, 0xFFFA3942'u32)
  HH(d, a, b, c, myBlock[8], 11'u32, 0x8771F681'u32)
  HH(c, d, a, b, myBlock[11], 16'u32, 0x6D9D6122'u32)
  HH(b, c, d, a, myBlock[14], 23'u32, 0xFDE5380C'u32)
  HH(a, b, c, d, myBlock[1], 4'u32, 0xA4BEEA44'u32)
  HH(d, a, b, c, myBlock[4], 11'u32, 0x4BDECFA9'u32)
  HH(c, d, a, b, myBlock[7], 16'u32, 0xF6BB4B60'u32)
  HH(b, c, d, a, myBlock[10], 23'u32, 0xBEBFBC70'u32)
  HH(a, b, c, d, myBlock[13], 4'u32, 0x289B7EC6'u32)
  HH(d, a, b, c, myBlock[0], 11'u32, 0xEAA127FA'u32)
  HH(c, d, a, b, myBlock[3], 16'u32, 0xD4EF3085'u32)
  HH(b, c, d, a, myBlock[6], 23'u32, 0x04881D05'u32)
  HH(a, b, c, d, myBlock[9], 4'u32, 0xD9D4D039'u32)
  HH(d, a, b, c, myBlock[12], 11'u32, 0xE6DB99E5'u32)
  HH(c, d, a, b, myBlock[15], 16'u32, 0x1FA27CF8'u32)
  HH(b, c, d, a, myBlock[2], 23'u32, 0xC4AC5665'u32)
  II(a, b, c, d, myBlock[0], 6'u32, 0xF4292244'u32)
  II(d, a, b, c, myBlock[7], 10'u32, 0x432AFF97'u32)
  II(c, d, a, b, myBlock[14], 15'u32, 0xAB9423A7'u32)
  II(b, c, d, a, myBlock[5], 21'u32, 0xFC93A039'u32)
  II(a, b, c, d, myBlock[12], 6'u32, 0x655B59C3'u32)
  II(d, a, b, c, myBlock[3], 10'u32, 0x8F0CCC92'u32)
  II(c, d, a, b, myBlock[10], 15'u32, 0xFFEFF47D'u32)
  II(b, c, d, a, myBlock[1], 21'u32, 0x85845DD1'u32)
  II(a, b, c, d, myBlock[8], 6'u32, 0x6FA87E4F'u32)
  II(d, a, b, c, myBlock[15], 10'u32, 0xFE2CE6E0'u32)
  II(c, d, a, b, myBlock[6], 15'u32, 0xA3014314'u32)
  II(b, c, d, a, myBlock[13], 21'u32, 0x4E0811A1'u32)
  II(a, b, c, d, myBlock[4], 6'u32, 0xF7537E82'u32)
  II(d, a, b, c, myBlock[11], 10'u32, 0xBD3AF235'u32)
  II(c, d, a, b, myBlock[2], 15'u32, 0x2AD7D2BB'u32)
  II(b, c, d, a, myBlock[9], 21'u32, 0xEB86D391'u32)

  state[0] = state[0] + a
  state[1] = state[1] + b
  state[2] = state[2] + c
  state[3] = state[3] + d

template md5InitC(ctx: var MD5Ctx): void =
  when Bits == 64:
    ctx.count = 0'u64
  else:
    ctx.count[0] = 0'u32
    ctx.count[1] = 0'u32
  ctx.state[0] = 0x67452301'u32
  ctx.state[1] = 0xefcdab89'u32
  ctx.state[2] = 0x98badcfe'u32
  ctx.state[3] = 0x10325476'u32
  for i in static(0 ..< 64):
    ctx.buffer[i] = 0x00'u8

template md5InputC(ctx: var MD5Ctx, input: lent openArray[uint8]): void =
  var i: uint32 = 0
  let inputLen: uint32 = input.len.uint32

  when Bits == 64:
    var index: uint32 = uint32((ctx.count shr 3) and 0x3F'u64)
    ctx.count += uint64(inputLen) shl 3
  else:
    var index: uint32 = (ctx.count[0] shr 3) and 0x3F'u32
    ctx.count[0] += uint32(inputLen shl 3)
    if ctx.count[0] < uint32(inputLen shl 3):
      ctx.count[1] += 1 # 0
    ctx.count[1] += uint32(inputLen shr 29)

  let partLen: uint32 = 64 - index.uint32

  if inputLen >= partLen:
    for i in 0 ..< partLen:
      ctx.buffer[index + i] = input[i]

    md5Transform(ctx.state, ctx.buffer)

    i = partLen

    while i + 63 < inputLen:
      var buffer: array[64, uint8]
      for j in 0 ..< 64:
        buffer[j] = input[j + i.int]
      md5Transform(ctx.state, buffer)
      i += 64

    if i < inputLen:
      for i in 0 ..< inputLen:
        ctx.buffer[index + i] = input[i]
  elif inputLen > 0:
    for i in 0 ..< inputLen:
      ctx.buffer[index + i] = input[i]

template md5FinalC(ctx: var MD5Ctx): array[16, uint8] =
  var output: array[16, uint8]
  var bits: array[8, uint8]

  when Bits == 64:
    toBytesLE(ctx.count, bits)
  else:
    encodeLE(ctx.count, bits)

  when Bits == 64:
    let index: uint32 = uint32((ctx.count shr 3) and 0x3F'u64)
  else:
    let index: uint32 = (ctx.count[0] shr 3) and 0x3F'u32
  var padLen: uint32 = if index < 56: 56 - index else: 120 - index

  md5InputC(ctx, Padding[0 ..< padLen])

  md5InputC(ctx, bits)

  encodeLE(ctx.state, output)

  output

# export wrappers
when defined(templateOpt):
  template md5Init*(ctx: var MD5Ctx): void =
    md5InitC(ctx)
  template md5Input*(ctx: var MD5Ctx, input: lent openArray[uint8]): void =
    md5InputC(ctx, input)
  when defined(varOpt):
    template md5Fianl*(ctx: var MD5Ctx, output: var array[16, uint8]): void =
      output = md5FinalC(ctx)
    template md5One*(input: lent openArray[uint8], output: var array[16, uint8]): void =
      output = md5OneC(input)
  else:
    template md5Final*(ctx: var MD5Ctx): array[16, uint8] =
      md5FinalC(ctx)
    template md5One*(input: lent openArray[uint8]): array[16, uint8] =
      md5OneC(input)
else:
  proc md5Init*(ctx: var MD5Ctx): void =
    md5InitC(ctx)
  proc md5Input*(ctx: var MD5Ctx, input: openArray[uint8]): void =
    md5InputC(ctx, input)
  when defined(varOpt):
    proc md5Fianl*(ctx: var MD5Ctx, output: var array[16, uint8]): void =
      output = md5FinalC(ctx)
    proc md5One*(input: openArray[uint8], output: var array[16, uint8]): void =
      output = md5OneC(input)
  else:
    proc md5Final*(ctx: var MD5Ctx): array[16, uint8] =
      md5FinalC(ctx)
    proc md5One*(input: openArray[uint8]): array[16, uint8] =
      md5OneC(input)

when defined(test):
  var S: seq[uint8] = charToBin("Hello, World!")
  var ctx: MD5Ctx
  md5Init(ctx)
  md5Input(ctx, S)
  echo "MD5Stream : ", binToHex(md5Final(ctx))
  echo "MD5One : ", binToHex(md5One(S))
  echo "MD5 Standard : 65A8E27D8879283831B664BD8B7F0AD4"
  echo "Input : Hello, World!"
