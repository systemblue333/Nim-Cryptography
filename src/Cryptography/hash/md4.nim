import ../../../../Utility/src/Utility/codeutils/indexutils
import ../../../../Utility/src/Utility/codeutils/bits
import ../../../../Utility/src/Utility/codeutils/errorutils
import ../../../../Utility/src/Utility/dataformat/dataformat

const
  Bits*: int = sizeof(int) * 8

when Bits == 64:
  type
    MD4Ctx* = object
      state*: array[4, uint32]
      count*: uint64
      buffer*: array[64, uint8]
else:
  type
    MD4Ctx* = object
      state*: array[4, uint32]
      count*: array[2, uint32]
      buffer*: array[64, uint8]

const
  Padding: array[64, uint8] = (block:
    var p: array[64, uint8]
    p[0] = 0x80'u8
    for i in 1 ..< 64:
      p[i] = 0x00'u8
    p
  )
  S11: uint32 = 3
  S12: uint32 = 7
  S13: uint32 = 11
  S14: uint32 = 19
  S21: uint32 = 3
  S22: uint32 = 5
  S23: uint32 = 9
  S24: uint32 = 13
  S31: uint32 = 3
  S32: uint32 = 9
  S33: uint32 = 11
  S34: uint32 = 15

template F(x, y, z: lent uint32): uint32 =
  (x and y) or ((not x) and z)

template G(x, y, z: lent uint32): uint32 =
  ((x and y) or ((x and z) or (y and z)))

template H(x, y, z: lent uint32): uint32 =
  (x xor y xor z)

template FF(a: var uint32, b, c, d, x, s: lent uint32): void =
  a += F(b, c, d) + x
  a = leftRotate(a, s)

template GG(a: var uint32, b, c, d, x, s: lent uint32): void =
  a += G(b, c, d) + x + 0x5a827999'u32
  a = leftRotate(a, s)

template HH(a: var uint32, b, c, d, x, s: lent uint32): void =
  a += H(b, c, d) + x + 0x6ed9eba1'u32
  a = leftRotate(a, s)

template md4InitC(ctx: var MD4Ctx): void =
  when Bits == 64:
    ctx.count = 0'u64
  else:
    ctx.count[0] = 0'u32
    ctx.count[1] = 0'u32
  ctx.state[0] = 0x67452301'u32
  ctx.state[1] = 0xefcdab89'u32
  ctx.state[2] = 0x98badcfe'u32
  ctx.state[3] = 0x10325476'u32

template md4Transform(state: var array[4, uint32], input: lent array[64, uint8]): void =
  var a: uint32 = state[0]
  var b: uint32 = state[1]
  var c: uint32 = state[2]
  var d: uint32 = state[3]
  var x: array[16, uint32]

  decodeLE(input, x)

  FF(a, b, c, d, x[ 0], S11)
  FF(d, a, b, c, x[ 1], S12)
  FF(c, d, a, b, x[ 2], S13)
  FF(b, c, d, a, x[ 3], S14)
  FF(a, b, c, d, x[ 4], S11)
  FF(d, a, b, c, x[ 5], S12)
  FF(c, d, a, b, x[ 6], S13)
  FF(b, c, d, a, x[ 7], S14)
  FF(a, b, c, d, x[ 8], S11)
  FF(d, a, b, c, x[ 9], S12)
  FF(c, d, a, b, x[10], S13)
  FF(b, c, d, a, x[11], S14)
  FF(a, b, c, d, x[12], S11)
  FF(d, a, b, c, x[13], S12)
  FF(c, d, a, b, x[14], S13)
  FF(b, c, d, a, x[15], S14)

  GG(a, b, c, d, x[ 0], S21)
  GG(d, a, b, c, x[ 4], S22)
  GG(c, d, a, b, x[ 8], S23)
  GG(b, c, d, a, x[12], S24)
  GG(a, b, c, d, x[ 1], S21)
  GG(d, a, b, c, x[ 5], S22)
  GG(c, d, a, b, x[ 9], S23)
  GG(b, c, d, a, x[13], S24)
  GG(a, b, c, d, x[ 2], S21)
  GG(d, a, b, c, x[ 6], S22)
  GG(c, d, a, b, x[10], S23)
  GG(b, c, d, a, x[14], S24)
  GG(a, b, c, d, x[ 3], S21)
  GG(d, a, b, c, x[ 7], S22)
  GG(c, d, a, b, x[11], S23)
  GG(b, c, d, a, x[15], S24)

  HH(a, b, c, d, x[ 0], S31)
  HH(d, a, b, c, x[ 8], S32)
  HH(c, d, a, b, x[ 4], S33)
  HH(b, c, d, a, x[12], S34)
  HH(a, b, c, d, x[ 2], S31)
  HH(d, a, b, c, x[10], S32)
  HH(c, d, a, b, x[ 6], S33)
  HH(b, c, d, a, x[14], S34)
  HH(a, b, c, d, x[ 1], S31)
  HH(d, a, b, c, x[ 9], S32)
  HH(c, d, a, b, x[ 5], S33)
  HH(b, c, d, a, x[13], S34)
  HH(a, b, c, d, x[ 3], S31)
  HH(d, a, b, c, x[11], S32)
  HH(c, d, a, b, x[ 7], S33)
  HH(b, c, d, a, x[15], S34)

  state[0] += a
  state[1] += b
  state[2] += c
  state[3] += d

template md4InputC(ctx: var MD4Ctx, input: lent openArray[uint8]): void =
  let inputLen: int = input.len

  when Bits == 64:
    var index: uint32 = uint32((ctx.count shr 3) and 0x3F'u64)
    ctx.count += uint64(inputLen) shl 3
  else:
    var index: uint32 = (ctx.count[0] shr 3) and 0x3F'u32

    ctx.count[0] += uint32(inputLen shl 3)
    if ctx.count[0] < uint32(inputLen shl 3):
      ctx.count[1] += 1
    ctx.count[1] += uint32(inputLen shr 29)

  let partLen: int = 64 - index.int

  var i: int = 0

  if inputLen >= partLen:
    for i in 0 ..< partLen:
      ctx.buffer[index.int + i] = input[i]
    md4Transform(ctx.state, ctx.buffer)

    i = partLen
    while i + 63 < inputLen:
      var buffer: array[64, uint8]
      for j in static(0 ..< 64):
        buffer[j] = input[i + j]
      md4Transform(ctx.state, buffer)

      i += 64
    index = 0

  if i < inputLen:
    for j in 0 ..< (inputLen - i):
      ctx.buffer[index.int + j] = input[i + j]

template md4FinalC(ctx: var MD4Ctx): array[16, uint8] =
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
  let padLen: uint32 = if index < 56'u32: 56'u32 - index else: 120'u32- index

  md4InputC(ctx, Padding[0 ..< padLen])

  md4InputC(ctx, bits)

  encodeLE(ctx.state, output)

  output

# export wrappers
when defined(templateOpt):
  template md4Init*(ctx: var MD4Ctx): void =
    md4InitC(ctx)
  template md4Input*(ctx: var MD4Ctx, input: lent openArray[uint8]): void =
    md4InputC(ctx, input)
  when defined(varOpt):
    template md4Fianl*(ctx: var MD4Ctx, output: var array[16, uint8]): void =
      output = md4FinalC(ctx)
  else:
    template md4Final*(ctx: var MD4Ctx): array[16, uint8] =
      md4FinalC(ctx)
else:
  proc md4Init*(ctx: var MD4Ctx): void =
    md4InitC(ctx)
  proc md4Input*(ctx: var MD4Ctx, input: openArray[uint8]): void =
    md4InputC(ctx, input)
  when defined(varOpt):
    proc md4Fianl*(ctx: var MD4Ctx, output: var array[16, uint8]): void =
      output = md4FinalC(ctx)
  else:
    proc md4Final*(ctx: var MD4Ctx): array[16, uint8] =
      md4FinalC(ctx)

when defined(test):
  var S: seq[uint8] = charToBin("Hello, World!")
  var ctx: MD4Ctx
  md4Init(ctx)
  md4Input(ctx, S)
  echo "MD4Stream : ", binToHex(md4Final(ctx))
  echo "MD4 Standard : 94E3CB0FA9AA7A5EE3DB74B79E915989"
  echo "Input : Hello, World!"
