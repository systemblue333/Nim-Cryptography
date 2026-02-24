import strutils
import sequtils
import ../../../../Utility/src/Utility/codeutils/indexutils
import ../../../../Utility/src/Utility/codeutils/bits
import ../../../../Utility/src/Utility/codeutils/errorutils
import ../../../../Utility/src/Utility/dataformat/dataformat
import std/[monotimes, times]
import std/bitops

# s specifies the per-round shift amounts
const
  # shift amount table
  S: array[64, uint32] =  [
  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
  ]

  # precomputed table
  K: array[64, uint32] = [
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

  # block indexing list
  BlockIndex: array[64, int] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,
    5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
    0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9
  ]

# md5 oneshot core
template md5OneC(msg: lent openArray[uint8]): array[16, uint8] =
  # declaring output
  var output: array[16, uint8]

  # declare and initialize state
  var state: array[4, uint32] = [0x67452301'u32, 0xefcdab89'u32, 0x98badcfe'u32, 0x10325476'u32]

  # set bit length
  let bitLen: uint64 = uint64(msg.len) * 8

  # declare buffer
  var buffer: array[64, uint8]

  # declare index and check variables
  var msgIndex: int = 0
  var paddingStarted = false
  var lengthAppended = false

  # while length is not end: loop
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
            for i in static(0 ..< 8):
              buffer[bufferIndex + i] = uint8((bitLen shr (8 * i)) and 0xFF'u64)
            lengthAppended = true
            bufferIndex = 64
          else:
            buffer[bufferIndex] = 0x00'u8
            bufferIndex.inc
      else:
        bufferIndex.inc

    var chunk: array[16, uint32]
    for j in static(0 ..< 16):
      chunk[j] = uint32(buffer[j * 4]) or
      (uint32(buffer[j * 4 + 1]) shl 8) or
      (uint32(buffer[j * 4 + 2]) shl 16) or
      (uint32(buffer[j * 4 + 3]) shl 24)

    var a: uint32 = state[0]
    var b: uint32 = state[1]
    var c: uint32 = state[2]
    var d: uint32 = state[3]

    for i in static(0 ..< 64):
      var f: uint32
      var g: int
      if i <= 15:
        f = (b and c) or ((not b) and d)
        g = i
      elif i <= 31:
        f = (b and d) or ((not d) and c)
        g = (5 * i + 1) mod 16
      elif i <= 47:
        f = b xor c xor d
        g = (3 * i + 5) mod 16
      else:
        f = c xor (b or (not d))
        g = (7 * i) mod 16

      let temp = f + a + K[i] + chunk[g]
      a = d
      d = c
      c = b
      b = b + rotateLeftBits(temp, S[i])

    state[0] += a
    state[1] += b
    state[2] += c
    state[3] += d


  encodeLE(state, output)

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
  a = rotateLeftBits(a, s)
  a += b

template GG(a, b, c, d, x: var uint32, s, ac: uint32): void =
  a += G(b, c, d) + x + ac
  a = rotateLeftBits(a, s)
  a += b

template HH(a, b, c, d, x: var uint32, s, ac: uint32): void =
  a += H(b, c, d) + x + ac
  a = rotateLeftBits(a, s)
  a += b

template II(a, b, c, d, x: var uint32, s, ac: uint32): void =
  a += I(b, c, d) + x + ac
  a = rotateLeftBits(a, s)
  a += b

template md5Transform(state: var array[4, uint32], input: lent openArray[uint8]): void =
  var chunk: array[16, uint32]

  decodeLE(input, chunk, 16)

  var a: uint32 = state[0]
  var b: uint32 = state[1]
  var c: uint32 = state[2]
  var d: uint32 = state[3]

  FF(a, b, c, d, chunk[ 0], S[ 0], K[ 0])
  FF(d, a, b, c, chunk[ 1], S[ 1], K[ 1])
  FF(c, d, a, b, chunk[ 2], S[ 2], K[ 2])
  FF(b, c, d, a, chunk[ 3], S[ 3], K[ 3])
  FF(a, b, c, d, chunk[ 4], S[ 4], K[ 4])
  FF(d, a, b, c, chunk[ 5], S[ 5], K[ 5])
  FF(c, d, a, b, chunk[ 6], S[ 6], K[ 6])
  FF(b, c, d, a, chunk[ 7], S[ 7], K[ 7])
  FF(a, b, c, d, chunk[ 8], S[ 8], K[ 8])
  FF(d, a, b, c, chunk[ 9], S[ 9], K[ 9])
  FF(c, d, a, b, chunk[10], S[10], K[10])
  FF(b, c, d, a, chunk[11], S[11], K[11])
  FF(a, b, c, d, chunk[12], S[12], K[12])
  FF(d, a, b, c, chunk[13], S[13], K[13])
  FF(c, d, a, b, chunk[14], S[14], K[14])
  FF(b, c, d, a, chunk[15], S[15], K[15])

  GG(a, b, c, d, chunk[ 1], S[16], K[16])
  GG(d, a, b, c, chunk[ 6], S[17], K[17])
  GG(c, d, a, b, chunk[11], S[18], K[18])
  GG(b, c, d, a, chunk[ 0], S[19], K[19])
  GG(a, b, c, d, chunk[ 5], S[20], K[20])
  GG(d, a, b, c, chunk[10], S[21], K[21])
  GG(c, d, a, b, chunk[15], S[22], K[22])
  GG(b, c, d, a, chunk[ 4], S[23], K[23])
  GG(a, b, c, d, chunk[ 9], S[24], K[24])
  GG(d, a, b, c, chunk[14], S[25], K[25])
  GG(c, d, a, b, chunk[ 3], S[26], K[26])
  GG(b, c, d, a, chunk[ 8], S[27], K[27])
  GG(a, b, c, d, chunk[13], S[28], K[28])
  GG(d, a, b, c, chunk[ 2], S[29], K[29])
  GG(c, d, a, b, chunk[ 7], S[30], K[30])
  GG(b, c, d, a, chunk[12], S[31], K[31])

  HH(a, b, c, d, chunk[ 5], S[32], K[32])
  HH(d, a, b, c, chunk[ 8], S[33], K[33])
  HH(c, d, a, b, chunk[11], S[34], K[34])
  HH(b, c, d, a, chunk[14], S[35], K[35])
  HH(a, b, c, d, chunk[ 1], S[36], K[36])
  HH(d, a, b, c, chunk[ 4], S[37], K[37])
  HH(c, d, a, b, chunk[ 7], S[38], K[38])
  HH(b, c, d, a, chunk[10], S[39], K[39])
  HH(a, b, c, d, chunk[13], S[40], K[40])
  HH(d, a, b, c, chunk[ 0], S[41], K[41])
  HH(c, d, a, b, chunk[ 3], S[42], K[42])
  HH(b, c, d, a, chunk[ 6], S[43], K[43])
  HH(a, b, c, d, chunk[ 9], S[44], K[44])
  HH(d, a, b, c, chunk[12], S[45], K[45])
  HH(c, d, a, b, chunk[15], S[46], K[46])
  HH(b, c, d, a, chunk[ 2], S[47], K[47])

  II(a, b, c, d, chunk[ 0], S[48], K[48])
  II(d, a, b, c, chunk[ 7], S[49], K[49])
  II(c, d, a, b, chunk[14], S[50], K[50])
  II(b, c, d, a, chunk[ 5], S[51], K[51])
  II(a, b, c, d, chunk[12], S[52], K[52])
  II(d, a, b, c, chunk[ 3], S[53], K[53])
  II(c, d, a, b, chunk[10], S[54], K[54])
  II(b, c, d, a, chunk[ 1], S[55], K[55])
  II(a, b, c, d, chunk[ 8], S[56], K[56])
  II(d, a, b, c, chunk[15], S[57], K[57])
  II(c, d, a, b, chunk[ 6], S[58], K[58])
  II(b, c, d, a, chunk[13], S[59], K[59])
  II(a, b, c, d, chunk[ 4], S[60], K[60])
  II(d, a, b, c, chunk[11], S[61], K[61])
  II(c, d, a, b, chunk[ 2], S[62], K[62])
  II(b, c, d, a, chunk[ 9], S[63], K[63])

  state[0] += a
  state[1] += b
  state[2] += c
  state[3] += d

when cpuEndian == littleEndian:
  template md5Transform(state: var array[4, uint32], input: ptr UncheckedArray[uint8]): void =
    var chunk: ptr UncheckedArray[uint32] = cast[ptr UncheckedArray[uint32]](input)

    var a: uint32 = state[0]
    var b: uint32 = state[1]
    var c: uint32 = state[2]
    var d: uint32 = state[3]

    FF(a, b, c, d, chunk[ 0], S[ 0], K[ 0])
    FF(d, a, b, c, chunk[ 1], S[ 1], K[ 1])
    FF(c, d, a, b, chunk[ 2], S[ 2], K[ 2])
    FF(b, c, d, a, chunk[ 3], S[ 3], K[ 3])
    FF(a, b, c, d, chunk[ 4], S[ 4], K[ 4])
    FF(d, a, b, c, chunk[ 5], S[ 5], K[ 5])
    FF(c, d, a, b, chunk[ 6], S[ 6], K[ 6])
    FF(b, c, d, a, chunk[ 7], S[ 7], K[ 7])
    FF(a, b, c, d, chunk[ 8], S[ 8], K[ 8])
    FF(d, a, b, c, chunk[ 9], S[ 9], K[ 9])
    FF(c, d, a, b, chunk[10], S[10], K[10])
    FF(b, c, d, a, chunk[11], S[11], K[11])
    FF(a, b, c, d, chunk[12], S[12], K[12])
    FF(d, a, b, c, chunk[13], S[13], K[13])
    FF(c, d, a, b, chunk[14], S[14], K[14])
    FF(b, c, d, a, chunk[15], S[15], K[15])

    GG(a, b, c, d, chunk[ 1], S[16], K[16])
    GG(d, a, b, c, chunk[ 6], S[17], K[17])
    GG(c, d, a, b, chunk[11], S[18], K[18])
    GG(b, c, d, a, chunk[ 0], S[19], K[19])
    GG(a, b, c, d, chunk[ 5], S[20], K[20])
    GG(d, a, b, c, chunk[10], S[21], K[21])
    GG(c, d, a, b, chunk[15], S[22], K[22])
    GG(b, c, d, a, chunk[ 4], S[23], K[23])
    GG(a, b, c, d, chunk[ 9], S[24], K[24])
    GG(d, a, b, c, chunk[14], S[25], K[25])
    GG(c, d, a, b, chunk[ 3], S[26], K[26])
    GG(b, c, d, a, chunk[ 8], S[27], K[27])
    GG(a, b, c, d, chunk[13], S[28], K[28])
    GG(d, a, b, c, chunk[ 2], S[29], K[29])
    GG(c, d, a, b, chunk[ 7], S[30], K[30])
    GG(b, c, d, a, chunk[12], S[31], K[31])

    HH(a, b, c, d, chunk[ 5], S[32], K[32])
    HH(d, a, b, c, chunk[ 8], S[33], K[33])
    HH(c, d, a, b, chunk[11], S[34], K[34])
    HH(b, c, d, a, chunk[14], S[35], K[35])
    HH(a, b, c, d, chunk[ 1], S[36], K[36])
    HH(d, a, b, c, chunk[ 4], S[37], K[37])
    HH(c, d, a, b, chunk[ 7], S[38], K[38])
    HH(b, c, d, a, chunk[10], S[39], K[39])
    HH(a, b, c, d, chunk[13], S[40], K[40])
    HH(d, a, b, c, chunk[ 0], S[41], K[41])
    HH(c, d, a, b, chunk[ 3], S[42], K[42])
    HH(b, c, d, a, chunk[ 6], S[43], K[43])
    HH(a, b, c, d, chunk[ 9], S[44], K[44])
    HH(d, a, b, c, chunk[12], S[45], K[45])
    HH(c, d, a, b, chunk[15], S[46], K[46])
    HH(b, c, d, a, chunk[ 2], S[47], K[47])

    II(a, b, c, d, chunk[ 0], S[48], K[48])
    II(d, a, b, c, chunk[ 7], S[49], K[49])
    II(c, d, a, b, chunk[14], S[50], K[50])
    II(b, c, d, a, chunk[ 5], S[51], K[51])
    II(a, b, c, d, chunk[12], S[52], K[52])
    II(d, a, b, c, chunk[ 3], S[53], K[53])
    II(c, d, a, b, chunk[10], S[54], K[54])
    II(b, c, d, a, chunk[ 1], S[55], K[55])
    II(a, b, c, d, chunk[ 8], S[56], K[56])
    II(d, a, b, c, chunk[15], S[57], K[57])
    II(c, d, a, b, chunk[ 6], S[58], K[58])
    II(b, c, d, a, chunk[13], S[59], K[59])
    II(a, b, c, d, chunk[ 4], S[60], K[60])
    II(d, a, b, c, chunk[11], S[61], K[61])
    II(c, d, a, b, chunk[ 2], S[62], K[62])
    II(b, c, d, a, chunk[ 9], S[63], K[63])

    state[0] += a
    state[1] += b
    state[2] += c
    state[3] += d

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
  var i: int = 0
  let inputLen: int = input.len

  when Bits == 64:
    var index: int = int((ctx.count shr 3) and 0x3F'u64)
    ctx.count += uint64(inputLen) shl 3
  else:
    var index: int = int((ctx.count[0] shr 3) and 0x3F'u32)
    ctx.count[0] += uint32(inputLen shl 3)
    if ctx.count[0] < uint32(inputLen shl 3):
      ctx.count[1] += 1 # 0
    ctx.count[1] += uint32(inputLen shr 29)

  let partLen: int = 64 - index

  if inputLen >= partLen:
    for i in 0 ..< partLen:
      ctx.buffer[index + i] = input[i]

    when cpuEndian == littleEndian:
      md5Transform(ctx.state, cast[ptr UncheckedArray[uint8]](addr ctx.buffer[0]))
    else:
      md5Transform(ctx.state, ctx.buffer)


    i = partLen

    while i + 63 < inputLen:
      when cpuEndian == littleEndian:
        md5Transform(ctx.state, cast[ptr UncheckedArray[uint8]](unsafeAddr input[i]))
      else:
        md5Transform(ctx.state, input.toOpenArray(i, i+63))
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
    var index: uint32 = uint32((ctx.count shr 3) and 0x3F'u64)
  else:
    var index: uint32 = (ctx.count[0] shr 3) and 0x3F'u32

  ctx.buffer[index] = 0x80'u8
  index.inc

  let padLen = if index < 56: 56 - index else: 64 - index

  if index < 56:
    zeroMem(addr ctx.buffer[index], padLen)
  else:
    zeroMem(addr ctx.buffer[index], padLen)
    when cpuEndian == littleEndian:
      md5Transform(ctx.state, cast[ptr UncheckedArray[uint8]](addr ctx.buffer[0]))
    else:
      md5Transform(ctx.state, ctx.buffer)
    zeroMem(addr ctx.buffer[0], 56)

  for i in static(0 ..< 8):
    ctx.buffer[56 + i] = bits[i]

  when cpuEndian == littleEndian:
    md5Transform(ctx.state, cast[ptr UncheckedArray[uint8]](addr ctx.buffer[0]))
  else:
    md5Transform(ctx.state, ctx.buffer)
  encodeLE(ctx.state, output)

  output

# export wrappers
when defined(templateOpt):
  template md5Init*(ctx: var MD5Ctx): void =
    md5InitC(ctx)
  template md5Input*(ctx: var MD5Ctx, input: lent openArray[uint8]): void =
    md5InputC(ctx, input)
  template md5Final*(ctx: var MD5Ctx): array[16, uint8] =
    md5FinalC(ctx)
  template md5One*(input: lent openArray[uint8]): array[16, uint8] =
    md5OneC(input)
else:
  proc md5Init*(ctx: var MD5Ctx): void =
    md5InitC(ctx)
  proc md5Input*(ctx: var MD5Ctx, input: openArray[uint8]): void =
    md5InputC(ctx, input)
  proc md5Final*(ctx: var MD5Ctx): array[16, uint8] =
    md5FinalC(ctx)
  proc md5One*(input: openArray[uint8]): array[16, uint8] =
    md5OneC(input)

when defined(test):
  var s: seq[uint8] = charToBin("Hello, World!")
  var ctx: MD5Ctx
  md5Init(ctx)
  md5Input(ctx, s)
  echo "MD5Stream : ", binToHex(md5Final(ctx))
  echo "MD5One : ", binToHex(md5One(s))
  echo "MD5 Standard : 65A8E27D8879283831B664BD8B7F0AD4"
  echo "Input : Hello, World!"
  template benchmark(name: string, code: untyped) =
    let start = getMonoTime()
    code
    let elapsed = getMonoTime() - start
    echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"
  var a: array[16, uint8]
  var ctx2: MD5Ctx
  md5Init(ctx2)
  benchmark("MD5 Benchamark"):
    for i in 1 .. 1_000_000:
      md5Input(ctx2, a)
      a = md5Final(ctx2)
