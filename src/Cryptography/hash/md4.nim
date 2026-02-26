import ../../../../Utility/src/Utility/codeutils/indexutils
import ../../../../Utility/src/Utility/codeutils/bits
import ../../../../Utility/src/Utility/codeutils/errorutils
import ../../../../Utility/src/Utility/dataformat/dataformat
import std/[monotimes, times]
import std/bitops

# CPU's bits constant
const
  Bits*: int = sizeof(int) * 8

when Bits == 64:
  # md4 context for 64 bits
  type
    MD4Ctx* = object
      state*: array[4, uint32]
      length*: uint64
      buffer*: array[64, uint8]
elif Bits == 32:
  # md4 context for 32 bits
  type
    MD4Ctx* = object
      state*: array[4, uint32]
      length*: array[2, uint32]
      buffer*: array[64, uint8]
else:
  # md4 context for 8/16 bits
  type
    MD4Ctx* = object
      state*: array[16, uint8]
      length*: array[8, uint8]
      buffer*: array[64, uint8]

# Padding : precalculated padding list
# block makes constant in compile time
const
  # rotate constant for FF round
  S1: array[4, uint32] = [3'u32, 7'u32, 11'u32, 19'u32]
  # rotate constant for GG round
  S2: array[4, uint32] = [3'u32, 5'u32, 9'u32, 13'u32]
  # rotate constant for HH round
  S3: array[4, uint32] = [3'u32, 9'u32, 11'u32, 15'u32]

  S: array[48, uint32] = [
  3'u32, 7'u32, 11'u32, 19'u32, 3'u32, 7'u32, 11'u32, 19'u32, 3'u32, 7'u32, 11'u32, 19'u32, 3'u32, 7'u32, 11'u32, 19'u32,
  3'u32, 5'u32, 9'u32, 13'u32, 3'u32, 5'u32, 9'u32, 13'u32, 3'u32, 5'u32, 9'u32, 13'u32, 3'u32, 5'u32, 9'u32, 13'u32,
  3'u32, 9'u32, 11'u32, 15'u32, 3'u32, 9'u32, 11'u32, 15'u32, 3'u32, 9'u32, 11'u32, 15'u32, 3'u32, 9'u32, 11'u32, 15'u32
  ]

  # state index for GG round
  GGIndex: array[16, int] = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
  # state index for HH round
  HHIndex: array[16, int] = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]

when Bits == 64 or Bits == 32:
  # declare F sub template
  template F(x, y, z: lent uint32): uint32 =
    (x and y) or ((not x) and z)

  # declare G sub template
  template G(x, y, z: lent uint32): uint32 =
    ((x and y) or ((x and z) or (y and z)))

  # declare H sub template
  template H(x, y, z: lent uint32): uint32 =
    (x xor y xor z)

  # declare FF round template
  template FF(a: var uint32, b, c, d, x, s: lent uint32): void =
    a += F(b, c, d) + x
    a = rotateLeftBits(a, s)

  # declare GG round template
  template GG(a: var uint32, b, c, d, x, s: lent uint32): void =
    a += G(b, c, d) + x + 0x5a827999'u32
    a = rotateLeftBits(a, s)

  # declare HH round template
  template HH(a: var uint32, b, c, d, x, s: lent uint32): void =
    a += H(b, c, d) + x + 0x6ed9eba1'u32
    a = rotateLeftBits(a, s)

  # md4 init core
  template md4InitC(ctx: var MD4Ctx): void =
    when Bits == 64:
      ctx.length = 0'u64
    elif Bits == 32:
      ctx.length[0] = 0'u32
      ctx.length[1] = 0'u32

    # initialize state by initialize vector
    ctx.state[0] = 0x67452301'u32
    ctx.state[1] = 0xefcdab89'u32
    ctx.state[2] = 0x98badcfe'u32
    ctx.state[3] = 0x10325476'u32

    # initialize buffer
    for i in static(0 ..< 64):
      ctx.buffer[i] = 0x00'u8

  # md4 transform part for pointer little endian
  when cpuEndian == littleEndian:
    template md4TransformP(state: var array[4, uint32], input: ptr UncheckedArray[uint8]): void =
      var chunk: ptr UncheckedArray[uint32] = cast[ptr UncheckedArray[uint32]](input)

      # declare and initialize temporary variables
      var a: uint32 = state[0]
      var b: uint32 = state[1]
      var c: uint32 = state[2]
      var d: uint32 = state[3]

      # call FF round template
      FF(a, b, c, d, chunk[ 0], S[ 0])
      FF(d, a, b, c, chunk[ 1], S[ 1])
      FF(c, d, a, b, chunk[ 2], S[ 2])
      FF(b, c, d, a, chunk[ 3], S[ 3])
      FF(a, b, c, d, chunk[ 4], S[ 4])
      FF(d, a, b, c, chunk[ 5], S[ 5])
      FF(c, d, a, b, chunk[ 6], S[ 6])
      FF(b, c, d, a, chunk[ 7], S[ 7])
      FF(a, b, c, d, chunk[ 8], S[ 8])
      FF(d, a, b, c, chunk[ 9], S[ 9])
      FF(c, d, a, b, chunk[10], S[10])
      FF(b, c, d, a, chunk[11], S[11])
      FF(a, b, c, d, chunk[12], S[12])
      FF(d, a, b, c, chunk[13], S[13])
      FF(c, d, a, b, chunk[14], S[14])
      FF(b, c, d, a, chunk[15], S[15])

      # call GG round template
      GG(a, b, c, d, chunk[ 0], S[16])
      GG(d, a, b, c, chunk[ 4], S[17])
      GG(c, d, a, b, chunk[ 8], S[18])
      GG(b, c, d, a, chunk[12], S[19])
      GG(a, b, c, d, chunk[ 1], S[20])
      GG(d, a, b, c, chunk[ 5], S[21])
      GG(c, d, a, b, chunk[ 9], S[22])
      GG(b, c, d, a, chunk[13], S[23])
      GG(a, b, c, d, chunk[ 2], S[24])
      GG(d, a, b, c, chunk[ 6], S[25])
      GG(c, d, a, b, chunk[10], S[26])
      GG(b, c, d, a, chunk[14], S[27])
      GG(a, b, c, d, chunk[ 3], S[28])
      GG(d, a, b, c, chunk[ 7], S[29])
      GG(c, d, a, b, chunk[11], S[30])
      GG(b, c, d, a, chunk[15], S[31])

      # call HH round template
      HH(a, b, c, d, chunk[ 0], S[32])
      HH(d, a, b, c, chunk[ 8], S[33])
      HH(c, d, a, b, chunk[ 4], S[34])
      HH(b, c, d, a, chunk[12], S[35])
      HH(a, b, c, d, chunk[ 2], S[36])
      HH(d, a, b, c, chunk[10], S[37])
      HH(c, d, a, b, chunk[ 6], S[38])
      HH(b, c, d, a, chunk[14], S[39])
      HH(a, b, c, d, chunk[ 1], S[40])
      HH(d, a, b, c, chunk[ 9], S[41])
      HH(c, d, a, b, chunk[ 5], S[42])
      HH(b, c, d, a, chunk[13], S[43])
      HH(a, b, c, d, chunk[ 3], S[44])
      HH(d, a, b, c, chunk[11], S[45])
      HH(c, d, a, b, chunk[ 7], S[46])
      HH(b, c, d, a, chunk[15], S[47])

      # add and assign temporary variables to
      state[0] += a
      state[1] += b
      state[2] += c
      state[3] += d

  # md4 transform part for big endian
  template md4Transform(state: var array[4, uint32], input: openArray[uint8]): void =
    # declare chunk
    var chunk: array[16, uint32]

    # decode input to chunk
    decodeLE(input, chunk, 16)

    # declare and initialize temporary variables
    var a: uint32 = state[0]
    var b: uint32 = state[1]
    var c: uint32 = state[2]
    var d: uint32 = state[3]

    # call FF round template
    FF(a, b, c, d, chunk[ 0], S[ 0])
    FF(d, a, b, c, chunk[ 1], S[ 1])
    FF(c, d, a, b, chunk[ 2], S[ 2])
    FF(b, c, d, a, chunk[ 3], S[ 3])
    FF(a, b, c, d, chunk[ 4], S[ 4])
    FF(d, a, b, c, chunk[ 5], S[ 5])
    FF(c, d, a, b, chunk[ 6], S[ 6])
    FF(b, c, d, a, chunk[ 7], S[ 7])
    FF(a, b, c, d, chunk[ 8], S[ 8])
    FF(d, a, b, c, chunk[ 9], S[ 9])
    FF(c, d, a, b, chunk[10], S[10])
    FF(b, c, d, a, chunk[11], S[11])
    FF(a, b, c, d, chunk[12], S[12])
    FF(d, a, b, c, chunk[13], S[13])
    FF(c, d, a, b, chunk[14], S[14])
    FF(b, c, d, a, chunk[15], S[15])

    # call GG round template
    GG(a, b, c, d, chunk[ 0], S[16])
    GG(d, a, b, c, chunk[ 4], S[17])
    GG(c, d, a, b, chunk[ 8], S[18])
    GG(b, c, d, a, chunk[12], S[19])
    GG(a, b, c, d, chunk[ 1], S[20])
    GG(d, a, b, c, chunk[ 5], S[21])
    GG(c, d, a, b, chunk[ 9], S[22])
    GG(b, c, d, a, chunk[13], S[23])
    GG(a, b, c, d, chunk[ 2], S[24])
    GG(d, a, b, c, chunk[ 6], S[25])
    GG(c, d, a, b, chunk[10], S[26])
    GG(b, c, d, a, chunk[14], S[27])
    GG(a, b, c, d, chunk[ 3], S[28])
    GG(d, a, b, c, chunk[ 7], S[29])
    GG(c, d, a, b, chunk[11], S[30])
    GG(b, c, d, a, chunk[15], S[31])

    # call HH round template
    HH(a, b, c, d, chunk[ 0], S[32])
    HH(d, a, b, c, chunk[ 8], S[33])
    HH(c, d, a, b, chunk[ 4], S[34])
    HH(b, c, d, a, chunk[12], S[35])
    HH(a, b, c, d, chunk[ 2], S[36])
    HH(d, a, b, c, chunk[10], S[37])
    HH(c, d, a, b, chunk[ 6], S[38])
    HH(b, c, d, a, chunk[14], S[39])
    HH(a, b, c, d, chunk[ 1], S[40])
    HH(d, a, b, c, chunk[ 9], S[41])
    HH(c, d, a, b, chunk[ 5], S[42])
    HH(b, c, d, a, chunk[13], S[43])
    HH(a, b, c, d, chunk[ 3], S[44])
    HH(d, a, b, c, chunk[11], S[45])
    HH(c, d, a, b, chunk[ 7], S[46])
    HH(b, c, d, a, chunk[15], S[47])

    # add and assign temporary variables to state
    state[0] += a
    state[1] += b
    state[2] += c
    state[3] += d

  # md4 input core
  template md4InputC(ctx: var MD4Ctx, input: lent openArray[uint8]): void =
    # set inputLen, index and add inputLen to ctx.length
    when Bits == 64:
      var inputLen: int = input.len
      var index: int = int(ctx.length and 0x3F'u64)
      ctx.length += inputLen.uint64
    elif Bits == 32:
      var index: int = int(ctx.length[0] and 0x3F'u32)
      var inputLen: int = input.len
      ctx.length[0] += inputLen.uint32
      if ctx.length[0] < inputLen.uint32:
        ctx.length[1] += 1

    # set partLen
    let partLen: int = 64 - index

    var i: int = 0

    if inputLen >= partLen:
      copyMem(addr ctx.buffer[index], unsafeAddr input[0], partLen)
      #for i in 0 ..< partLen:
      #  ctx.buffer[index + i] = input[i]
      # call md4 transform template
      when cpuEndian == littleEndian:
        md4TransformP(ctx.state, cast[ptr UncheckedArray[uint8]](addr ctx.buffer[0]))
      else:
        md4Transform(ctx.state, ctx.buffer)

      i = partLen
      # loop whil inputLen
      while i + 63 < inputLen:
        md4Transform(ctx.state, input[i..i+63])

        i += 64
      index = 0

    if i < inputLen:
      #for j in 0 ..< (inputLen - i):
      #  ctx.buffer[index + j] = input[i + j]
      copyMem(addr ctx.buffer[index], unsafeAddr input[i], inputLen - i)

  # md4 final core
  template md4FinalC(ctx: var MD4Ctx): array[16, uint8] =
    # declare output
    var output: array[16, uint8]

    # set index
    when Bits == 64:
      var index: int = int(ctx.length and 0x3F'u64)
    elif Bits == 32:
      var index: int = int(ctx.length[0] and 0x3F'u32)

    # add padding
    ctx.buffer[index] = 0x80'u8
    index.inc

    # set padding length
    let padLen: int = if index < 56: 56 - index else: 64 - index

    # if index is smaller then 56
    if index < 56:
      # zerofill buffer until 56
      zeroMem(addr ctx.buffer[index], padLen)
    else:
      # zerofill buffer until 64
      zeroMem(addr ctx.buffer[index], padLen)
      # call md4 transform template by endian
      when cpuEndian == littleEndian:
        md4TransformP(ctx.state, cast[ptr UncheckedArray[uint8]](addr ctx.buffer[0]))
      else:
        md4Transform(ctx.state, ctx.buffer)

      # zerofill buffer until 56
      zeroMem(addr ctx.buffer[0], 56)

    # multiple 8 to ctx.length and copy to ctx.buffer
    when Bits == 64:
      ctx.length = ctx.length shl 3
      discard toBytesLE(ctx.length, ctx.buffer.toOpenArray(56, 63))
    elif Bits == 32:
      ctx.length[1] = (ctx.length[0] shr 29) or (ctx.length[1] shl 3)
      ctx.length[0] = ctx.length[0] shl 3
      encodeLE(ctx.length, ctx.buffer.toOpenArray(56, 63), 8)

    #for i in static(0 ..< 8):
    #  ctx.buffer[56 + i] = bitLen[i]

    # call md4 transform template by endian
    when cpuEndian == littleEndian:
      md4TransformP(ctx.state, cast[ptr UncheckedArray[uint8]](addr ctx.buffer[0]))
    else:
      md4Transform(ctx.state, ctx.buffer)

    # encode state to output
    encodeLE(ctx.state, output)

    output

# export wrappers
when defined(templateOpt):
  template md4Init*(ctx: var MD4Ctx): void =
    md4InitC(ctx)
  template md4Input*(ctx: var MD4Ctx, input: lent openArray[uint8]): void =
    md4InputC(ctx, input)
  template md4Final*(ctx: var MD4Ctx): array[16, uint8] =
    md4FinalC(ctx)
else:
  proc md4Init*(ctx: var MD4Ctx): void =
    md4InitC(ctx)
  proc md4Input*(ctx: var MD4Ctx, input: openArray[uint8]): void =
    md4InputC(ctx, input)
  proc md4Final*(ctx: var MD4Ctx): array[16, uint8] =
    md4FinalC(ctx)

# test code
when defined(test):
  var s: seq[uint8] = charToBin("Hello, World!")
  var ctx: MD4Ctx
  md4Init(ctx)
  md4Input(ctx, s)
  echo "MD4Stream : ", binToHex(md4Final(ctx))
  echo "MD4 Standard : 94E3CB0FA9AA7A5EE3DB74B79E915989"
  echo "Input : Hello, World!"
  template benchmark(name: string, code: untyped) =
    let start = getMonoTime()
    code
    let elapsed = getMonoTime() - start
    echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"
  var a: array[16, uint8]
  var ctx2: MD4Ctx
  md4Init(ctx2)
  benchmark("MD4 Benchamark"):
    for i in 1 .. 1_000_000:
      md4Input(ctx2, a)
      a = md4Final(ctx2)
