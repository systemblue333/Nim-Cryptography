import strutils
import sequtils
import ../../../../Utility/src/Utility/codeutils/indexutils
import ../../../../Utility/src/Utility/codeutils/bits
import ../../../../Utility/src/Utility/codeutils/errorutils
import ../../../../Utility/src/Utility/dataformat/dataformat
import std/[monotimes, times]
import bitops

# CPU's bits constant
const
  Bits*: int = sizeof(int) * 8

when Bits == 64:
  # SHA-1 context for 64 bits
  type
    SHA1Ctx* = object
      state*: array[5, uint32]
      bitLength*: uint64
      index*: int
      buffer*: array[64, uint8]
      computed*: bool
elif Bits == 32:
  # SHA-1 context for 32/lower bits
  type
    SHA1Ctx* = object
      state*: array[5, uint32]
      bitLength*: array[2, uint32]
      index*: int
      buffer*: array[64, uint8]
      computed*: bool

# common sha1 operating process template
template sha1Transform(state: var array[5, uint32], input: lent openArray[uint8]): void =
  # declare extended chunk
  var w: array[80, uint32]

  # decode chunk to extended chunk(w)
  decodeBE(input, w.toOpenArray(0, 15), 16)

  # extend w
  for i in static(16..<80):
    w[i] = rotateLeftBits(w[i-3] xor w[i-8] xor w[i-14] xor w[i-16], 1)

  # declare and initialize temporary variables
  var a: uint32 = state[0]
  var b: uint32 = state[1]
  var c: uint32 = state[2]
  var d: uint32 = state[3]
  var e: uint32 = state[4]

  # round loop : 80
  for i in static(0 ..< 80):
    var f: uint32
    var k: uint32

    if i <= 19:
      f = (b and c) xor ((not b) and d)
      k = 0x5a827999'u32
    elif i <= 39:
      f = b xor c xor d
      k = 0x6ed9eba1'u32
    elif i <= 59:
      f = (b and c) xor (b and d) xor (c and d)
      k = 0x8f1bbcdc'u32
    elif i <= 79:
      f = b xor c xor d
      k = 0xca62c1d6'u32

    let temp = rotateLeftBits(a, 5) + f + e + k + w[i]
    e = d
    d = c
    c = rotateLeftBits(b, 30)
    b = a
    a = temp

  # assign and add temporary variables to state
  state[0] += a
  state[1] += b
  state[2] += c
  state[3] += d
  state[4] += e

# initialize sha1 context
template sha1InitC(ctx: var SHA1Ctx): void =
  when Bits == 64:
    ctx.bitLength = 0x00'u64
  elif Bits == 32:
    ctx.bitLength[0] = 0x00'u32
    ctx.bitLength[1] = 0x00'u32

  ctx.state[0] = 0x67452301'u32
  ctx.state[1] = 0xEFCDAB89'u32
  ctx.state[2] = 0x98BADCFE'u32
  ctx.state[3] = 0x10325476'u32
  ctx.state[4] = 0xC3D2E1F0'u32

  ctx.computed = false
  ctx.index = 0

  for i in static(0 ..< 64):
    ctx.buffer[i] = 0

# one-shot sha1 core
template sha1OneC(input: lent openArray[uint8]): array[20, uint8] =
  # declare output
  var output: array[20, uint8]
  # declare buffer
  let totalLen = ((input.len + 9 + 63) div 64) * 64
  var buffer: seq[uint8] = newSeq[uint8](totalLen)
  # declare and initialize index
  var index: int = input.len
  # copy input to buffer
  for i in 0 ..< input.len:
    buffer[i] = input[i]
  # declare and initialize state
  var state: array[5, uint32] = [0x67452301'u32, 0xefcdab89'u32, 0x98badcfe'u32, 0x10325476'u32, 0xC3D2E1F0'u32]

  # append '1' bit -> 0x80
  buffer[index] = 0x80'u8
  index += 1

  # append '0' bits until index mod 64 == 56
  while (index mod 64) != 56:
    buffer[index] = 0x00'u8
    index += 1

  let bitLen = uint64(input.len) * 8
  for i in static(0 ..< 8):
    buffer[index + i] = uint8((bitLen shr ((7 - i) * 8)) and 0xFF)

  # break chunk 512bits
  for chunkStart in countup(0, buffer.len - 64, 64):
    sha1Transform(state, buffer[chunkStart..<chunkStart + 64])

  # encode state to output
  encodeBE(state, output)

  output

# sha1 input core
template sha1InputC(ctx: var SHA1Ctx, input: openArray[uint8]): void =
  # declare check variables
  var check: bool = true
  # check computed state and input length
  if ctx.computed or input.len == 0:
    check = false

  if check:
    # declare and initialize constant and index
    var index: int = 0
    let inputLen: int = input.len

    # add input bit length to ctx.bitLength
    # 64 bits version
    when Bits == 64:
      ctx.bitLength += uint64(inputLen shl 3)
    # 32/lower bits version
    else:
      let oldLow = ctx.bitLength[0]
      ctx.bitLength[0] += uint32((inputLen shl 3) and 0xFFFFFFFF'u32)
      if ctx.bitLength[0] < oldLow:
        ctx.bitLength[1] += 1
      ctx.bitLength[1] += uint32((inputLen shl 3) shr 32)

    if ctx.index > 0:
      let space: int = 64 - ctx.index
      let fill: int = min(inputLen, space)

      copyMem(addr ctx.buffer[ctx.index], addr input[0], fill)

      if ctx.index == 64:
        sha1Transform(ctx.state, ctx.buffer)
        ctx.index = 0

      while index <= inputLen - 64:
        sha1Transform(ctx.state, input.toOpenArray(index, index + 63))
        index += 64

    let rem = inputLen - index
    if rem > 0:
      copyMem(addr ctx.buffer[0], unsafeAddr input[index], rem)
      ctx.index = rem

# sha1 finalize core
template sha1FinalC(ctx: var SHA1Ctx): array[20, uint8] =
  var check: bool = true
  var output: array[20, uint8]

  # check computed state and encode
  if ctx.computed:
    encodeBE(ctx.state, output)
    check = false

  if check:
    # do padding(add 0x80 and zero)
    ctx.buffer[ctx.index] = 0x80
    ctx.index += 1

    # if messageBlockIndex is bigger then 56
    if ctx.index > 56:
      # add 0 while messageBlockIndex is smaller then 64
      while ctx.index < 64:
        ctx.buffer[ctx.index] = 0
        ctx.index += 1
      # call process
      sha1Transform(ctx.state, ctx.buffer)
      ctx.index = 0

    # add 0 whil messageBlockIndex is smaller then 56
    while ctx.index < 56:
      ctx.buffer[ctx.index] = 0
      ctx.index += 1

    # add bit length to end by big endian
    when Bits == 64:
      for i in static(0 ..< 8):
        ctx.buffer[56 + i] = uint8(ctx.bitLength shr ((7 - i) * 8) and 0xFF)
    else:
      for i in static(0 ..< 4):
        ctx.buffer[56 + i] = uint8(ctx.bitLength[0] shr ((3 - i) * 8) and 0xFF)
      for i in static(0 ..< 4):
        ctx.buffer[60 + i] = uint8(ctx.bitLength[1] shr ((3 - i) * 8) and 0xFF)

    # process and encoding part
    sha1Transform(ctx.state, ctx.buffer)
    ctx.computed = true

    # encode state to output
    encodeBE(ctx.state, output)

  output

# export wrappers
when defined(templateOpt):
  template sha1Init*(ctx: var SHA1Ctx): void =
    sha1InitC(ctx)
  template sha1Input*(ctx: var SHA1Ctx, input: lent openArray[uint8]): void =
    sha1InputC(ctx, input)
  template sha1Final*(ctx: var SHA1Ctx): array[20, uint8] =
    sha1FinalC(ctx)
  template sha1One*(input: lent openArray[uint8]): array[20, uint8] =
    sha1OneC(input)
else:
  proc sha1Init*(ctx: var SHA1Ctx): void =
    sha1InitC(ctx)
  proc sha1Input*(ctx: var SHA1Ctx, input: openArray[uint8]): void =
    sha1InputC(ctx, input)
  proc sha1Final*(ctx: var SHA1Ctx): array[20, uint8] =
    sha1FinalC(ctx)
  proc sha1One*(input: openArray[uint8]): array[20, uint8] =
    sha1OneC(input)

when defined(test):
  var s: seq[uint8] = charToBin("Hello, World!")
  var ctx: SHA1Ctx
  sha1Init(ctx)
  sha1Input(ctx, s)
  echo "SHA1Stream : ", binToHex(sha1Final(ctx))
  echo "SHA1One : ", binToHex(sha1One(s))
  echo "SHA1 Standard : 0A0A9F2A6772942557AB5355D76AF442F8F65E01"
  echo "Input : Hello, World!"

  template benchmark(name: string, code: untyped) =
    let start = getMonoTime()
    code
    let elapsed = getMonoTime() - start
    echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"
  var a: array[20, uint8]
  var ctx2: SHA1Ctx
  benchmark("SHA-1 Benchamark"):
    for i in 1 .. 1_000_000:
      sha1Init(ctx2)
      sha1Input(ctx2, a)
      a = sha1Final(ctx2)
