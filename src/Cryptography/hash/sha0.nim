import strutils
import sequtils
import ../../../../Utility/src/Utility/codeutils/indexutils
import ../../../../Utility/src/Utility/codeutils/bits
import ../../../../Utility/src/Utility/codeutils/errorutils
import ../../../../Utility/src/Utility/dataformat/dataformat

# common sha0 operating process template
template process(chunk: lent openArray[uint8], state: var array[5, uint32]): void =
  # declare extended chunk
  var w: array[80, uint32]

  # copy chunk to extended chunk(w)
  discard decodeBE(chunk, w.toOpenArray(0, 15), 16)

  # extend chunk to extended chunk
  for i in static(16..<80):
    w[i] = w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]

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

    let temp = leftRotate(a, 5) + f + e + k + w[i]
    e = d
    d = c
    c = leftRotate(b, 30)
    b = a
    a = temp

  # assign and add temporary variable to state
  state[0] += a
  state[1] += b
  state[2] += c
  state[3] += d
  state[4] += e

# one-shot sha0 core
template sha0OneC(input: lent openArray[uint8]): array[20, uint8] =
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
    process(buffer[chunkStart..<chunkStart + 64], state)

  # encode state to output
  encodeBE(state, output)

  output

# CPU's bits constant
const
  Bits*: int = sizeof(int) * 8


when Bits == 64:
  # SHA-0 context for 64 bits
  type
    SHA0Ctx* = object
      intermediateHash*: array[5, uint32]
      bitLength*: uint64
      messageBlockIndex*: int
      messageBlock*: array[64, uint8]
      computed*: bool
else:
  # SHA-0 context for 32 or lower bits
  type
    SHA0Ctx* = object
      intermediateHash*: array[5, uint32]
      bitLength*: array[2, uint32]
      messageBlockIndex*: int
      messageBlock*: array[64, uint8]
      computed*: bool

# sha0 init core
template sha0InitC(ctx: var SHA0Ctx): void =
  when Bits == 64:
    ctx.bitLength = 0
  else:
    for i in static(0 ..< 2):
      bitLength[i] = 0
  ctx.messageBlockIndex = 0
  ctx.intermediateHash[0] = 0x67452301'u32
  ctx.intermediateHash[1] = 0xefcdab89'u32
  ctx.intermediateHash[2] = 0x98badcfe'u32
  ctx.intermediateHash[3] = 0x10325476'u32
  ctx.intermediateHash[4] = 0xc3d2e1f0'u32
  ctx.computed = false

# sha0 input core
template sha0InputC(ctx: var SHA0Ctx, input: openArray[uint8]): void =
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

    if ctx.messageBlockIndex > 0:
      let space: int = 64 - ctx.messageBlockIndex
      let fill: int = min(inputLen, space)

      copyMem(addr ctx.messageBlock[ctx.messageBlockIndex], addr input[0], fill)

      if ctx.messageBlockIndex == 64:
        process(ctx.messageBlock, ctx.intermediateHash)
        ctx.messageBlockIndex = 0

      while index <= inputLen - 64:
        process(input.toOpenArray(index, index + 63), ctx.intermediateHash)
        index += 64

    let rem = inputLen - index
    if rem > 0:
      copyMem(addr ctx.messageBlock[0], unsafeAddr input[index], rem)
      ctx.messageBlockIndex = rem

# sha0 finalize core
template sha0FinalC(ctx: var SHA0Ctx): array[20, uint8] =
  var check: bool = true
  var output: array[20, uint8]

  # check computed state and encode
  if ctx.computed:
    encodeBE(ctx.intermediateHash, output)
    check = false

  if check:
    # do padding(add 0x80 and zero)
    ctx.messageBlock[ctx.messageBlockIndex] = 0x80
    ctx.messageBlockIndex += 1

    # if messageBlockIndex is bigger then 56
    if ctx.messageBlockIndex > 56:
      # add 0 while messageBlockIndex is smaller then 64
      while ctx.messageBlockIndex < 64:
        ctx.messageBlock[ctx.messageBlockIndex] = 0
        ctx.messageBlockIndex += 1
      # call process
      process(ctx.messageBlock, ctx.intermediateHash)
      ctx.messageBlockIndex = 0

    # add 0 whil messageBlockIndex is smaller then 56
    while ctx.messageBlockIndex < 56:
      ctx.messageBlock[ctx.messageBlockIndex] = 0
      ctx.messageBlockIndex += 1

    # add bit length to end by big endian
    when Bits == 64:
      for i in static(0 ..< 8):
        ctx.messageBlock[56 + i] = uint8(ctx.bitLength shr ((7 - i) * 8) and 0xFF)
    else:
      for i in static(0 ..< 4):
        ctx.messageBlock[56 + i] = uint8(ctx.bitLength[0] shr ((7 - i) * 8) and 0xFF)
      for i in static(4 ..< 8):
        ctx.messageBlock[56 + i] = uint8(ctx.bitLength[1] shr ((7 - i) * 8) and 0xFF)

    # process and encoding part
    process(ctx.messageBlock, ctx.intermediateHash)
    ctx.computed = true

    # encode intermediateHash to output
    encodeBE(ctx.intermediateHash, output)

  output

# export wrappers
when defined(templateOpt):
  template sha0Init*(ctx: var SHA0Ctx): void =
    sha0InitC(ctx)
  template sha0Input*(ctx: var SHA0Ctx, input: lent openArray[uint8]): void =
    sha0InputC(ctx, input)
  template sha0Final*(ctx: var SHA0Ctx): array[20, uint8] =
    sha0FinalC(ctx)
  template sha0One*(input: lent openArray[uint8]): array[20, uint8] =
    sha0OneC(input)
else:
  proc sha0Init*(ctx: var SHA0Ctx): void =
    sha0InitC(ctx)
  proc sha0Input*(ctx: var SHA0Ctx, input: openArray[uint8]): void =
    sha0InputC(ctx, input)
  proc sha0Final*(ctx: var SHA0Ctx): array[20, uint8] =
    sha0FinalC(ctx)
  proc sha0One*(input: openArray[uint8]): array[20, uint8] =
    sha0OneC(input)

when defined(test):
  var s: seq[uint8] = charToBin("Hello, World!")
  var ctx: SHA0Ctx
  sha0Init(ctx)
  sha0Input(ctx, s)
  echo "SHA0Stream : ", binToHex(sha0Final(ctx))
  echo "SHA0One : ", binToHex(sha0One(s))
  echo "SHA0 Standard : 5A5588F0407C6AE9A988758E76965F841B299229"
  echo "Input : Hello, World!"
