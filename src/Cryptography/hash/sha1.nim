import strutils
import sequtils
import ../../../../Utility/src/Utility/codeutils/indexutils
import ../../../../Utility/src/Utility/codeutils/bits
import ../../../../Utility/src/Utility/codeutils/errorutils
import ../../../../Utility/src/Utility/dataformat/dataformat

# common sha1 operating process template
template process(chunk: lent array[64, uint8], V: var array[5, uint32]): void =
  var w: array[80, uint32]

  for i in static(0 ..< 16):
    let j = i * 4
    w[i] = (uint32(chunk[j]) shl 24) or
    (uint32(chunk[j + 1]) shl 16) or
    (uint32(chunk[j + 2]) shl 8) or
    uint32(chunk[j + 3])

  for i in static(16..<80):
    w[i] = leftRotate(w[i-3] xor w[i-8] xor w[i-14] xor w[i-16], 1)

  var h: array[5, uint32]
  copyArray(V, h)

  const
    A = 0
    B = 1
    C = 2
    D = 3
    E = 4

  for i in static(0 ..< 80):
    var f: uint32
    var k: uint32

    if i <= 19:
      f = (h[B] and h[C]) or ((not h[B]) and h[D])
      k = 0x5a827999'u32
    elif i <= 39:
      f = h[B] xor h[C] xor h[D]
      k = 0x6ed9eba1'u32
    elif i <= 59:
      f = (h[B] and h[C]) or (h[B] and h[D]) or (h[C] and h[D])
      k = 0x8f1bbcdc'u32
    elif i <= 79:
      f = h[B] xor h[C] xor h[D]
      k = 0xca62c1d6'u32

    let temp = leftRotate(h[A], 5) + f + h[E] + k + w[i]
    h[E] = h[D]
    h[D] = h[C]
    h[C] = leftRotate(h[B], 30)
    h[B] = h[A]
    h[A] = temp

  V[0] += h[A]
  V[1] += h[B]
  V[2] += h[C]
  V[3] += h[D]
  V[4] += h[E]

# one-shot sha1 core
template sha1OneC(msg: lent openArray[uint8]): array[20, uint8] =
  var output: array[20, uint8]
  var input: seq[uint8]
  for i in 0 ..< msg.len:
    input.add(msg[i])
  var V: array[5, uint32] = [0x67452301'u32, 0xefcdab89'u32, 0x98badcfe'u32, 0x10325476'u32, 0xC3D2E1F0'u32]

  # bit len of msg
  let ml: int = input.len * 8

  # 1. append '1' bit -> 0x80
  input.add(0x80'u8)

  # 2. append '0' bits until length = 448 mod 512
  while ((input.len * 8) mod 512) != 448:
    input.add(0x00'u8)

  for i in countdown(7, 0):
    input.add(uint8((ml shr (i * 8)) and 0xFF))

  # break chunk 512bits
  for chunkStart in countup(0, input.len - 64, 64):
    var buffer: seq[uint8] = input[chunkStart ..< chunkStart + 64]
    var chunk: array[64, uint8]
    toArray(buffer, chunk)

    process(chunk, V)

  encodeBE(V, output)

  output

const
  Bits*: int = sizeof(int) * 8


when Bits == 64:
  type
    SHA1Ctx* = object
      intermediateHash*: array[5, uint32]
      bitLength*: uint64
      messageBlockIndex*: int
      messageBlock*: array[64, uint8]
      computed*: bool
else:
  type
    SHA1Ctx* = object
      intermediateHash*: array[5, uint32]
      bitLength*: array[2, uint32]
      messageBlockIndex*: int
      messageBlock*: array[64, uint8]
      computed*: bool

# initialize sha1 ctx
template sha1InitC(ctx: var SHA1Ctx): void =
  ctx.bitLength = 0
  ctx.messageBlockIndex = 0
  ctx.intermediateHash[0] = 0x67452301'u32
  ctx.intermediateHash[1] = 0xefcdab89'u32
  ctx.intermediateHash[2] = 0x98badcfe'u32
  ctx.intermediateHash[3] = 0x10325476'u32
  ctx.intermediateHash[4] = 0xc3d2e1f0'u32
  ctx.computed = false

# sha1 input core
template sha1InputC(ctx: var SHA1Ctx, input: openArray[uint8]): void =
  var isValid: bool = true
  # check computed state and input length
  if ctx.computed or input.len == 0:
    isValid = false

  if isValid:
    var index: int = 0
    let length: int= input.len

    while index < length:
      let space: int = 64 - ctx.messageBlockIndex
      let fill: int = min(length - index, space)

      copyMem(addr ctx.messageBlock[ctx.messageBlockIndex], addr input[index], fill)

      let fillBits: uint64 = fill.uint64 shl 3

      when Bits == 64:
        ctx.bitLength += uint64(fill * 8)
      else:
        let oldLow = ctx.bitLength[0]
        ctx.bitLength[0] += uint32(fillBits and 0xFFFFFFFF'u64)

        if ctx.bitLength[0] < oldLow:
          ctx.bitLength[1] += 1
        ctx.bitLength[1] = uint32(fillBits shr 32)

      ctx.messageBlockIndex += fill

      index += fill

      if ctx.messageBlockIndex == 64:
        process(ctx.messageBlock, ctx.intermediateHash)
        ctx.messageBlockIndex = 0

# sha1 finalize core
template sha1FinalC(ctx: var SHA1Ctx): array[20, uint8] =
  var isValid: bool = true
  var output: array[20, uint8]

  # check computed state and encode
  if ctx.computed:
    encodeBE(ctx.intermediateHash, output)
    isValid = false

  if isValid:
    # do padding(add 0x80 and zero)
    ctx.messageBlock[ctx.messageBlockIndex] = 0x80'u8
    ctx.messageBlockIndex += 1

    if ctx.messageBlockIndex > 56:
      while ctx.messageBlockIndex < 64:
        ctx.messageBlock[ctx.messageBlockIndex] = 0
        ctx.messageBlockIndex += 1
      process(ctx.messageBlock, ctx.intermediateHash)
      ctx.messageBlockIndex = 0

    while ctx.messageBlockIndex < 56:
      ctx.messageBlock[ctx.messageBlockIndex] = 0
      ctx.messageBlockIndex += 1

    # add bit length by big endian
    # don't use bits.nim because of performance and memory layout
    ctx.messageBlock[56] = uint8(ctx.bitLength shr 56)
    ctx.messageBlock[57] = uint8(ctx.bitLength shr 48)
    ctx.messageBlock[58] = uint8(ctx.bitLength shr 40)
    ctx.messageBlock[59] = uint8(ctx.bitLength shr 32)
    ctx.messageBlock[60] = uint8(ctx.bitLength shr 24)
    ctx.messageBlock[61] = uint8(ctx.bitLength shr 16)
    ctx.messageBlock[62] = uint8(ctx.bitLength shr 8)
    ctx.messageBlock[63] = uint8(ctx.bitLength)

    # process and encoding part
    process(ctx.messageBlock, ctx.intermediateHash)
    ctx.computed = true

    encodeBE(ctx.intermediateHash, output)

  output

# export wrappers
when defined(templateOpt):
  template sha1Init*(ctx: var SHA1Ctx): void =
    sha1InitC(ctx)
  template sha1Input*(ctx: var SHA1Ctx, input: lent openArray[uint8]): void =
    sha1InputC(ctx, input)
  when defined(varOpt):
    template sha1Fianl*(ctx: var SHA1Ctx, output: var array[20, uint8]): void =
      output = sha1FinalC(ctx)
    template sha1One*(input: lent openArray[uint8], output: var array[20, uint8]): void =
      output = sha1OneC(input)
  else:
    template sha1Final*(ctx: var SHA1Ctx): array[20, uint8] =
      sha1FinalC(ctx)
    template sha1One*(input: lent openArray[uint8]): array[20, uint8] =
      sha1OneC(input)
else:
  proc sha1Init*(ctx: var SHA1Ctx): void =
    sha1InitC(ctx)
  proc sha1Input*(ctx: var SHA1Ctx, input: openArray[uint8]): void =
    sha1InputC(ctx, input)
  when defined(varOpt):
    proc sha1Fianl*(ctx: var SHA1Ctx, output: var array[20, uint8]): void =
      output = sha1FinalC(ctx)
    proc sha1One*(input: openArray[uint8], output: var array[20, uint8]): void =
      output = sha1OneC(input)
  else:
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
