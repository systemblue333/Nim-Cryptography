import strutils
import sequtils
import ../../../../Utility/src/Utility/codeutils/indexutils
import ../../../../Utility/src/Utility/codeutils/bits
import ../../../../Utility/src/Utility/codeutils/errorutils
import ../../../../Utility/src/Utility/dataformat/dataformat
import std/[monotimes, times]
import std/bitops


# declare s-box
const
  SBox: array[8, array[16, uint32]] = [
    [4'u32, 10'u32, 9'u32, 2'u32, 13'u32, 8'u32, 0'u32, 14'u32, 6'u32, 11'u32, 1'u32, 12'u32, 7'u32, 15'u32, 5'u32, 3'u32],
    [14'u32, 11'u32, 4'u32, 12'u32, 6'u32, 13'u32, 15'u32, 10'u32, 2'u32, 3'u32, 8'u32, 1'u32, 0'u32, 7'u32, 5'u32, 9'u32],
    [5'u32, 8'u32, 1'u32, 13'u32, 10'u32, 3'u32, 4'u32, 2'u32, 14'u32, 15'u32, 12'u32, 7'u32, 6'u32, 0'u32, 9'u32, 11'u32],
    [7'u32, 13'u32, 10'u32, 1'u32, 0'u32, 8'u32, 9'u32, 15'u32, 14'u32, 4'u32, 6'u32, 12'u32, 11'u32, 2'u32, 5'u32, 3'u32],
    [6'u32, 12'u32, 7'u32, 1'u32, 5'u32, 15'u32, 13'u32, 8'u32, 4'u32, 10'u32, 9'u32, 14'u32, 0'u32, 3'u32, 11'u32, 2'u32],
    [4'u32, 11'u32, 10'u32, 0'u32, 7'u32, 2'u32, 1'u32, 13'u32, 3'u32, 6'u32, 8'u32, 5'u32, 9'u32, 12'u32, 15'u32, 14'u32],
    [13'u32, 11'u32, 4'u32, 1'u32, 3'u32, 15'u32, 5'u32, 9'u32, 0'u32, 10'u32, 14'u32, 7'u32, 6'u32, 8'u32, 2'u32, 12'u32],
    [1'u32, 15'u32, 13'u32, 0'u32, 5'u32, 7'u32, 10'u32, 4'u32, 9'u32, 2'u32, 3'u32, 14'u32, 6'u32, 11'u32, 8'u32, 12'u32]
  ]

# declare GOST Hash context
type
  GOSTHashCtx* = object
    checksum*: array[8, uint32]
    state*: array[8, uint32]
    length*: array[8, uint32]
    buffer*: array[32, uint8]
    index*: int
    gostSbox1* {.align: 64.}: array[256, uint32]
    gostSbox2* {.align: 64.}: array[256, uint32]
    gostSbox3* {.align: 64.}: array[256, uint32]
    gostSbox4* {.align: 64.}: array[256, uint32]

# gost hash init core
template gostHashInitC*(ctx: var GOSTHashCtx): void =
  # initialise checksum, buffer, state
  zeroMem(addr ctx.checksum[0], 32)
  zeroMem(addr ctx.state[0], 32)
  zeroMem(addr ctx.buffer[0], 32)
  ctx.index = 0

  var i = 0

  # extend object S-Box by S-Box constant
  for a in static(0..15):
    let ax = SBox[1][a] shl 15
    let bx = SBox[3][a] shl 23
    var cx = SBox[5][a]
    cx = (cx shr 1) or (cx shl 31)
    let dx = SBox[7][a] shl 7

    for b in static(0..15):
      ctx.gostSbox1[i] = ax or (SBox[0][b] shl 11)
      ctx.gostSbox2[i] = bx or (SBox[2][b] shl 19)
      ctx.gostSbox3[i] = cx or (SBox[4][b] shl 27)
      ctx.gostSbox4[i] = dx or (SBox[6][b] shl 3)
      inc i

# gost encrypt round : performs a single Feistel round of GOST 28147-89
template gostEncryptRound(ctx: var GOSTHashCtx, k1, k2, right, left, temp: var uint32): void =
  # first half-round : process right and xor into left
  temp = k1 + right
  left = left xor (ctx.gostSbox1[temp and 0xff'u32] xor ctx.gostSbox2[(temp shr 8) and 0xff'u32] xor
           ctx.gostSbox3[(temp shr 16) and 0xff'u32] xor ctx.gostSbox4[temp shr 24])

  # second half-round : process left and xor into right
  temp = k2 + left
  right = right xor (ctx.gostSbox1[temp and 0xff'u32] xor ctx.gostSbox2[(temp shr 8) and 0xff'u32] xor
           ctx.gostSbox3[(temp shr 16) and 0xff'u32] xor ctx.gostSbox4[temp shr 24])

# gost encrypt : the full 32-round gost block cipher encryption
template gostEncrypt(ctx: var GOSTHashCtx, key: var array[8, uint32], right, left, temp: var uint32): void =
  # round 1 ~ 24 : eky is used in direct order (0 .. 7) three times
  gostEncryptRound(ctx, key[0], key[1], right, left, temp)
  gostEncryptRound(ctx, key[2], key[3], right, left, temp)
  gostEncryptRound(ctx, key[4], key[5], right, left, temp)
  gostEncryptRound(ctx, key[6], key[7], right, left, temp)
  gostEncryptRound(ctx, key[0], key[1], right, left, temp)
  gostEncryptRound(ctx, key[2], key[3], right, left, temp)
  gostEncryptRound(ctx, key[4], key[5], right, left, temp)
  gostEncryptRound(ctx, key[6], key[7], right, left, temp)
  gostEncryptRound(ctx, key[0], key[1], right, left, temp)
  gostEncryptRound(ctx, key[2], key[3], right, left, temp)
  gostEncryptRound(ctx, key[4], key[5], right, left, temp)
  gostEncryptRound(ctx, key[6], key[7], right, left, temp)

  # round 25 ~ 32 : key is used in reverse order (7 .. 0)
  gostEncryptRound(ctx, key[7], key[6], right, left, temp)
  gostEncryptRound(ctx, key[5], key[4], right, left, temp)
  gostEncryptRound(ctx, key[3], key[2], right, left, temp)
  gostEncryptRound(ctx, key[1], key[0], right, left, temp)

  # final swap of feistel halves
  temp = right
  right = left
  left = temp

# mixIter : a single iteration of the key transfromation and state encryption
template mixIter(ctx: var GOSTHashCtx, i: static[int], tempU, tempV, tempW, roundKey, state, sub: var array[8, uint32], right, left, temp: var uint32): void =
  # step 1 : generate tempW = tempU xor tempV
  tempW[0] = tempU[0] xor tempV[0]
  tempW[1] = tempU[1] xor tempV[1]
  tempW[2] = tempU[2] xor tempV[2]
  tempW[3] = tempU[3] xor tempV[3]
  tempW[4] = tempU[4] xor tempV[4]
  tempW[5] = tempU[5] xor tempV[5]
  tempW[6] = tempU[6] xor tempV[6]
  tempW[7] = tempU[7] xor tempV[7]

  # step 2 : transform w into the roundKey (bit-shuffling/interleaving)
  roundKey[0] = (tempW[0] and 0x000000ff'u32) or ((tempW[2] and 0x000000ff'u32) shl 8) or
           ((tempW[4] and 0x000000ff'u32) shl 16) or ((tempW[6] and 0x000000ff'u32) shl 24)
  roundKey[1] = ((tempW[0] and 0x0000ff00'u32) shr 8) or (tempW[2] and 0x0000ff00'u32) or
           ((tempW[4] and 0x0000ff00'u32) shl 8) or ((tempW[6] and 0x0000ff00'u32) shl 16)
  roundKey[2] = ((tempW[0] and 0x00ff0000'u32) shr 16) or ((tempW[2] and 0x00ff0000'u32) shr 8) or
           (tempW[4] and 0x00ff0000'u32) or ((tempW[6] and 0x00ff0000'u32) shl 8)
  roundKey[3] = ((tempW[0] and 0xff000000'u32) shr 24) or ((tempW[2] and 0xff000000'u32) shr 16) or
           ((tempW[4] and 0xff000000'u32) shr 8) or (tempW[6] and 0xff000000'u32)
  roundKey[4] = (tempW[1] and 0x000000ff'u32) or ((tempW[3] and 0x000000ff'u32) shl 8) or
           ((tempW[5] and 0x000000ff'u32) shl 16) or ((tempW[7] and 0x000000ff'u32) shl 24)
  roundKey[5] = ((tempW[1] and 0x0000ff00'u32) shr 8) or (tempW[3] and 0x0000ff00'u32) or
           ((tempW[5] and 0x0000ff00'u32) shl 8) or ((tempW[7] and 0x0000ff00'u32) shl 16)
  roundKey[6] = ((w[1] and 0x00ff0000'u32) shr 16) or ((tempW[3] and 0x00ff0000'u32) shr 8) or
           (tempW[5] and 0x00ff0000'u32) or ((tempW[7] and 0x00ff0000'u32) shl 8)
  roundKey[7] = ((tempW[1] and 0xff000000'u32) shr 24) or ((tempW[3] and 0xff000000'u32) shr 16) or
           ((tempW[5] and 0xff000000'u32) shr 8) or (tempW[7] and 0xff000000'u32)

  # step 3 : encrypt the current state slice with the derived roundKey
  right = state[i]
  left = state[i + 1]
  gostEncrypt(ctx, roundKey, right, left, temp)
  sub[i] = right
  sub[i + 1] = left

  # step 4 : update registers U and V for the next iteration
  when i != 6:
    temp = tempU[0] xor tempU[2]
    right = tempU[1] xor tempU[3]
    tempU[0] = tempU[2]
    tempU[1] = tempU[3]
    tempU[2] = tempU[4]
    tempU[3] = tempU[5]
    tempU[4] = tempU[6]
    tempU[5] = tempU[7]
    tempU[6] = temp
    tempU[7] = right

    # apply constant C to U during 3rd iteration(i == 2)
    when i == 2:
      tempU[0] = tempU[0] xor 0xff00ff00'u32
      tempU[1] = tempU[1] xor 0xff00ff00'u32
      tempU[2] = tempU[2] xor 0x00ff00ff'u32
      tempU[3] = tempU[3] xor 0x00ff00ff'u32
      tempU[4] = tempU[4] xor 0x00ffff00'u32
      tempU[5] = tempU[5] xor 0xff0000ff'u32
      tempU[6] = tempU[6] xor 0x000000ff'u32
      tempU[7] = tempU[7] xor 0xff00ffff'u32

    # transformation P (linear feedback shift on V)
    temp = tempV[0]
    right = tempV[2]
    tempV[0] = tempV[4]
    tempV[2] = tempV[6]
    tempV[4] = temp xor right
    tempV[6] = tempV[0] xor right
    temp = tempV[1]
    right = tempV[3]
    tempV[1] = tempV[5]
    tempV[3] = tempV[7]
    tempV[5] = temp xor right
    tempV[7] = tempV[1] xor right

# gost hash compress : the central compression function
template gosthashCompress*(ctx: var GOSTHashCtx, state: var array[8, uint32], chunk: array[8, uint32]): void =
  # declare variables
  var
    left, right, temp: uint32
    roundKey: array[8, uint32]
    sub: array[8, uint32]
    tempU, tempV, tempW: array[8, uint32]

  # U register starts as the current hash state
  tempU = state
  # V register starts as the message block
  tempV = chunk

  # perform 4 iterations of mixing to generate the internal 'sub' key
  mixIter(ctx, 0, tempU, tempV, tempW, roundKey, state, sub, right, left, temp)
  mixIter(ctx, 2, tempU, tempV, tempW, roundKey, state, sub, right, left, temp)
  mixIter(ctx, 4, tempU, tempV, tempW, roundKey, state, sub, right, left, temp)
  mixIter(ctx, 6, tempU, tempV, tempW, roundKey, state, sub, right, left, temp)

  # step 5 : apply the 'psi' transformation to the 'sub' key
  tempU[0] = chunk[0] xor sub[6]
  tempU[1] = chunk[1] xor sub[7]
  tempU[2] = chunk[2] xor (sub[0] shl 16) xor (sub[0] shr 16) xor (sub[0] and 0xffff'u32) xor
         (sub[1] and 0xffff'u32) xor (sub[1] shr 16) xor (sub[2] shl 16) xor sub[6] xor (sub[6] shl 16) xor
         (sub[7] and 0xffff0000'u32) xor (sub[7] shr 16)
  tempU[3] = chunk[3] xor (sub[0] and 0xffff'u32) xor (sub[0] shl 16) xor (sub[1] and 0xffff'u32) xor
         (sub[1] shl 16) xor (sub[1] shr 16) xor (sub[2] shl 16) xor (sub[2] shr 16) xor
         (sub[3] shl 16) xor sub[6] xor (sub[6] shl 16) xor (sub[6] shr 16) xor (sub[7] and 0xffff'u32) xor
         (sub[7] shl 16) xor (sub[7] shr 16)
  tempU[4] = chunk[4] xor
         (sub[0] and 0xffff0000'u32) xor (sub[0] shl 16) xor (sub[0] shr 16) xor
         (sub[1] and 0xffff0000'u32) xor (sub[1] shr 16) xor (sub[2] shl 16) xor (sub[2] shr 16) xor
         (sub[3] shl 16) xor (sub[3] shr 16) xor (sub[4] shl 16) xor (sub[6] shl 16) xor
         (sub[6] shr 16) xor (sub[7] and 0xffff'u32) xor (sub[7] shl 16) xor (sub[7] shr 16)
  tempU[5] = chunk[5] xor (sub[0] shl 16) xor (sub[0] shr 16) xor (sub[0] and 0xffff0000'u32) xor
         (sub[1] and 0xffff'u32) xor sub[2] xor (sub[2] shr 16) xor (sub[3] shl 16) xor (sub[3] shr 16) xor
         (sub[4] shl 16) xor (sub[4] shr 16) xor (sub[5] shl 16) xor (sub[6] shl 16) xor
         (sub[6] shr 16) xor (sub[7] and 0xffff0000'u32) xor (sub[7] shl 16) xor (sub[7] shr 16)
  tempU[6] = chunk[6] xor sub[0] xor (sub[1] shr 16) xor (sub[2] shl 16) xor sub[3] xor (sub[3] shr 16) xor
         (sub[4] shl 16) xor (sub[4] shr 16) xor (sub[5] shl 16) xor (sub[5] shr 16) xor sub[6] xor
         (sub[6] shl 16) xor (sub[6] shr 16) xor (sub[7] shl 16)
  tempU[7] = chunk[7] xor (sub[0] and 0xffff0000'u32) xor (sub[0] shl 16) xor (sub[1] and 0xffff'u32) xor
         (sub[1] shl 16) xor (sub[2] shr 16) xor (sub[3] shl 16) xor sub[4] xor (sub[4] shr 16) xor
         (sub[5] shl 16) xor (sub[5] shr 16) xor (sub[6] shr 16) xor (sub[7] and 0xffff'u32) xor
         (sub[7] shl 16) xor (sub[7] shr 16)

  # step 6 : map the transformed results back into tempV
  tempV[0] = state[0] xor (tempU[1] shl 16) xor (tempU[0] shr 16)
  tempV[1] = state[1] xor (tempU[2] shl 16) xor (tempU[1] shr 16)
  tempV[2] = state[2] xor (tempU[3] shl 16) xor (tempU[2] shr 16)
  tempV[3] = state[3] xor (tempU[4] shl 16) xor (tempU[3] shr 16)
  tempV[4] = state[4] xor (tempU[5] shl 16) xor (tempU[4] shr 16)
  tempV[5] = state[5] xor (tempU[6] shl 16) xor (tempU[5] shr 16)
  tempV[6] = state[6] xor (tempU[7] shl 16) xor (tempU[6] shr 16)
  tempV[7] = state[7] xor (tempU[0] and 0xffff0000'u32) xor (tempU[0] shl 16) xor (tempU[7] shr 16) xor
         (tempU[1] and 0xffff0000'u32) xor (tempU[1] shl 16) xor (tempU[6] shl 16) xor (tempU[7] and 0xffff0000'u32)

  # step 7 : final state update using the 'P' transformation
  state[0] = (tempV[0] and 0xffff0000'u32) xor (tempV[0] shl 16) xor (tempV[0] shr 16) xor (tempV[1] shr 16) xor
         (tempV[1] and 0xffff0000'u32) xor (tempV[2] shl 16) xor (tempV[3] shr 16) xor (tempV[4] shl 16) xor
         (tempV[5] shr 16) xor tempV[5] xor (tempV[6] shr 16) xor (tempV[7] shl 16) xor (tempV[7] shr 16) xor
         (tempV[7] and 0xffff'u32)
  state[1] = (tempV[0] shl 16) xor (tempV[0] shr 16) xor (tempV[0] and 0xffff0000'u32) xor (tempV[1] and 0xffff'u32) xor
         tempV[2] xor (tempV[2] shr 16) xor (tempV[3] shl 16) xor (tempV[4] shr 16) xor (tempV[5] shl 16) xor
         (tempV[6] shl 16) xor tempV[6] xor (tempV[7] and 0xffff0000'u32) xor (tempV[7] shr 16)
  state[2] = (tempV[0] and 0xffff'u32) xor (tempV[0] shl 16) xor (tempV[1] shl 16) xor (tempV[1] shr 16) xor
         (tempV[1] and 0xffff0000'u32) xor (tempV[2] shl 16) xor (tempV[3] shr 16) xor tempV[3] xor (tempV[4] shl 16) xor
         (tempV[5] shr 16) xor tempV[6] xor (tempV[6] shr 16) xor (tempV[7] and 0xffff'u32) xor (tempV[7] shl 16) xor
         (tempV[7] shr 16)
  state[3] = (tempV[0] shl 16) xor (tempV[0] shr 16) xor (tempV[0] and 0xffff0000'u32) xor
         (tempV[1] and 0xffff0000'u32) xor (tempV[1] shr 16) xor (tempV[2] shl 16) xor (tempV[2] shr 16) xor tempV[2] xor
         (tempV[3] shl 16) xor (tempV[4] shr 16) xor tempV[4] xor (tempV[5] shl 16) xor (tempV[6] shl 16) xor
         (tempV[7] and 0xffff'u32) xor (tempV[7] shr 16)
  state[4] = (tempV[0] shr 16) xor (tempV[1] shl 16) xor tempV[1] xor (tempV[2] shr 16) xor tempV[2] xor
         (tempV[3] shl 16) xor (tempV[3] shr 16) xor tempV[3] xor (tempV[4] shl 16) xor (tempV[5] shr 16) xor
         tempV[5] xor (tempV[6] shl 16) xor (tempV[6] shr 16) xor (tempV[7] shl 16)
  state[5] = (tempV[0] shl 16) xor (tempV[0] and 0xffff0000'u32) xor (tempV[1] shl 16) xor (tempV[1] shr 16) xor
         (tempV[1] and 0xffff0000'u32) xor (tempV[2] shl 16) xor tempV[2] xor (tempV[3] shr 16) xor tempV[3] xor
         (tempV[4] shl 16) xor (tempV[4] shr 16) xor tempV[4] xor (tempV[5] shl 16) xor (tempV[6] shl 16) xor
         (tempV[6] shr 16) xor tempV[6] xor (tempV[7] shl 16) xor (tempV[7] shr 16) xor (tempV[7] and 0xffff0000'u32)
  state[6] = tempV[0] xor tempV[2] xor (tempV[2] shr 16) xor tempV[3] xor (tempV[3] shl 16) xor tempV[4] xor
         (tempV[4] shr 16) xor (tempV[5] shl 16) xor (tempV[5] shr 16) xor tempV[5] xor (tempV[6] shl 16) xor
         (tempV[6] shr 16) xor tempV[6] xor (tempV[7] shl 16) xor tempV[7]
  state[7] = tempV[0] xor (tempV[0] shr 16) xor (tempV[1] shl 16) xor (tempV[1] shr 16) xor (tempV[2] shl 16) xor
         (tempV[3] shr 16) xor tempV[3] xor (tempV[4] shl 16) xor tempV[4] xor (tempV[5] shr 16) xor tempV[5] xor
         (tempV[6] shl 16) xor (tempV[6] shr 16) xor (tempV[7] shl 16) xor tempV[7]

# gost hash bytes : processes exactly 32 bytes (256 bits)
template gosthashBytes(ctx: var GostHashCtx, buffer: openArray[byte], bits: int): void =
  var m: array[8, uint32]
  var c: uint64 = 0

  # convert byte buffer to 8x32 bit words
  when cpuEndian == littleEndian:
    let p32 = cast[ptr array[8, uint32]](unsafeAddr buffer[0])
    m = p32[]

    template addSum(i: untyped) =
      let a = m[i]
      let res = a.uint64 + c + ctx.checksum[i].uint64
      ctx.checksum[i] = (res and 0xffffffff'u32).uint32
      c = if res > 0xffffffff'u64: 1'u64 else: 0'u64

    addSum(0)
    addSum(1)
    addSum(2)
    addSum(3)
    addSum(4)
    addSum(5)
    addSum(6)
    addSum(7)
  else:
    for i in 0..7:
      let j = i * 4
      let a = buffer[j].uint32 or (buffer[j + 1].uint32 shl 8) or
              (buffer[j + 2].uint32 shl 16) or (buffer[j + 3].uint32 shl 24)
      m[i] = a
      let b = ctx.checksum[i].uint64
      let res = a.uint64 + c + b
      ctx.checksum[i] = (res and 0xffffffff'u32).uint32
      c = if res > 0xffffffff'u64: 1'u64 else: 0'u64

  # call the compression function with the current state and block M
  gosthashCompress(ctx, ctx.state, m)

  # update the total length counter
  let bitsU64 = bits.uint64
  let resLen = ctx.length[0].uint64 + bitsU64
  ctx.length[0] = (resLen and 0xffffffff'u32).uint32
  if resLen > 0xffffffff'u64:
    ctx.length[1].inc

# gost hash input core
template gostHashInputC(ctx: var GostHashCtx, input: lent openArray[uint8]): void =
  var i = ctx.index
  var j = 0
  let inputLen = input.len

  # check inputLen is bigger then 0
  if inputLen != 0:
    # fill the internal buffer
    if i > 0:
      # process full blocks directly from the input array
      while i < 32 and j < inputLen:
        ctx.buffer[i] = input[j]
        inc i
        inc j
      if i == 32:
        gosthashBytes(ctx, ctx.buffer, 256)
        ctx.index = 0
        i = 0
      else:
        ctx.index = i
        return

    while j + 32 <= inputLen:
      gosthashBytes(ctx, toOpenArray(input, j, j + 31), 256)
      j += 32

    # keep remaining trailing bytes in the buffer
    while j < inputLen:
      ctx.buffer[i] = input[j]
      inc i
      inc j
    ctx.index = i

# gost hash final core
template gostHashFinalC(ctx: var GostHashCtx): array[32, uint8] =
  # declare output
  var output: array[32, uint8]

  # pad the last block with zeros and compress it
  if ctx.index > 0:
    for i in ctx.index..31:
      ctx.buffer[i] = 0
    gosthashBytes(ctx, ctx.buffer, ctx.index shl 3)

  # final transformation : compress message length and checksum
  gosthashCompress(ctx, ctx.state, ctx.length)
  gosthashCompress(ctx, ctx.state, ctx.checksum)

  # encode ctx.state to output
  encodeLE(ctx.state, output)

  output

# export wrappers
when defined(templateOpt):
  template gostHashInit*(ctx: var GOSTHashCtx): void =
    gostHashInitC(ctx)
  template gostHashInput*(ctx: var GOSTHashCtx, input: lent openArray[uint8]): void =
    gostHashInputC(ctx, input)
  template gostHashFinal*(ctx: var GOSTHashCtx): array[32, uint8] =
    gostHashFinalC(ctx)
else:
  proc gostHashInit*(ctx: var GOSTHashCtx): void =
    gostHashInitC(ctx)
  proc gostHashInput*(ctx: var GOSTHashCtx, input: openArray[uint8]): void =
    gostHashInputC(ctx, input)
  proc gostHashFinal*(ctx: var GOSTHashCtx): array[32, uint8] =
    gostHashFinalC(ctx)

# test code
when defined(test):
  var s: seq[uint8] = charToBin("Hello, World!")
  var ctx: GOSTHashCtx
  gostHashInit(ctx)
  gostHashInput(ctx, s)
  echo "GOST Hash Stream : ", binToHex(gostHashFinal(ctx))
  echo "GOST Hash Standard : 9251C7D7AD6BBF5A14A67002BF8261E8AD742FEAF3DD4F8C95B8964B4203DA80"
  echo "Input : Hello, World!"
  echo "S-Box : D-TEST"
  template benchmark(name: string, code: untyped) =
    let start = getMonoTime()
    code
    let elapsed = getMonoTime() - start
    echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"
  var a: array[32, uint8]
  var ctx2: GOSTHashCtx
  benchmark("GOST Hash Benchamark"):
    for i in 1 .. 1_000_000:
      gostHashInit(ctx2)
      gostHashInput(ctx2, a)
      a = gostHashFinal(ctx2)
