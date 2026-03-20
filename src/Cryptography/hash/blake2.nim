import strutils
import sequtils
import std/[monotimes, times]
import std/bitops
import ../../../../Utility/src/Utility/codeutils/indexutils
import ../../../../Utility/src/Utility/codeutils/bits
import ../../../../Utility/src/Utility/codeutils/errorutils
import ../../../../Utility/src/Utility/dataformat/dataformat

type
  # declare blake2b generic context
  Blake2bCtx*[bits: static int] = object
    buffer*: array[128, uint8]
    state*: array[8, uint64]
    length*: array[2, uint64]
    index*: int
    tempBuffer*: array[128, uint8]
    tempState*: array[8, uint64]
    tempLength*: array[2, uint64]
    tempIndex*: int

  # declare blake2s generic context
  Blake2sCtx*[bits: static int] = object
    buffer*: array[64, uint8]
    state*: array[8, uint32]
    length*: array[2, uint32]
    index*: int
    tempBuffer*: array[64, uint8]
    tempState*: array[8, uint32]
    tempLength*: array[2, uint32]
    tempIndex*: int

  # declare blake2 context type
  Blake2Ctx* = Blake2sCtx | Blake2bCtx

  # declare blake2s 128/160/224/256 context
  Blake2s_128Ctx* = Blake2sCtx[128]
  Blake2s_160Ctx* = Blake2sCtx[160]
  Blake2s_224Ctx* = Blake2sCtx[224]
  Blake2s_256Ctx* = Blake2sCtx[256]

  # declare blake2b 128/160/224/256/384/512 context
  Blake2b_128Ctx* = Blake2bCtx[128]
  Blake2b_160Ctx* = Blake2bCtx[160]
  Blake2b_224Ctx* = Blake2bCtx[224]
  Blake2b_256Ctx* = Blake2bCtx[256]
  Blake2b_384Ctx* = Blake2bCtx[384]
  Blake2b_512Ctx* = Blake2bCtx[512]

# calculate hash size
template hashSize*(ctx: Blake2Ctx): int =
  (ctx.bits div 8)

# calculate block size
template blockSize*(ctx: Blake2Ctx): int =
  when ctx is Blake2sCtx:
    64
  else:
    128

const
  # blake2b initialise vector
  B2BIV = [
    0x6A09E667F3BCC908'u64, 0xBB67AE8584CAA73B'u64,
    0x3C6EF372FE94F82B'u64, 0xA54FF53A5F1D36F1'u64,
    0x510E527FADE682D1'u64, 0x9B05688C2B3E6C1F'u64,
    0x1F83D9ABFB41BD6B'u64, 0x5BE0CD19137E2179'u64
  ]

  # blake2s initialise vector
  B2SIV = [
    0x6A09E667'u32, 0xBB67AE85'u32, 0x3C6EF372'u32, 0xA54FF53A'u32,
    0x510E527F'u32, 0x9B05688C'u32, 0x1F83D9AB'u32, 0x5BE0CD19'u32
  ]

# blake2b mix g template
template blake2bMixG(vector: var array[16, uint64], a, b, c, d: static int, x, y: uint64): void =
  vector[a] = vector[a] + vector[b] + x
  vector[d] = rotateRightBits(vector[d] xor vector[a], 32)
  vector[c] = vector[c] + vector[d]
  vector[b] = rotateRightBits(vector[b] xor vector[c], 24)
  vector[a] = vector[a] + vector[b] + y
  vector[d] = rotateRightBits(vector[d] xor vector[a], 16)
  vector[c] = vector[c] + vector[d]
  vector[b] = rotateRightBits(vector[b] xor vector[c], 63)

# blake2s mix g template
template blake2sMixG(vector: var array[16, uint32], a, b, c, d: static int, x, y: uint32): void =
  vector[a] = vector[a] + vector[b] + x
  vector[d] = rotateRightBits(vector[d] xor vector[a], 16)
  vector[c] = vector[c] + vector[d]
  vector[b] = rotateRightBits(vector[b] xor vector[c], 12)
  vector[a] = vector[a] + vector[b] + y
  vector[d] = rotateRightBits(vector[d] xor vector[a], 8)
  vector[c] = vector[c] + vector[d]
  vector[b] = rotateRightBits(vector[b] xor vector[c], 7)

# blake2b rounds
template blake2bRounds(vector: var array[16, uint64], chunk: array[16, uint64]): void =
  # round 0
  blake2bMixG(vector, 0, 4,  8, 12, chunk[ 0], chunk[ 1])
  blake2bMixG(vector, 1, 5,  9, 13, chunk[ 2], chunk[ 3])
  blake2bMixG(vector, 2, 6, 10, 14, chunk[ 4], chunk[ 5])
  blake2bMixG(vector, 3, 7, 11, 15, chunk[ 6], chunk[ 7])
  blake2bMixG(vector, 0, 5, 10, 15, chunk[ 8], chunk[ 9])
  blake2bMixG(vector, 1, 6, 11, 12, chunk[10], chunk[11])
  blake2bMixG(vector, 2, 7,  8, 13, chunk[12], chunk[13])
  blake2bMixG(vector, 3, 4,  9, 14, chunk[14], chunk[15])

  # round 1
  blake2bMixG(vector, 0, 4,  8, 12, chunk[14], chunk[10])
  blake2bMixG(vector, 1, 5,  9, 13, chunk[ 4], chunk[ 8])
  blake2bMixG(vector, 2, 6, 10, 14, chunk[ 9], chunk[15])
  blake2bMixG(vector, 3, 7, 11, 15, chunk[13], chunk[ 6])
  blake2bMixG(vector, 0, 5, 10, 15, chunk[ 1], chunk[12])
  blake2bMixG(vector, 1, 6, 11, 12, chunk[ 0], chunk[ 2])
  blake2bMixG(vector, 2, 7,  8, 13, chunk[11], chunk[ 7])
  blake2bMixG(vector, 3, 4,  9, 14, chunk[ 5], chunk[ 3])

  # round 2
  blake2bMixG(vector, 0, 4,  8, 12, chunk[11], chunk[ 8])
  blake2bMixG(vector, 1, 5,  9, 13, chunk[12], chunk[ 0])
  blake2bMixG(vector, 2, 6, 10, 14, chunk[ 5], chunk[ 2])
  blake2bMixG(vector, 3, 7, 11, 15, chunk[15], chunk[13])
  blake2bMixG(vector, 0, 5, 10, 15, chunk[10], chunk[14])
  blake2bMixG(vector, 1, 6, 11, 12, chunk[ 3], chunk[ 6])
  blake2bMixG(vector, 2, 7,  8, 13, chunk[ 7], chunk[ 1])
  blake2bMixG(vector, 3, 4,  9, 14, chunk[ 9], chunk[ 4])

  # round 3
  blake2bMixG(vector, 0, 4,  8, 12, chunk[ 7], chunk[ 9])
  blake2bMixG(vector, 1, 5,  9, 13, chunk[ 3], chunk[ 1])
  blake2bMixG(vector, 2, 6, 10, 14, chunk[13], chunk[12])
  blake2bMixG(vector, 3, 7, 11, 15, chunk[11], chunk[14])
  blake2bMixG(vector, 0, 5, 10, 15, chunk[ 2], chunk[ 6])
  blake2bMixG(vector, 1, 6, 11, 12, chunk[ 5], chunk[10])
  blake2bMixG(vector, 2, 7,  8, 13, chunk[ 4], chunk[ 0])
  blake2bMixG(vector, 3, 4,  9, 14, chunk[15], chunk[ 8])

  # round 4
  blake2bMixG(vector, 0, 4,  8, 12, chunk[ 9], chunk[ 0])
  blake2bMixG(vector, 1, 5,  9, 13, chunk[ 5], chunk[ 7])
  blake2bMixG(vector, 2, 6, 10, 14, chunk[ 2], chunk[ 4])
  blake2bMixG(vector, 3, 7, 11, 15, chunk[10], chunk[15])
  blake2bMixG(vector, 0, 5, 10, 15, chunk[14], chunk[ 1])
  blake2bMixG(vector, 1, 6, 11, 12, chunk[11], chunk[12])
  blake2bMixG(vector, 2, 7,  8, 13, chunk[ 6], chunk[ 8])
  blake2bMixG(vector, 3, 4,  9, 14, chunk[ 3], chunk[13])

  # round 5
  blake2bMixG(vector, 0, 4,  8, 12, chunk[ 2], chunk[12])
  blake2bMixG(vector, 1, 5,  9, 13, chunk[ 6], chunk[10])
  blake2bMixG(vector, 2, 6, 10, 14, chunk[ 0], chunk[11])
  blake2bMixG(vector, 3, 7, 11, 15, chunk[ 8], chunk[ 3])
  blake2bMixG(vector, 0, 5, 10, 15, chunk[ 4], chunk[13])
  blake2bMixG(vector, 1, 6, 11, 12, chunk[ 7], chunk[ 5])
  blake2bMixG(vector, 2, 7,  8, 13, chunk[15], chunk[14])
  blake2bMixG(vector, 3, 4,  9, 14, chunk[ 1], chunk[ 9])

  # round 6
  blake2bMixG(vector, 0, 4,  8, 12, chunk[12], chunk[ 5])
  blake2bMixG(vector, 1, 5,  9, 13, chunk[ 1], chunk[15])
  blake2bMixG(vector, 2, 6, 10, 14, chunk[14], chunk[13])
  blake2bMixG(vector, 3, 7, 11, 15, chunk[ 4], chunk[10])
  blake2bMixG(vector, 0, 5, 10, 15, chunk[ 0], chunk[ 7])
  blake2bMixG(vector, 1, 6, 11, 12, chunk[ 6], chunk[ 3])
  blake2bMixG(vector, 2, 7,  8, 13, chunk[ 9], chunk[ 2])
  blake2bMixG(vector, 3, 4,  9, 14, chunk[ 8], chunk[11])

  # round 7
  blake2bMixG(vector, 0, 4,  8, 12, chunk[13], chunk[11])
  blake2bMixG(vector, 1, 5,  9, 13, chunk[ 7], chunk[14])
  blake2bMixG(vector, 2, 6, 10, 14, chunk[12], chunk[ 1])
  blake2bMixG(vector, 3, 7, 11, 15, chunk[ 3], chunk[ 9])
  blake2bMixG(vector, 0, 5, 10, 15, chunk[ 5], chunk[ 0])
  blake2bMixG(vector, 1, 6, 11, 12, chunk[15], chunk[ 4])
  blake2bMixG(vector, 2, 7,  8, 13, chunk[ 8], chunk[ 6])
  blake2bMixG(vector, 3, 4,  9, 14, chunk[ 2], chunk[10])

  # round 8
  blake2bMixG(vector, 0, 4,  8, 12, chunk[ 6], chunk[15])
  blake2bMixG(vector, 1, 5,  9, 13, chunk[14], chunk[ 9])
  blake2bMixG(vector, 2, 6, 10, 14, chunk[11], chunk[ 3])
  blake2bMixG(vector, 3, 7, 11, 15, chunk[ 0], chunk[ 8])
  blake2bMixG(vector, 0, 5, 10, 15, chunk[12], chunk[ 2])
  blake2bMixG(vector, 1, 6, 11, 12, chunk[13], chunk[ 7])
  blake2bMixG(vector, 2, 7,  8, 13, chunk[ 1], chunk[ 4])
  blake2bMixG(vector, 3, 4,  9, 14, chunk[10], chunk[ 5])

  # round 9
  blake2bMixG(vector, 0, 4,  8, 12, chunk[10], chunk[ 2])
  blake2bMixG(vector, 1, 5,  9, 13, chunk[ 8], chunk[ 4])
  blake2bMixG(vector, 2, 6, 10, 14, chunk[ 7], chunk[ 6])
  blake2bMixG(vector, 3, 7, 11, 15, chunk[ 1], chunk[ 5])
  blake2bMixG(vector, 0, 5, 10, 15, chunk[15], chunk[11])
  blake2bMixG(vector, 1, 6, 11, 12, chunk[ 9], chunk[14])
  blake2bMixG(vector, 2, 7,  8, 13, chunk[ 3], chunk[12])
  blake2bMixG(vector, 3, 4,  9, 14, chunk[13], chunk[ 0])

  # round 10
  blake2bMixG(vector, 0, 4,  8, 12, chunk[ 0], chunk[ 1])
  blake2bMixG(vector, 1, 5,  9, 13, chunk[ 2], chunk[ 3])
  blake2bMixG(vector, 2, 6, 10, 14, chunk[ 4], chunk[ 5])
  blake2bMixG(vector, 3, 7, 11, 15, chunk[ 6], chunk[ 7])
  blake2bMixG(vector, 0, 5, 10, 15, chunk[ 8], chunk[ 9])
  blake2bMixG(vector, 1, 6, 11, 12, chunk[10], chunk[11])
  blake2bMixG(vector, 2, 7,  8, 13, chunk[12], chunk[13])
  blake2bMixG(vector, 3, 4,  9, 14, chunk[14], chunk[15])

  # round 11
  blake2bMixG(vector, 0, 4,  8, 12, chunk[14], chunk[10])
  blake2bMixG(vector, 1, 5,  9, 13, chunk[ 4], chunk[ 8])
  blake2bMixG(vector, 2, 6, 10, 14, chunk[ 9], chunk[15])
  blake2bMixG(vector, 3, 7, 11, 15, chunk[13], chunk[ 6])
  blake2bMixG(vector, 0, 5, 10, 15, chunk[ 1], chunk[12])
  blake2bMixG(vector, 1, 6, 11, 12, chunk[ 0], chunk[ 2])
  blake2bMixG(vector, 2, 7,  8, 13, chunk[11], chunk[ 7])
  blake2bMixG(vector, 3, 4,  9, 14, chunk[ 5], chunk[ 3])

# blake2s rounds
template blake2sRounds(vector: var array[16, uint32], chunk: array[16, uint32]): void =
  # round 0
  blake2sMixG(vector, 0, 4,  8, 12, chunk[ 0], chunk[ 1])
  blake2sMixG(vector, 1, 5,  9, 13, chunk[ 2], chunk[ 3])
  blake2sMixG(vector, 2, 6, 10, 14, chunk[ 4], chunk[ 5])
  blake2sMixG(vector, 3, 7, 11, 15, chunk[ 6], chunk[ 7])
  blake2sMixG(vector, 0, 5, 10, 15, chunk[ 8], chunk[ 9])
  blake2sMixG(vector, 1, 6, 11, 12, chunk[10], chunk[11])
  blake2sMixG(vector, 2, 7,  8, 13, chunk[12], chunk[13])
  blake2sMixG(vector, 3, 4,  9, 14, chunk[14], chunk[15])

  # round 1
  blake2sMixG(vector, 0, 4,  8, 12, chunk[14], chunk[10])
  blake2sMixG(vector, 1, 5,  9, 13, chunk[ 4], chunk[ 8])
  blake2sMixG(vector, 2, 6, 10, 14, chunk[ 9], chunk[15])
  blake2sMixG(vector, 3, 7, 11, 15, chunk[13], chunk[ 6])
  blake2sMixG(vector, 0, 5, 10, 15, chunk[ 1], chunk[12])
  blake2sMixG(vector, 1, 6, 11, 12, chunk[ 0], chunk[ 2])
  blake2sMixG(vector, 2, 7,  8, 13, chunk[11], chunk[ 7])
  blake2sMixG(vector, 3, 4,  9, 14, chunk[ 5], chunk[ 3])

  # round 2
  blake2sMixG(vector, 0, 4,  8, 12, chunk[11], chunk[ 8])
  blake2sMixG(vector, 1, 5,  9, 13, chunk[12], chunk[ 0])
  blake2sMixG(vector, 2, 6, 10, 14, chunk[ 5], chunk[ 2])
  blake2sMixG(vector, 3, 7, 11, 15, chunk[15], chunk[13])
  blake2sMixG(vector, 0, 5, 10, 15, chunk[10], chunk[14])
  blake2sMixG(vector, 1, 6, 11, 12, chunk[ 3], chunk[ 6])
  blake2sMixG(vector, 2, 7,  8, 13, chunk[ 7], chunk[ 1])
  blake2sMixG(vector, 3, 4,  9, 14, chunk[ 9], chunk[ 4])

  # round 3
  blake2sMixG(vector, 0, 4,  8, 12, chunk[ 7], chunk[ 9])
  blake2sMixG(vector, 1, 5,  9, 13, chunk[ 3], chunk[ 1])
  blake2sMixG(vector, 2, 6, 10, 14, chunk[13], chunk[12])
  blake2sMixG(vector, 3, 7, 11, 15, chunk[11], chunk[14])
  blake2sMixG(vector, 0, 5, 10, 15, chunk[ 2], chunk[ 6])
  blake2sMixG(vector, 1, 6, 11, 12, chunk[ 5], chunk[10])
  blake2sMixG(vector, 2, 7,  8, 13, chunk[ 4], chunk[ 0])
  blake2sMixG(vector, 3, 4,  9, 14, chunk[15], chunk[ 8])

  # round 4
  blake2sMixG(vector, 0, 4,  8, 12, chunk[ 9], chunk[ 0])
  blake2sMixG(vector, 1, 5,  9, 13, chunk[ 5], chunk[ 7])
  blake2sMixG(vector, 2, 6, 10, 14, chunk[ 2], chunk[ 4])
  blake2sMixG(vector, 3, 7, 11, 15, chunk[10], chunk[15])
  blake2sMixG(vector, 0, 5, 10, 15, chunk[14], chunk[ 1])
  blake2sMixG(vector, 1, 6, 11, 12, chunk[11], chunk[12])
  blake2sMixG(vector, 2, 7,  8, 13, chunk[ 6], chunk[ 8])
  blake2sMixG(vector, 3, 4,  9, 14, chunk[ 3], chunk[13])

  # round 5
  blake2sMixG(vector, 0, 4,  8, 12, chunk[ 2], chunk[12])
  blake2sMixG(vector, 1, 5,  9, 13, chunk[ 6], chunk[10])
  blake2sMixG(vector, 2, 6, 10, 14, chunk[ 0], chunk[11])
  blake2sMixG(vector, 3, 7, 11, 15, chunk[ 8], chunk[ 3])
  blake2sMixG(vector, 0, 5, 10, 15, chunk[ 4], chunk[13])
  blake2sMixG(vector, 1, 6, 11, 12, chunk[ 7], chunk[ 5])
  blake2sMixG(vector, 2, 7,  8, 13, chunk[15], chunk[14])
  blake2sMixG(vector, 3, 4,  9, 14, chunk[ 1], chunk[ 9])

  # round 6
  blake2sMixG(vector, 0, 4,  8, 12, chunk[12], chunk[ 5])
  blake2sMixG(vector, 1, 5,  9, 13, chunk[ 1], chunk[15])
  blake2sMixG(vector, 2, 6, 10, 14, chunk[14], chunk[13])
  blake2sMixG(vector, 3, 7, 11, 15, chunk[ 4], chunk[10])
  blake2sMixG(vector, 0, 5, 10, 15, chunk[ 0], chunk[ 7])
  blake2sMixG(vector, 1, 6, 11, 12, chunk[ 6], chunk[ 3])
  blake2sMixG(vector, 2, 7,  8, 13, chunk[ 9], chunk[ 2])
  blake2sMixG(vector, 3, 4,  9, 14, chunk[ 8], chunk[11])

  # round 7
  blake2sMixG(vector, 0, 4,  8, 12, chunk[13], chunk[11])
  blake2sMixG(vector, 1, 5,  9, 13, chunk[ 7], chunk[14])
  blake2sMixG(vector, 2, 6, 10, 14, chunk[12], chunk[ 1])
  blake2sMixG(vector, 3, 7, 11, 15, chunk[ 3], chunk[ 9])
  blake2sMixG(vector, 0, 5, 10, 15, chunk[ 5], chunk[ 0])
  blake2sMixG(vector, 1, 6, 11, 12, chunk[15], chunk[ 4])
  blake2sMixG(vector, 2, 7,  8, 13, chunk[ 8], chunk[ 6])
  blake2sMixG(vector, 3, 4,  9, 14, chunk[ 2], chunk[10])

  # round 8
  blake2sMixG(vector, 0, 4,  8, 12, chunk[ 6], chunk[15])
  blake2sMixG(vector, 1, 5,  9, 13, chunk[14], chunk[ 9])
  blake2sMixG(vector, 2, 6, 10, 14, chunk[11], chunk[ 3])
  blake2sMixG(vector, 3, 7, 11, 15, chunk[ 0], chunk[ 8])
  blake2sMixG(vector, 0, 5, 10, 15, chunk[12], chunk[ 2])
  blake2sMixG(vector, 1, 6, 11, 12, chunk[13], chunk[ 7])
  blake2sMixG(vector, 2, 7,  8, 13, chunk[ 1], chunk[ 4])
  blake2sMixG(vector, 3, 4,  9, 14, chunk[10], chunk[ 5])

  # round 9
  blake2sMixG(vector, 0, 4,  8, 12, chunk[10], chunk[ 2])
  blake2sMixG(vector, 1, 5,  9, 13, chunk[ 8], chunk[ 4])
  blake2sMixG(vector, 2, 6, 10, 14, chunk[ 7], chunk[ 6])
  blake2sMixG(vector, 3, 7, 11, 15, chunk[ 1], chunk[ 5])
  blake2sMixG(vector, 0, 5, 10, 15, chunk[15], chunk[11])
  blake2sMixG(vector, 1, 6, 11, 12, chunk[ 9], chunk[14])
  blake2sMixG(vector, 2, 7,  8, 13, chunk[ 3], chunk[12])
  blake2sMixG(vector, 3, 4,  9, 14, chunk[13], chunk[ 0])

# blake2 trnasform
template blake2Transform(ctx: var Blake2Ctx, final: bool): void =
  # set Word and IV for blake2 context type
  when ctx is Blake2sCtx:
    type Word = uint32
    const IV = B2SIV
  else:
    type Word = uint64
    const IV = B2BIV

  # declare value and message
  var value: array[16, Word]
  var message: array[16, Word]

  # copy ctx.state and IV to value
  for i in static(0 ..< 8):
    value[i] = ctx.state[i]
    value[i + 8] = IV[i]

  # xor value with length
  value[12] = value[12] xor ctx.length[0]
  value[13] = value[13] xor ctx.length[1]

  # when final
  if final:
    value[14] = not value[14]

  # decode ctx.buffer to message
  decodeLE(ctx.buffer, message, 16)

  # call rounds for each context
  when ctx is Blake2sCtx:
    blake2sRounds(value, message)
  else:
    blake2bRounds(value, message)

  # update ctx.state by xor with value
  for i in static(0 ..< 8):
    ctx.state[i] = ctx.state[i] xor (value[i] xor value[i + 8])

# blake2 init core
template blake2InitC(ctx: var Blake2Ctx, key: openArray[uint8] = []): void =
  # declare block size, iv, word, paramBlock for each context
  when ctx is Blake2sCtx:
    const MaxBlock = 64
    const IV = B2SIV
    type Word = uint32
    let paramBlock = (Word(0x01010000'u32)) xor
                     (Word(key.len) shl 8) xor
                     (Word(ctx.bits div 8))
  else:
    const MaxBlock = 128
    const IV = B2BIV
    type Word = uint64
    let paramBlock = (Word(0x01010000'u64)) xor
                     (Word(key.len) shl 8) xor
                     (Word(ctx.bits div 8))

  # when nim vm
  when nimvm:
    for i in 0 ..< MaxBlock: ctx.buffer[i] = 0x00'u8
    for i in 0 ..< 8: ctx.state[i] = IV[i]
  else:
    # zerofill ctx.buffer
    zeroMem(addr ctx.buffer[0], MaxBlock)
    # set ctx.state to initialise vector
    ctx.state = IV

  # set index and length to 0
  ctx.length[0] = 0
  ctx.length[1] = 0
  ctx.index = 0

  # xor paramBLock with state[0]
  ctx.state[0] = ctx.state[0] xor paramBlock

  # if key exists, call input
  if key.len > 0:
    blake2InputC(ctx, key)
    ctx.index = MaxBlock

  # when nim vm
  when nimvm:
    # copy buffer/state to temporary state/buffer
    for i in 0 ..< MaxBlock: ctx.tempBuffer[i] = ctx.buffer[i]
    for i in 0 ..< 8: ctx.tempState[i] = ctx.state[i]
  else:
    # copy buffer/state to temporary state/buffer
    copyMem(addr ctx.tempBuffer[0], addr ctx.buffer[0], MaxBlock)
    copyMem(addr ctx.tempState[0], addr ctx.state[0], sizeof(ctx.state))

  # copy length/index to temporary length/index
  ctx.tempLength = ctx.length
  ctx.tempIndex = ctx.index

# blake2 input core
template blake2InputC*(ctx: var Blake2Ctx, input: openArray[uint8]): void =
  var i = 0
  # set input length
  let inputLen = input.len

  # set block size
  const maxBlock = when ctx is Blake2sCtx: 64 else: 128

  while i < inputLen:
    # calculate left space and fill size
    let left = maxBlock - ctx.index
    let fill = min(left, inputLen - i)

    # fill buffer with input
    if fill > 0:
      when nimvm:
        for j in 0 ..< fill:
          ctx.buffer[ctx.index + j] = input[i + j]
      else:
        copyMem(addr ctx.buffer[ctx.index], addr input[i], fill)

      i += fill
      ctx.index += fill

    # when index reach maxBlock and input not end
    if ctx.index == maxBlock and i < inputLen:
      let oldLen = ctx.length[0]
      when ctx is Blake2sCtx:
        ctx.length[0] += uint32(maxBlock)
      else:
        ctx.length[0] += uint64(maxBlock)
      if ctx.length[0] < oldLen:
        ctx.length[1] += 1

      # call blake2 transform
      ctx.blake2Transform(false)
      ctx.index = 0

# blake2s final core
template blake2FinalC*[B: static int](ctx: var Blake2sCtx[B]): array[B div 8, uint8] =
  # declare output
  var output: array[ctx.bits div 8, uint8]

  # set final length
  ctx.length[0] = ctx.length[0] + ctx.index.uint32
  if ctx.length[0] < ctx.index.uint32:
    ctx.length[1] = ctx.length[1] + 1'u32

  # pad buffer with 0x00
  if ctx.index < ctx.blockSize:
    when nimvm:
      for i in ctx.index ..< ctx.blockSize: ctx.buffer[i] = 0x00'u8
    else:
      zeroMem(addr ctx.buffer[ctx.index], ctx.blockSize - ctx.index)

  # call blake2Transform with final
  blake2Transform(ctx, true)

  # if cpu endian is little endian -> copy
  when cpuEndian == littleEndian:
    copyMem(addr output[0], addr ctx.state[0], ctx.bits div 8)
  # else -> encode state to output by little endian
  else:
    when ctx.bits == 128:
      encodeLE(ctx.state, output, 4)
    elif ctx.bits == 160:
      encdoeLE(ctx.state, output, 5)
    elif ctx.bits == 224:
      encodeLE(ctx.state, output, 7)
    elif ctx.bits == 256:
      encodeLE(ctx.state, output, 8)

  # return output
  output

# blake2b final core
template blake2FinalC*[B: static int](ctx: var Blake2bCtx[B]): array[B div 8, uint8] =
  # declare output
  var output: array[ctx.bits div 8, uint8]

  # set final length
  ctx.length[0] = ctx.length[0] + ctx.index.uint64
  if ctx.length[0] < ctx.index.uint64:
    ctx.length[1] = ctx.length[1] + 1'u64

  # pad buffer with 0x00
  if ctx.index < ctx.blockSize:
    when nimvm:
      for i in ctx.index ..< ctx.blockSize: ctx.buffer[i] = 0x00'u8
    else:
      zeroMem(addr ctx.buffer[ctx.index], ctx.blockSize - ctx.index)
  
  # call blake2Transform with final
  blake2Transform(ctx, true)

  # when cpu endian is little endian -> copy
  when cpuEndian == littleEndian:
    copyMem(addr output[0], addr ctx.state[0], ctx.bits div 8)
  # else -> encode state to output by little endian
  else:
    when ctx.bits == 128:
      encodeLE(ctx.state, output, 2)
    elif ctx.bits == 160:
      var temp: array[24, uint8]
      encodeLE(ctx.state, temp, 3)
      copyMem(addr output[0], addr temp[0], 20)
    elif ctx.bits == 224:
      var temp: array[32, uint8]
      encodeLE(ctx.state, temp, 4)
      copyMem(addr output[0], addr temp[0], 28)
    elif ctx.bits == 256:
      encodeLE(ctx.state, output, 4)
    elif ctx.bits == 384:
      encodeLE(ctx.state, output, 6)
    elif ctx.bits == 512:
      encodeLE(ctx.state, output, 8)

  # return output
  output

# export wrappers
when defined(templateOpt):
  # Blake2s-224
  template blake2s_128Init*(ctx: var Blake2s_128Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  template blake2s_128Input*(ctx: var Blake2s_128Ctx, input: lent openArray[uint8]): void = blake2InputC(ctx, input)
  template blake2s_128Final*(ctx: var Blake2s_128Ctx): array[16, uint8] = blake2FinalC(ctx)

  # Blake2s-256
  template blake2s_160Init*(ctx: var Blake2s_160Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  template blake2s_160Input*(ctx: var Blake2s_160Ctx, input: lent openArray[uint8]): void = blake2InputC(ctx, input)
  template blake2s_160Final*(ctx: var Blake2s_160Ctx): array[20, uint8] = blake2FinalC(ctx)

  # Blake2s-224
  template blake2s_224Init*(ctx: var Blake2s_224Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  template blake2s_224Input*(ctx: var Blake2s_224Ctx, input: lent openArray[uint8]): void = blake2InputC(ctx, input)
  template blake2s_224Final*(ctx: var Blake2s_224Ctx): array[28, uint8] = blake2FinalC(ctx)

  # Blake2s-256
  template blake2s_256Init*(ctx: var Blake2s_256Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  template blake2s_256Input*(ctx: var Blake2s_256Ctx, input: lent openArray[uint8]): void = blake2InputC(ctx, input)
  template blake2s_256Final*(ctx: var Blake2s_256Ctx): array[32, uint8] = blake2FinalC(ctx)

  # Blake2b-224
  template blake2b_128Init*(ctx: var Blake2b_128Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  template blake2b_128Input*(ctx: var Blake2b_128Ctx, input: lent openArray[uint8]): void = blake2InputC(ctx, input)
  template blake2b_128Final*(ctx: var Blake2b_128Ctx): array[16, uint8] = blake2FinalC(ctx)

  # Blake2b-256
  template blake2b_160Init*(ctx: var Blake2b_160Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  template blake2b_160Input*(ctx: var Blake2b_160Ctx, input: lent openArray[uint8]): void = blake2InputC(ctx, input)
  template blake2b_160Final*(ctx: var Blake2b_160Ctx): array[20, uint8] = blake2FinalC(ctx)

  # Blake2b-224
  template blake2b_224Init*(ctx: var Blake2b_224Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  template blake2b_224Input*(ctx: var Blake2b_224Ctx, input: lent openArray[uint8]): void = blake2InputC(ctx, input)
  template blake2b_224Final*(ctx: var Blake2b_224Ctx): array[28, uint8] = blake2FinalC(ctx)

  # Blake2b-256
  template blake2b_256Init*(ctx: var Blake2b_256Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  template blake2b_256Input*(ctx: var Blake2b_256Ctx, input: lent openArray[uint8]): void = blake2InputC(ctx, input)
  template blake2b_256Final*(ctx: var Blake2b_256Ctx): array[32, uint8] = blake2FinalC(ctx)

  # Blake2b-384
  template blake2b_384Init*(ctx: var Blake2b_384Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  template blake2b_384Input*(ctx: var Blake2b_384Ctx, input: lent openArray[uint8]): void = blake2InputC(ctx, input)
  template blake2b_384Final*(ctx: var Blake2b_384Ctx): array[48, uint8] = blake2FinalC(ctx)

  # Blake2b-512
  template blake2b_512Init*(ctx: var Blake2b_512Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  template blake2b_512Input*(ctx: var Blake2b_512Ctx, input: lent openArray[uint8]): void = blake2InputC(ctx, input)
  template blake2b_512Final*(ctx: var Blake2b_512Ctx): array[64, uint8] = blake2FinalC(ctx)
else:
  # Blake2s-224
  proc blake2s_128Init*(ctx: var Blake2s_128Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  proc blake2s_128Input*(ctx: var Blake2s_128Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
  proc blake2s_128Final*(ctx: var Blake2s_128Ctx): array[16, uint8] = return blake2FinalC(ctx)

  # Blake2s-256
  proc blake2s_160Init*(ctx: var Blake2s_160Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  proc blake2s_160Input*(ctx: var Blake2s_160Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
  proc blake2s_160Final*(ctx: var Blake2s_160Ctx): array[20, uint8] = return blake2FinalC(ctx)

  # Blake2s-224
  proc blake2s_224Init*(ctx: var Blake2s_224Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  proc blake2s_224Input*(ctx: var Blake2s_224Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
  proc blake2s_224Final*(ctx: var Blake2s_224Ctx): array[28, uint8] = return blake2FinalC(ctx)

  # Blake2s-256
  proc blake2s_256Init*(ctx: var Blake2s_256Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  proc blake2s_256Input*(ctx: var Blake2s_256Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
  proc blake2s_256Final*(ctx: var Blake2s_256Ctx): array[32, uint8] = return blake2FinalC(ctx)

  # Blake2b-224
  proc blake2b_128Init*(ctx: var Blake2b_128Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  proc blake2b_128Input*(ctx: var Blake2b_128Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
  proc blake2b_128Final*(ctx: var Blake2b_128Ctx): array[16, uint8] = return blake2FinalC(ctx)

  # Blake2b-256
  proc blake2b_160Init*(ctx: var Blake2b_160Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  proc blake2b_160Input*(ctx: var Blake2b_160Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
  proc blake2b_160Final*(ctx: var Blake2b_160Ctx): array[20, uint8] = return blake2FinalC(ctx)

  # Blake2b-224
  proc blake2b_224Init*(ctx: var Blake2b_224Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  proc blake2b_224Input*(ctx: var Blake2b_224Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
  proc blake2b_224Final*(ctx: var Blake2b_224Ctx): array[28, uint8] = return blake2FinalC(ctx)

  # Blake2b-256
  proc blake2b_256Init*(ctx: var Blake2b_256Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  proc blake2b_256Input*(ctx: var Blake2b_256Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
  proc blake2b_256Final*(ctx: var Blake2b_256Ctx): array[32, uint8] = return blake2FinalC(ctx)

  # Blake2b-384
  proc blake2b_384Init*(ctx: var Blake2b_384Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  proc blake2b_384Input*(ctx: var Blake2b_384Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
  proc blake2b_384Final*(ctx: var Blake2b_384Ctx): array[48, uint8] = return blake2FinalC(ctx)

  # Blake2b-512
  proc blake2b_512Init*(ctx: var Blake2b_512Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  proc blake2b_512Input*(ctx: var Blake2b_512Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
  proc blake2b_512Final*(ctx: var Blake2b_512Ctx): array[64, uint8] = return blake2FinalC(ctx)

# test code
when defined(test):
  var s: seq[uint8] = charToBin("Hello, World!")

  var s128Ctx: Blake2s_128Ctx
  blake2s_128Init(s128Ctx)
  blake2s_128Input(s128Ctx, s)
  echo "BLAKE2S-128 Stream   : ", binToHex(blake2s_128Final(s128Ctx))
  echo "BLAKE2S-128 Standard : CB5F50CCA5F56F28B7D885C345FF65DE"

  var s160Ctx: Blake2s_160Ctx
  blake2s_160Init(s160Ctx)
  blake2s_160Input(s160Ctx, s)
  echo "BLAKE2S-160 Stream   : ", binToHex(blake2s_160Final(s160Ctx))
  echo "BLAKE2S-160 Standard : 5561E2F4CA2C61CF7C2261088DB8342659D2BC98"

  var s224Ctx: Blake2s_224Ctx
  blake2s_224Init(s224Ctx)
  blake2s_224Input(s224Ctx, s)
  echo "BLAKE2S-224 Stream : ", binToHex(blake2s_224Final(s224Ctx))

  var s256Ctx: Blake2s_256Ctx
  blake2s_256Init(s256Ctx)
  blake2s_256Input(s256Ctx, s)
  echo "BLAKE2S-256 Stream   : ", binToHex(blake2s_256Final(s256Ctx))
  echo "BLAKE2S-256 Standard : EC9DB904D636EF61F1421B2BA47112A4FA6B8964FD4A0A514834455C21DF7812"

  var b128Ctx: Blake2b_128Ctx
  blake2b_128Init(b128Ctx)
  blake2b_128Input(b128Ctx, s)
  echo "BLAKE2B-128 Stream   : ", binToHex(blake2b_128Final(b128Ctx))
  echo "BLAKE2B-128 Standard : 3895C59E4AEB0903396B5BE3FBEC69FE"

  var b160Ctx: Blake2b_160Ctx
  blake2b_160Init(b160Ctx)
  blake2b_160Input(b160Ctx, s)
  echo "BLAKE2B-160 Stream   : ", binToHex(blake2b_160Final(b160Ctx))
  echo "BLAKE2B-160 Standard : 522F974C6500EB7923C28E3B129B52A79405F0FA"

  var b224Ctx: Blake2b_224Ctx
  blake2b_224Init(b224Ctx)
  blake2b_224Input(b224Ctx, s)
  echo "BLAKE2B-224 Stream : ", binToHex(blake2b_224Final(b224Ctx))

  var b256Ctx: Blake2b_256Ctx
  blake2b_256Init(b256Ctx)
  blake2b_256Input(b256Ctx, s)
  echo "BLAKE2B-256 Stream   : ", binToHex(blake2b_256Final(b256Ctx))
  echo "BLAKE2B-256 Standard : 511BC81DDE11180838C562C82BB35F3223F46061EBDE4A955C27B3F489CF1E03"

  var b384Ctx: Blake2b_384Ctx
  blake2b_384Init(b384Ctx)
  blake2b_384Input(b384Ctx, s)
  echo "BLAKE2B-384 Stream   : ", binToHex(blake2b_384Final(b384Ctx))
  echo "BLAKE2B-384 Standard : ABCFF1BA93147176D032D840372864602CCC2499E084C0A9F6C459D5BF9220C56F79B02382104B3126D20168C1FC4D31"

  var b512Ctx: Blake2b_512Ctx
  blake2b_512Init(b512Ctx)
  blake2b_512Input(b512Ctx, s)
  echo "BLAKE2B-512 Stream   : ", binToHex(blake2b_512Final(b512Ctx))
  echo "BLAKE2B-512 Standard : 7DFDB888AF71EAE0E6A6B751E8E3413D767EF4FA52A7993DAA9EF097F7AA3D949199C113CAA37C94F80CF3B22F7D9D6E4F5DEF4FF927830CFFE4857C34BE3D89"

  template benchmark(name: string, code: untyped) =
    let start = getMonoTime()
    code
    let elapsed = getMonoTime() - start
    echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

  var
    res128: array[16, uint8]
    res160: array[20, uint8]
    res224: array[28, uint8]
    res256: array[32, uint8]
    res384: array[48, uint8]
    res512: array[64, uint8]

    ctxS128: Blake2s_128Ctx
    ctxS160: Blake2s_160Ctx
    ctxS224: Blake2s_224Ctx
    ctxS256: Blake2s_256Ctx

    ctxB128: Blake2b_128Ctx
    ctxB160: Blake2b_160Ctx
    ctxB224: Blake2b_224Ctx
    ctxB256: Blake2b_256Ctx
    ctxB384: Blake2b_384Ctx
    ctxB512: Blake2b_512Ctx

  benchmark("BLAKE2s-128 Benchmark"):
    for i in 1 .. 1_000_000:
      blake2s_128Init(ctxS128)
      blake2s_128Input(ctxS128, res128)
      res128 = blake2s_128Final(ctxS128)

  benchmark("BLAKE2s-160 Benchmark"):
    for i in 1 .. 1_000_000:
      blake2s_160Init(ctxS160)
      blake2s_160Input(ctxS160, res160)
      res160 = blake2s_160Final(ctxS160)

  benchmark("BLAKE2s-224 Benchmark"):
    for i in 1 .. 1_000_000:
      blake2s_224Init(ctxS224)
      blake2s_224Input(ctxS224, res224)
      res224 = blake2s_224Final(ctxS224)

  benchmark("BLAKE2s-256 Benchmark"):
    for i in 1 .. 1_000_000:
      blake2s_256Init(ctxS256)
      blake2s_256Input(ctxS256, res256)
      res256 = blake2s_256Final(ctxS256)

  benchmark("BLAKE2b-128 Benchmark"):
    for i in 1 .. 1_000_000:
      blake2b_128Init(ctxB128)
      blake2b_128Input(ctxB128, res128)
      res128 = blake2b_128Final(ctxB128)

  benchmark("BLAKE2b-160 Benchmark"):
    for i in 1 .. 1_000_000:
      blake2b_160Init(ctxB160)
      blake2b_160Input(ctxB160, res160)
      res160 = blake2b_160Final(ctxB160)

  benchmark("BLAKE2b-224 Benchmark"):
    for i in 1 .. 1_000_000:
      blake2b_224Init(ctxB224)
      blake2b_224Input(ctxB224, res224)
      res224 = blake2b_224Final(ctxB224)

  benchmark("BLAKE2b-256 Benchmark"):
    for i in 1 .. 1_000_000:
      blake2b_256Init(ctxB256)
      blake2b_256Input(ctxB256, res256)
      res256 = blake2b_256Final(ctxB256)

  benchmark("BLAKE2b-384 Benchmark"):
    for i in 1 .. 1_000_000:
      blake2b_384Init(ctxB384)
      blake2b_384Input(ctxB384, res384)
      res384 = blake2b_384Final(ctxB384)

  benchmark("BLAKE2b-512 Benchmark"):
    for i in 1 .. 1_000_000:
      blake2b_512Init(ctxB512)
      blake2b_512Input(ctxB512, res512)
      res512 = blake2b_512Final(ctxB512)
