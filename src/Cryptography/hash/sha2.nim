import sequtils
import strutils
import ../../../../Utility/src/Utility/codeutils/indexutils
import ../../../../Utility/src/Utility/codeutils/bits
import ../../../../Utility/src/Utility/codeutils/errorutils
import ../../../../Utility/src/Utility/dataformat/dataformat
import std/[monotimes, times]
import bitops

# SHA-2 256 series : SHA-2-224, SHA-2-256 : for 32 bits
# SHA-2 512 series : SHA-2-384, SHA-2-512, SHA-2-512/224, SHA-2-512/256 : for 64 bits

# declaring constant
const
  # K for 256 series
  K256: array[64, uint32] = [
    0x428a2f98'u32, 0x71374491'u32, 0xb5c0fbcf'u32, 0xe9b5dba5'u32, 0x3956c25b'u32, 0x59f111f1'u32, 0x923f82a4'u32, 0xab1c5ed5'u32,
    0xd807aa98'u32, 0x12835b01'u32, 0x243185be'u32, 0x550c7dc3'u32, 0x72be5d74'u32, 0x80deb1fe'u32, 0x9bdc06a7'u32, 0xc19bf174'u32,
    0xe49b69c1'u32, 0xefbe4786'u32, 0x0fc19dc6'u32, 0x240ca1cc'u32, 0x2de92c6f'u32, 0x4a7484aa'u32, 0x5cb0a9dc'u32, 0x76f988da'u32,
    0x983e5152'u32, 0xa831c66d'u32, 0xb00327c8'u32, 0xbf597fc7'u32, 0xc6e00bf3'u32, 0xd5a79147'u32, 0x06ca6351'u32, 0x14292967'u32,
    0x27b70a85'u32, 0x2e1b2138'u32, 0x4d2c6dfc'u32, 0x53380d13'u32, 0x650a7354'u32, 0x766a0abb'u32, 0x81c2c92e'u32, 0x92722c85'u32,
    0xa2bfe8a1'u32, 0xa81a664b'u32, 0xc24b8b70'u32, 0xc76c51a3'u32, 0xd192e819'u32, 0xd6990624'u32, 0xf40e3585'u32, 0x106aa070'u32,
    0x19a4c116'u32, 0x1e376c08'u32, 0x2748774c'u32, 0x34b0bcb5'u32, 0x391c0cb3'u32, 0x4ed8aa4a'u32, 0x5b9cca4f'u32, 0x682e6ff3'u32,
    0x748f82ee'u32, 0x78a5636f'u32, 0x84c87814'u32, 0x8cc70208'u32, 0x90befffa'u32, 0xa4506ceb'u32, 0xbef9a3f7'u32, 0xc67178f2'u32
  ]

  # K for 512 series
  K512: array[80, uint64] = [
  0x428a2f98d728ae22'u64, 0x7137449123ef65cd'u64, 0xb5c0fbcfec4d3b2f'u64, 0xe9b5dba58189dbbc'u64, 0x3956c25bf348b538'u64,
  0x59f111f1b605d019'u64, 0x923f82a4af194f9b'u64, 0xab1c5ed5da6d8118'u64, 0xd807aa98a3030242'u64, 0x12835b0145706fbe'u64,
  0x243185be4ee4b28c'u64, 0x550c7dc3d5ffb4e2'u64, 0x72be5d74f27b896f'u64, 0x80deb1fe3b1696b1'u64, 0x9bdc06a725c71235'u64,
  0xc19bf174cf692694'u64, 0xe49b69c19ef14ad2'u64, 0xefbe4786384f25e3'u64, 0x0fc19dc68b8cd5b5'u64, 0x240ca1cc77ac9c65'u64,
  0x2de92c6f592b0275'u64, 0x4a7484aa6ea6e483'u64, 0x5cb0a9dcbd41fbd4'u64, 0x76f988da831153b5'u64, 0x983e5152ee66dfab'u64,
  0xa831c66d2db43210'u64, 0xb00327c898fb213f'u64, 0xbf597fc7beef0ee4'u64, 0xc6e00bf33da88fc2'u64, 0xd5a79147930aa725'u64,
  0x06ca6351e003826f'u64, 0x142929670a0e6e70'u64, 0x27b70a8546d22ffc'u64, 0x2e1b21385c26c926'u64, 0x4d2c6dfc5ac42aed'u64,
  0x53380d139d95b3df'u64, 0x650a73548baf63de'u64, 0x766a0abb3c77b2a8'u64, 0x81c2c92e47edaee6'u64, 0x92722c851482353b'u64,
  0xa2bfe8a14cf10364'u64, 0xa81a664bbc423001'u64, 0xc24b8b70d0f89791'u64, 0xc76c51a30654be30'u64, 0xd192e819d6ef5218'u64,
  0xd69906245565a910'u64, 0xf40e35855771202a'u64, 0x106aa07032bbd1b8'u64, 0x19a4c116b8d2d0c8'u64, 0x1e376c085141ab53'u64,
  0x2748774cdf8eeb99'u64, 0x34b0bcb5e19b48a8'u64, 0x391c0cb3c5c95a63'u64, 0x4ed8aa4ae3418acb'u64, 0x5b9cca4f7763e373'u64,
  0x682e6ff3d6b2b8a3'u64, 0x748f82ee5defb2fc'u64, 0x78a5636f43172f60'u64, 0x84c87814a1f0ab72'u64, 0x8cc702081a6439ec'u64,
  0x90befffa23631e28'u64, 0xa4506cebde82bde9'u64, 0xbef9a3f7b2c67915'u64, 0xc67178f2e372532b'u64, 0xca273eceea26619c'u64,
  0xd186b8c721c0c207'u64, 0xeada7dd6cde0eb1e'u64, 0xf57d4f7fee6ed178'u64, 0x06f067aa72176fba'u64, 0x0a637dc5a2c898a6'u64,
  0x113f9804bef90dae'u64, 0x1b710b35131c471b'u64, 0x28db77f523047d84'u64, 0x32caab7b40c72493'u64, 0x3c9ebe0a15c9bebc'u64,
  0x431d67c49c100d4c'u64, 0x4cc5d4becb3e42b6'u64, 0x597f299cfc657e2a'u64, 0x5fcb6fab3ad6faec'u64, 0x6c44198c4a475817'u64
  ]

# padding part for 256 series
template padding256(input: var seq[uint8], bitLen: lent uint64): void =
  # append a single '1' bit 0x80
  input.add(0x80'u8)

  # append K '0' bits (as bytes) until length = 56 mod 64
  while (input.len mod 64) != 56:
    input.add(0x00'u8)

  # append original length as 64-bits big-endian integer
  for i in countdown(7, 0):
    input.add(uint8((bitLen shr (i * 8)) and 0xFF))

# padding part for 512 series
template padding512(input: var seq[uint8], bitLen: lent uint64): void =
  # append a single '1' bit 0x80
  input.add(0x80'u8)

  # append K '0' bits (as bytes) until length = 56 mod 64
  while (input.len mod 128) != 112:
    input.add(0x00'u8)

  for j in 0..7:
    input.add(0x00'u8)

  # append original length as 64-bits big-endian integer
  for i in countdown(7, 0):
    input.add(uint8((bitLen shr (i * 8)) and 0xFF))

# processing part for 256 series
template sha2Transform256(state: var array[8, uint32], chunk: lent openArray[uint8]): void =
  # declare w
  var w: array[64, uint32]

  # decode chunk to w
  # static is for deploying loop in compile time
  for i in static(0..<16):
    w[i] = (uint32(chunk[i * 4]) shl 24) or
    (uint32(chunk[i * 4 + 1]) shl 16) or
    (uint32(chunk[i * 4 + 2]) shl 8) or
    uint32(chunk[i * 4 + 3])

  # extending w by rotate
  for i in static(16..<64):
    let s0 = rotateRightBits(w[i - 15], 7) xor rotateRightBits(w[i - 15], 18) xor (w[i - 15] shr 3)
    let s1 = rotateRightBits(w[i - 2], 17) xor rotateRightBits(w[i - 2], 19) xor (w[i - 2] shr 10)
    w[i] = w[i - 16] + s0 + w[i - 7] + s1

  # declare temporary array and assign state
  var temp: array[8, uint32]
  for i in static(0 ..< 8):
    temp[i] = state[i]

  # round process : 64 round of ARX operation(256 series)
  for i in static(0..<64):
    let s1 = rotateRightBits(temp[4], 6) xor rotateRightBits(temp[4], 11) xor rotateRightBits(temp[4], 25)
    let ch = (temp[4] and temp[5]) xor ((not temp[4]) and temp[6])
    let temp1 = temp[7] + s1 + ch + K256[i] + w[i]
    let s0 = rotateRightBits(temp[0], 2) xor rotateRightBits(temp[0], 13) xor rotateRightBits(temp[0], 22)
    let maj = (temp[0] and temp[1]) xor (temp[0] and temp[2]) xor (temp[1] and temp[2])
    let temp2 = s0 + maj

    temp[7] = temp[6]
    temp[6] = temp[5]
    temp[5] = temp[4]
    temp[4] = temp[3] + temp1
    temp[3] = temp[2]
    temp[2] = temp[1]
    temp[1] = temp[0]
    temp[0] = temp1 + temp2

  # add and assign temporary variable to H
  for i in static(0 ..< 8):
    state[i] += temp[i]

# processing part for 512 series
template sha2Transform512(state: var array[8, uint64], chunk: lent openArray[uint8]): void =
  # declaring w
  var w: array[80, uint64]

  # decode chunk to w
  # static is for deploying loop in compile time
  for i in static(0..<16):
    w[i] = (uint64(chunk[i * 8]) shl 56) or
    (uint64(chunk[i * 8 + 1]) shl 48) or
    (uint64(chunk[i * 8 + 2]) shl 40) or
    (uint64(chunk[i * 8 + 3]) shl 32) or
    (uint64(chunk[i * 8 + 4]) shl 24) or
    (uint64(chunk[i * 8 + 5]) shl 16) or
    (uint64(chunk[i * 8 + 6]) shl 8) or
    uint64(chunk[i * 8 + 7])

  # extending w by rotate
  for i in static(16..<80):
    let s0 = rotateRightBits(w[i - 15], 1) xor rotateRightBits(w[i - 15], 8) xor (w[i - 15] shr 7)
    let s1 = rotateRightBits(w[i - 2], 19) xor rotateRightBits(w[i - 2], 61) xor (w[i - 2] shr 6)
    w[i] = w[i - 16] + s0 + w[i - 7] + s1

  # declare temporary variables and assign state
  var temp: array[8, uint64]
  for i in static(0 ..< 8):
    temp[i] = state[i]

  # round process : 80 round of ARX operation(512 series)
  for i in static(0..<80):
    let s1 = rotateRightBits(temp[4], 14) xor rotateRightBits(temp[4], 18) xor rotateRightBits(temp[4], 41)
    let ch = (temp[4] and temp[5]) xor ((not temp[4]) and temp[6])
    let temp1 = temp[7] + s1 + ch + K512[i] + w[i]
    let s0 = rotateRightBits(temp[0], 28) xor rotateRightBits(temp[0], 34) xor rotateRightBits(temp[0], 39)
    let maj = (temp[0] and temp[1]) xor (temp[0] and temp[2]) xor (temp[1] and temp[2])
    let temp2 = s0 + maj

    temp[7] = temp[6]
    temp[6] = temp[5]
    temp[5] = temp[4]
    temp[4] = temp[3] + temp1
    temp[3] = temp[2]
    temp[2] = temp[1]
    temp[1] = temp[0]
    temp[0] = temp1 + temp2

  # add and assign temporary variables to h
  for i in static(0 ..< 8):
    state[i] += temp[i]

# chunking part of 256 series
template chunking256(state: var array[8, uint32], input: lent openArray[uint8]): void =
  # calculate chunk count
  let chunkCount = input.len div 64

  # divide chunk and process
  for chunkIdx in 0 ..< chunkCount:
    sha2Transform256(state, input[(chunkIdx * 64)..(chunkIdx * 64 + 63)])

template chunking512(state: var array[8, uint64], input: lent openArray[uint8]): void =
  # calculate chunk count
  let chunkCount = input.len div 128

  # divide chunk and process
  for chunkIdx in 0 ..< chunkCount:
    sha2Transform512(state, input[(chunkIdx * 128)..(chunkIdx * 128 + 127)])

# SHA-2-224 oneshot core
template sha2_224OneC(input: lent openArray[uint8]): array[28, uint8] =
  # declare output
  var output: array[28, uint8]
  # copy input to buffer
  var buffer: seq[uint8] = newSeq[uint8](input.len)
  for i in 0 ..< input.len:
    buffer[i] = input[i]

  # declare state
  var state: array[8, uint32] = [
  0xc1059ed8'u32, 0x367cd507'u32, 0x3070dd17'u32, 0xf70e5939'u32, 0xffc00b31'u32, 0x68581511'u32, 0x64f98fa7'u32, 0xbefa4fa4'u32
  ]

  # call padding256
  padding256(buffer, uint64(input.len * 8))

  # call chunking256
  chunking256(state, buffer)

  # encode state to output(openArray)
  # discard result because state's index is verified in compile time
  discard encodeBE(state[0..<7], output)

  output

# SHA-2-256 oneshot core
template sha2_256OneC(input: lent openArray[uint8]): array[32, uint8] =
  # declare output
  var output: array[32, uint8]
  # copy input to buffer
  var buffer: seq[uint8] = newSeq[uint8](input.len)
  for i in 0 ..< input.len:
    buffer[i] = input[i]

  # declare state
  var state: array[8, uint32] = [
  0x6a09e667'u32, 0xbb67ae85'u32, 0x3c6ef372'u32, 0xa54ff53a'u32, 0x510e527f'u32, 0x9b05688c'u32, 0x1f83d9ab'u32, 0x5be0cd19'u32
  ]

  # call padding256
  padding256(buffer, uint64(input.len * 8))

  # call chunking256
  chunking256(state, buffer)

  # encode state to output(array)
  encodeBE(state, output)

  output

# SHA-2-384 oneshot core
template sha2_384OneC(input: lent openArray[uint8]): array[48, uint8] =
  # declare output
  var output: array[48, uint8]
  # copy input to buffer
  var buffer: seq[uint8] = newSeq[uint8](input.len)
  for i in 0 ..< input.len:
    buffer[i] = input[i]
  #declare state
  var state: array[8, uint64] = [
  0xcbbb9d5dc1059ed8'u64, 0x629a292a367cd507'u64, 0x9159015a3070dd17'u64, 0x152fecd8f70e5939'u64,
  0x67332667ffc00b31'u64, 0x8eb44a8768581511'u64, 0xdb0c2e0d64f98fa7'u64, 0x47b5481dbefa4fa4'u64
  ]

  # call padding512
  padding512(buffer, uint64(input.len * 8))

  # call chunking512
  chunking512(state, buffer)

  # encode state to output(openArray)
  # discard result because state's index is verified in compile time
  discard encodeBE(state[0..<6], output)

  output

# SHA-2-512 oneshot core
template sha2_512OneC(input: lent openArray[uint8]): array[64, uint8] =
  # declare output
  var output: array[64, uint8]
  # copy input to buffer
  var buffer: seq[uint8] = newSeq[uint8](input.len)
  for i in 0 ..< input.len:
    buffer[i] = input[i]
  # declare state
  var state: array[8, uint64] = [
  0x6a09e667f3bcc908'u64, 0xbb67ae8584caa73b'u64, 0x3c6ef372fe94f82b'u64, 0xa54ff53a5f1d36f1'u64,
  0x510e527fade682d1'u64, 0x9b05688c2b3e6c1f'u64, 0x1f83d9abfb41bd6b'u64, 0x5be0cd19137e2179'u64
  ]

  # call padding512
  padding512(buffer, uint64(input.len * 8))

  # call chunking512
  chunking512(state, buffer)

  # encdoe state to output(array)
  encodeBE(state, output)

  output

# SHA-2-512/224 oneshot core
template sha2_512_224OneC(input: lent openArray[uint8]): array[28, uint8] =
  # declare output
  var output: array[28, uint8]
  # copy input to buffer
  var buffer: seq[uint8] = newSeq[uint8](input.len)
  for i in 0 ..< input.len:
    buffer[i] = input[i]
  # declare state
  var state: array[8, uint64] = [
  0x8c3d37c819544da2'u64, 0x73e1996689dcd4d6'u64, 0x1dfab7ae32ff9c82'u64, 0x679dd514582f9fcf'u64,
  0x0f6d2b697bd44da8'u64, 0x77e36f7304C48942'u64, 0x3f9d85a86a1d36C8'u64, 0x1112e6ad91d692a1'u64
  ]

  # call padding512
  padding512(buffer, uint64(input.len * 8))

  # call chunking512
  chunking512(state, buffer)

  # encode state to temp(openArray)
  var temp: array[32, uint8]
  # discard result because state's index is verified in compile time
  discard encodeBE(state[0..<4], temp)
  # copy temp to output
  for i in static(0 ..< 28):
    output[i] = temp[i]

  output

# SHA-2-512/224 oneshot core
template sha2_512_256OneC(input: lent openArray[uint8]): array[32, uint8] =
  # declare output
  var output: array[32, uint8]
  # copy input to buffer
  var buffer: seq[uint8] = newSeq[uint8](input.len)
  for i in 0 ..< input.len:
    buffer[i] = input[i]
  # declare state
  var state: array[8, uint64] = [
  0x22312194fc2bf72c'u64, 0x9f555fa3c84c64c2'u64, 0x2393b86b6f53b151'u64, 0x963877195940eabd'u64,
  0x96283ee2a88effe3'u64, 0xbe5e1e2553863992'u64, 0x2b0199fc2c85b8aa'u64, 0x0eb72ddC81c52ca2'u64
  ]

  # call padding512
  padding512(buffer, uint64(input.len * 8))

  # call chunking512
  chunking512(state, buffer)

  # encode state to output(openArray)
  # discard result because state's index is verified in compile time
  discard encodeBE(state[0..<4], output)

  output

const
  # declare hash size constant
  SHA2_224_HASH_SIZE*: int = 224 div 8
  SHA2_256_HASH_SIZE*: int = 256 div 8
  SHA2_384_HASH_SIZE*: int = 384 div 8
  SHA2_512_HASH_SIZE*: int = 512 div 8

  # # declare block size constant
  SHA2_256_BLOCK_SIZE*: int = 512 div 8
  SHA2_512_BLOCK_SIZE*: int = 1024 div 8
  SHA2_224_BLOCK_SIZE*: int = SHA2_256_BLOCK_SIZE
  SHA2_384_BLOCK_SIZE*: int = SHA2_512_BLOCK_SIZE
  SHA2_512_224_BLOCK_SIZE*: int = SHA2_512_BLOCK_SIZE
  SHA2_512_256_BLOCK_SIZE*: int = SHA2_512_BLOCK_SIZE

# CPU's bits constant
const
  Bits*: int = sizeof(int) * 8

type
  SHA2Kind* = enum
    SHA2_224
    SHA2_256
    SHA2_384
    SHA2_512
    SHA2_512_224
    SHA2_512_256

when Bits == 64:
  # declare generic SHA-2 context for 64bits
  type
    SHA2Ctx*[bufferSize: static[int], hashSize: static[int], T; kind: static SHA2Kind] = object
      totalLength*: uint64
      index*: int
      buffer*: array[2 * bufferSize, uint8]
      state*: array[8, T]
elif Bits == 32:
  # declare generic SHA-2 context for 32bits
  type
    SHA2Ctx*[bufferSize: static[int], hashSize: static[int], T; kind: static SHA2Kind] = object
      totalLength*: array[2, uint32]
      index*: int
      buffer*: array[2 * bufferSize, uint8]
      state*: array[8, T]

type
  # declare SHA-2 context by generic context
  SHA2_224Ctx* = SHA2Ctx[SHA2_224_BLOCK_SIZE, SHA2_224_HASH_SIZE, uint32, SHA2_224]
  SHA2_256Ctx* = SHA2Ctx[SHA2_256_BLOCK_SIZE, SHA2_256_HASH_SIZE, uint32, SHA2_256]
  SHA2_384Ctx* = SHA2Ctx[SHA2_384_BLOCK_SIZE, SHA2_384_HASH_SIZE, uint64, SHA2_384]
  SHA2_512Ctx* = SHA2Ctx[SHA2_512_BLOCK_SIZE, SHA2_512_HASH_SIZE, uint64, SHA2_512]
  SHA2_512_224Ctx* = SHA2Ctx[SHA2_512_224_BLOCK_SIZE, SHA2_224_HASH_SIZE, uint64, SHA2_512_224]
  SHA2_512_256Ctx* = SHA2Ctx[SHA2_512_256_BLOCK_SIZE, SHA2_256_HASH_SIZE, uint64, SHA2_512_256]

template sha2InitC[bufferSize: static[int], hashSize: static[int], T; kind: static SHA2Kind](ctx: var SHA2Ctx[bufferSize, hashSize, T, kind]): void =
  for i in static(0 ..< (bufferSize * 2)):
    ctx.buffer[i] = 0x00'u8

  when Bits == 64:
    ctx.totalLength = 0x00'u64
  elif Bits == 32:
    ctx.totalLength[0] = 0x00'u32
    ctx.totalLength[1] = 0x00'u32

  ctx.index = 0

  when kind == SHA2_224:
    ctx.state[0] = 0xC1059ED8'u32
    ctx.state[1] = 0x367CD507'u32
    ctx.state[2] = 0x3070DD17'u32
    ctx.state[3] = 0xF70E5939'u32
    ctx.state[4] = 0xFFC00B31'u32
    ctx.state[5] = 0x68581511'u32
    ctx.state[6] = 0x64F98FA7'u32
    ctx.state[7] = 0xBEFA4FA4'u32
  elif kind == SHA2_256:
    ctx.state[0] = 0x6A09E667'u32
    ctx.state[1] = 0xBB67AE85'u32
    ctx.state[2] = 0x3C6EF372'u32
    ctx.state[3] = 0xA54FF53A'u32
    ctx.state[4] = 0x510E527F'u32
    ctx.state[5] = 0x9B05688C'u32
    ctx.state[6] = 0x1F83D9AB'u32
    ctx.state[7] = 0x5BE0CD19'u32
  elif kind == SHA2_384:
    ctx.state[0] = 0xcbbb9d5dc1059ed8'u64
    ctx.state[1] = 0x629a292a367cd507'u64
    ctx.state[2] = 0x9159015a3070dd17'u64
    ctx.state[3] = 0x152fecd8f70e5939'u64
    ctx.state[4] = 0x67332667ffc00b31'u64
    ctx.state[5] = 0x8eb44a8768581511'u64
    ctx.state[6] = 0xdb0c2e0d64f98fa7'u64
    ctx.state[7] = 0x47b5481dbefa4fa4'u64
  elif kind == SHA2_512:
    ctx.state[0] = 0x6a09e667f3bcc908'u64
    ctx.state[1] = 0xbb67ae8584caa73b'u64
    ctx.state[2] = 0x3c6ef372fe94f82b'u64
    ctx.state[3] = 0xa54ff53a5f1d36f1'u64
    ctx.state[4] = 0x510e527fade682d1'u64
    ctx.state[5] = 0x9b05688c2b3e6c1f'u64
    ctx.state[6] = 0x1f83d9abfb41bd6b'u64
    ctx.state[7] = 0x5be0cd19137e2179'u64
  elif kind == SHA2_512_224:
    ctx.state[0] = 0x8c3d37c819544da2'u64
    ctx.state[1] = 0x73e1996689dcd4d6'u64
    ctx.state[2] = 0x1dfab7ae32ff9c82'u64
    ctx.state[3] = 0x679dd514582f9fcf'u64
    ctx.state[4] = 0x0f6d2b697bd44da8'u64
    ctx.state[5] = 0x77e36f7304C48942'u64
    ctx.state[6] = 0x3f9d85a86a1d36C8'u64
    ctx.state[7] = 0x1112e6ad91d692a1'u64
  elif kind == SHA2_512_256:
    ctx.state[0] = 0x22312194fc2bf72c'u64
    ctx.state[1] = 0x9f555fa3c84c64c2'u64
    ctx.state[2] = 0x2393b86b6f53b151'u64
    ctx.state[3] = 0x963877195940eabd'u64
    ctx.state[4] = 0x96283ee2a88effe3'u64
    ctx.state[5] = 0xbe5e1e2553863992'u64
    ctx.state[6] = 0x2b0199fc2c85b8aa'u64
    ctx.state[7] = 0x0eb72ddC81c52ca2'u64

template sha2InputC[bufferSize: static[int], hashSize: static[int], T; kind: static SHA2Kind](ctx: var SHA2Ctx[bufferSize, hashSize, T, kind], input: lent openArray[uint8]): void =
  let inputLen: int = input.len
  var check: bool = true
  var consumed: int = 0

  if inputLen == 0: check = false

  if check:
    var pInput = unsafeAddr input[0]
    var index: int = ctx.index

    if index > 0:
      let take: int = min(inputLen, bufferSize - index)
      copyMem(addr ctx.buffer[index], pInput, take)
      ctx.index += take
      consumed += take

      if ctx.index == bufferSize:
        when ctx.state[0] is uint32:
          sha2Transform256(ctx.state, ctx.buffer)
        elif ctx.state[0] is uint64:
          sha2Transform512(ctx.state, ctx.buffer)
        ctx.index = 0

    while (inputLen - consumed) >= bufferSize:
      let startIndex: int = consumed
      when ctx.state[0] is uint32:
        sha2Transform256(ctx.state, input.toOpenArray(startIndex, startIndex + bufferSize - 1))
      elif ctx.state[0] is uint64:
        sha2Transform512(ctx.state, input.toOpenArray(startIndex, startIndex + bufferSize - 1))

      consumed += bufferSize

  let remain = inputLen - consumed
  if remain > 0:
    copyMem(addr ctx.buffer[0], addr input[consumed], remain)
    ctx.index = remain

  when Bits == 64:
    ctx.totalLength += inputLen.uint64
  elif Bits == 32:
    let oldLen: int = ctx.totalLength[0]
    ctx.totalLength += inputLen.uint32
    if ctx.totalLength < oldLen:
      ctx.totalLength[1] += 1

template sha2FinalC[bufferSize: static[int], hashSize: static[int], T; kind: static SHA2Kind](ctx: var SHA2Ctx[bufferSize, hashSize, T, kind]): array[hashSize, uint8] =
  var output: array[hashSize, uint8]
  when Bits == 64:
    let bitLen: uint64 = ctx.totalLength shl 3
  elif Bits == 32:
    let bitLen: array[2, uint32] = [ctx.totalLength[0] shl 3, (ctx.totalLength[1] shl 3) or (ctx.totalLength[0] shr 29)]

  ctx.buffer[ctx.index] = 0x80'u8
  ctx.index.inc

  const LenPos = when ctx.state[0] is uint32: 56 elif ctx.state[0] is uint64: 112

  if ctx.index > LenPos:
    if ctx.index < bufferSize:
      zeroMem(addr ctx.buffer[ctx.index], bufferSize - ctx.index)

    when ctx.state[0] is uint32:
      sha2Transform256(ctx.state, ctx.buffer)
    elif ctx.state[0] is uint64:
      sha2Transform512(ctx.state, ctx.buffer)
    ctx.index = 0

  if ctx.index < LenPos:
    zeroMem(addr ctx.buffer[ctx.index], LenPos - ctx.index)

  when ctx.state[0] is uint64:
    zeroMem(addr ctx.buffer[LenPos], 8)

  when Bits == 64:
    when ctx.state[0] is uint32:
      for i in static(0 ..< 8):
        ctx.buffer[56 + i] = uint8((bitLen shr ((7 - i) * 8)) and 0xFF'u64)
    elif ctx.state[0] is uint64:
      for i in static(0 ..< 8):
        ctx.buffer[120 + i] = uint8((bitLen shr ((7 - i) * 8)) and 0xFF'u64)
  elif Bits == 32:
    when ctx.state[0] is uint32:
      for i in static(0 ..< 4):
        ctx.buffer[56 + i] = uint8((bitLen[1] shr ((3 - i) * 8)) and 0xFF'u32)
      for i in static(0 ..< 4):
        ctx.buffer[60 + i] = uint8((bitLen[0] shr ((3 - i) * 8)) and 0xFF'u32)
    elif ctx.state[0] is uint64:
      for i in static(0 ..< 4):
        ctx.buffer[120 + i] = uint8((bitLen[1] shr ((3 - i) * 8)) and 0xFF'u32)
      for i in static(0 ..< 4):
        ctx.buffer[124 + i] = uint8((bitLen[0] shr ((3 - i) * 8)) and 0xFF'u32)

  when ctx.state[0] is uint32:
    sha2Transform256(ctx.state, ctx.buffer)
  elif ctx.state[0] is uint64:
    sha2Transform512(ctx.state, ctx.buffer)

  when kind == SHA2_224:
    encodeBE(ctx.state[0..<7], output, 7)
  elif kind == SHA2_256:
    encodeBE(ctx.state, output)
  elif kind == SHA2_384:
    encodeBE(ctx.state[0..<6], output, 6)
  elif kind == SHA2_512:
    encodeBE(ctx.state, output)
  elif kind == SHA2_512_224:
    var temp: array[32, uint8]
    encodeBE(ctx.state[0..<4], temp, 4)
    for i in static(0 ..< 28):
      output[i] = temp[i]
  elif kind == SHA2_512_256:
    encodeBE(ctx.state[0..<4], output, 4)

  output

when defined(templateOpt):
  # SHA-2-224
  template sha2_224Init*(ctx: var SHA2_224Ctx): void = sha2InitC(ctx)
  template sha2_224Input*(ctx: var SHA2_224Ctx, input: lent openArray[uint8]): void = sha2InputC(ctx, input)
  template sha2_224Final*(ctx: var SHA2_224Ctx): array[28, uint8] = sha2FinalC(ctx)
  template sha2_224One*(input: lent openArray[uint8]): array[28, uint8] = sha2_224OneC(input)

  # SHA-2-256
  template sha2_256Init*(ctx: var SHA2_256Ctx): void = sha2InitC(ctx)
  template sha2_256Input*(ctx: var SHA2_256Ctx, input: lent openArray[uint8]): void = sha2InputC(ctx, input)
  template sha2_256Final*(ctx: var SHA2_256Ctx): array[32, uint8] = sha2FinalC(ctx)
  template sha2_256One*(input: lent openArray[uint8]): array[32, uint8] = sha2_256OneC(input)

  # SHA-2-384
  template sha2_384Init*(ctx: var SHA2_384Ctx): void = sha2InitC(ctx)
  template sha2_384Input*(ctx: var SHA2_384Ctx, input: lent openArray[uint8]): void = sha2InputC(ctx, input)
  template sha2_384Final*(ctx: var SHA2_384Ctx): array[48, uint8] = sha2FinalC(ctx)
  template sha2_384One*(input: lent openArray[uint8]): array[48, uint8] = sha2_384OneC(input)

  # SHA-2-512
  template sha2_512Init*(ctx: var SHA2_512Ctx): void = sha2InitC(ctx)
  template sha2_512Input*(ctx: var SHA2_512Ctx, input: lent openArray[uint8]): void = sha2InputC(ctx, input)
  template sha2_512Final*(ctx: var SHA2_512Ctx): array[64, uint8] = sha2FinalC(ctx)
  template sha2_512One*(input: lent openArray[uint8]): array[64, uint8] = sha2_512OneC(input)

  # SHA-2-512/224
  template sha2_512_224Init*(ctx: var SHA2_512_224Ctx): void = sha2InitC(ctx)
  template sha2_512_224Input*(ctx: var SHA2_512_224Ctx, input: lent openArray[uint8]): void = sha2InputC(ctx, input)
  template sha2_512_224Final*(ctx: var SHA2_512_224Ctx): array[28, uint8] = sha2FinalC(ctx)
  template sha2_512_224One*(input: lent openArray[uint8]): array[28, uint8] = sha2_512_224OneC(input)

  # SHA-2-512/256
  template sha2_512_256Init*(ctx: var SHA2_512_256Ctx): void = sha2InitC(ctx)
  template sha2_512_256Input*(ctx: var SHA2_512_256Ctx, input: lent openArray[uint8]): void = sha2InputC(ctx, input)
  template sha2_512_256Final*(ctx: var SHA2_512_256Ctx): array[32, uint8] = sha2FinalC(ctx)
  template sha2_512_256One*(input: lent openArray[uint8]): array[32, uint8] = sha2_512_256OneC(input)
else:
  # SHA-2-224
  proc sha2_224Init*(ctx: var SHA2_224Ctx): void = sha2InitC(ctx)
  proc sha2_224Input*(ctx: var SHA2_224Ctx, input: openArray[uint8]): void = sha2InputC(ctx, input)
  proc sha2_224Final*(ctx: var SHA2_224Ctx): array[28, uint8] = return sha2FinalC(ctx)
  proc sha2_224One*(input: openArray[uint8]): array[28, uint8] = return sha2_224OneC(input)

  # SHA-2-256
  proc sha2_256Init*(ctx: var SHA2_256Ctx): void = sha2InitC(ctx)
  proc sha2_256Input*(ctx: var SHA2_256Ctx, input: openArray[uint8]): void = sha2InputC(ctx, input)
  proc sha2_256Final*(ctx: var SHA2_256Ctx): array[32, uint8] = return sha2FinalC(ctx)
  proc sha2_256One*(input: openArray[uint8]): array[32, uint8] = return sha2_256OneC(input)

  # SHA-2-384
  proc sha2_384Init*(ctx: var SHA2_384Ctx): void = sha2InitC(ctx)
  proc sha2_384Input*(ctx: var SHA2_384Ctx, input: openArray[uint8]): void = sha2InputC(ctx, input)
  proc sha2_384Final*(ctx: var SHA2_384Ctx): array[48, uint8] = return sha2FinalC(ctx)
  proc sha2_384One*(input: openArray[uint8]): array[48, uint8] = return sha2_384OneC(input)

  # SHA-2-512
  proc sha2_512Init*(ctx: var SHA2_512Ctx): void = sha2InitC(ctx)
  proc sha2_512Input*(ctx: var SHA2_512Ctx, input: openArray[uint8]): void = sha2InputC(ctx, input)
  proc sha2_512Final*(ctx: var SHA2_512Ctx): array[64, uint8] = return sha2FinalC(ctx)
  proc sha2_512One*(input: openArray[uint8]): array[64, uint8] = return sha2_512OneC(input)

  # SHA-2-512/224
  proc sha2_512_224Init*(ctx: var SHA2_512_224Ctx): void = sha2InitC(ctx)
  proc sha2_512_224Input*(ctx: var SHA2_512_224Ctx, input: openArray[uint8]): void = sha2InputC(ctx, input)
  proc sha2_512_224Final*(ctx: var SHA2_512_224Ctx): array[28, uint8] = return sha2FinalC(ctx)
  proc sha2_512_224One*(input: openArray[uint8]): array[28, uint8] = return sha2_512_224OneC(input)

  # SHA-2-512/256
  proc sha2_512_256Init*(ctx: var SHA2_512_256Ctx): void = sha2InitC(ctx)
  proc sha2_512_256Input*(ctx: var SHA2_512_256Ctx, input: openArray[uint8]): void = sha2InputC(ctx, input)
  proc sha2_512_256Final*(ctx: var SHA2_512_256Ctx): array[32, uint8] = return sha2FinalC(ctx)
  proc sha2_512_256One*(input: openArray[uint8]): array[32, uint8] = return sha2_512_256OneC(input)

when defined(test):
  var s: seq[uint8] = charToBin("Hello, World!")
  var ctx224: SHA2_224Ctx
  sha2_224Init(ctx224)
  sha2_224Input(ctx224, s)
  echo "SHA2-224 One : ", binToHex(sha2_224One(s))
  echo "SHA2-224 Stream : ", binToHex(sha2_224Final(ctx224))
  echo "SHA2-224 Standard : 72A23DFA411BA6FDE01DBFABF3B00A709C93EBF273DC29E2D8B261FF"
  var ctx256: SHA2_256Ctx
  sha2_256Init(ctx256)
  sha2_256Input(ctx256, s)
  echo "SHA2-256 One : ", binToHex(sha2_256One(s))
  echo "SHA2-256 Stream : ", binToHex(sha2_256Final(ctx256))
  echo "SHA2-256 Standard : DFFD6021BB2BD5B0AF676290809EC3A53191DD81C7F70A4B28688A362182986F"
  var ctx384: SHA2_384Ctx
  sha2_384Init(ctx384)
  sha2_384Input(ctx384, s)
  echo "SHA2-384 One : ", binToHex(sha2_384One(s))
  echo "SHA2-384 Stream : ", binToHex(sha2_384Final(ctx384))
  echo "SHA2-384 Standard : 5485CC9B3365B4305DFB4E8337E0A598A574F8242BF17289E0DD6C20A3CD44A089DE16AB4AB308F63E44B1170EB5F515"
  var ctx512: SHA2_512Ctx
  sha2_512Init(ctx512)
  sha2_512Input(ctx512, s)
  echo "SHA2-512 One : ", binToHex(sha2_512One(s))
  echo "SHA2-512 Stream : ", binToHex(sha2_512Final(ctx512))
  echo "SHA2-512 Standard : 374D794A95CDCFD8B35993185FEF9BA368F160D8DAF432D08BA9F1ED1E5ABE6CC69291E0FA2FE0006A52570EF18C19DEF4E617C33CE52EF0A6E5FBE318CB0387"
  var ctx512_224: SHA2_512_224Ctx
  sha2_512_224Init(ctx512_224)
  sha2_512_224Input(ctx512_224, s)
  echo "SHA2-512-224 One : ", binToHex(sha2_512_224One(s))
  echo "SHA2-512-224 Stream : ", binToHex(sha2_512_224Final(ctx512_224))
  echo "SHA2-512-224 Standard : 766745F058E8A0438F19DE48AE56EA5F123FE738AF39BCA050A7547A"
  var ctx512_256: SHA2_512_256Ctx
  sha2_512_256Init(ctx512_256)
  sha2_512_256Input(ctx512_256, s)
  echo "SHA2-512-256 One : ", binToHex(sha2_512_256One(s))
  echo "SHA2-512-256 Stream : ", binToHex(sha2_512_256Final(ctx512_256))
  echo "SHA2-512-256 Standard : 0686F0A605973DC1BF035D1E2B9BAD1985A0BFF712DDD88ABD8D2593E5F99030"

  template benchmark(name: string, code: untyped) =
    let start = getMonoTime()
    code
    let elapsed = getMonoTime() - start
    echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

  var temp224: array[28, uint8]
  var temp256: array[32, uint8]
  var temp384: array[48, uint8]
  var temp512: array[64, uint8]
  var temp512_224: array[28, uint8]
  var temp512_256: array[32, uint8]

  benchmark("SHA2-224 Benchmark"):
    for i in 1 .. 1_000_000:
      sha2_224Init(ctx224)
      sha2_224Input(ctx224, temp224)
      temp224 = sha2_224Final(ctx224)

  benchmark("SHA2-256 Benchmark"):
    for i in 1 .. 1_000_000:
      sha2_256Init(ctx256)
      sha2_256Input(ctx256, temp256)
      temp256 = sha2_256Final(ctx256)

  benchmark("SHA2-384 Benchmark"):
    for i in 1 .. 1_000_000:
      sha2_384Init(ctx384)
      sha2_384Input(ctx384, temp384)
      temp384 = sha2_384Final(ctx384)

  benchmark("SHA2-512 Benchmark"):
    for i in 1 .. 1_000_000:
      sha2_512Init(ctx512)
      sha2_512Input(ctx512, temp512)
      temp512 = sha2_512Final(ctx512)

  benchmark("SHA2-512/224 Benchmark"):
    for i in 1 .. 1_000_000:
      sha2_512_224Init(ctx512_224)
      sha2_512_224Input(ctx512_224, temp512_224)
      temp512_224 = sha2_512_224Final(ctx512_224)

  benchmark("SHA2-512/256 Benchmark"):
    for i in 1 .. 1_000_000:
      sha2_512_256Init(ctx512_256)
      sha2_512_256Input(ctx512_256, temp512_256)
      temp512_256 = sha2_512_256Final(ctx512_256)
