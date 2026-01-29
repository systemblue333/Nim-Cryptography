import sequtils
import strutils
import ../../../../Utility/src/Utility/codeutils/indexutils
import ../../../../Utility/src/Utility/codeutils/bits
import ../../../../Utility/src/Utility/codeutils/errorutils
import ../../../../Utility/src/Utility/dataformat/dataformat

const k256: array[64, uint32] = [
    0x428a2f98'u32, 0x71374491'u32, 0xb5c0fbcf'u32, 0xe9b5dba5'u32, 0x3956c25b'u32, 0x59f111f1'u32, 0x923f82a4'u32, 0xab1c5ed5'u32,
    0xd807aa98'u32, 0x12835b01'u32, 0x243185be'u32, 0x550c7dc3'u32, 0x72be5d74'u32, 0x80deb1fe'u32, 0x9bdc06a7'u32, 0xc19bf174'u32,
    0xe49b69c1'u32, 0xefbe4786'u32, 0x0fc19dc6'u32, 0x240ca1cc'u32, 0x2de92c6f'u32, 0x4a7484aa'u32, 0x5cb0a9dc'u32, 0x76f988da'u32,
    0x983e5152'u32, 0xa831c66d'u32, 0xb00327c8'u32, 0xbf597fc7'u32, 0xc6e00bf3'u32, 0xd5a79147'u32, 0x06ca6351'u32, 0x14292967'u32,
    0x27b70a85'u32, 0x2e1b2138'u32, 0x4d2c6dfc'u32, 0x53380d13'u32, 0x650a7354'u32, 0x766a0abb'u32, 0x81c2c92e'u32, 0x92722c85'u32,
    0xa2bfe8a1'u32, 0xa81a664b'u32, 0xc24b8b70'u32, 0xc76c51a3'u32, 0xd192e819'u32, 0xd6990624'u32, 0xf40e3585'u32, 0x106aa070'u32,
    0x19a4c116'u32, 0x1e376c08'u32, 0x2748774c'u32, 0x34b0bcb5'u32, 0x391c0cb3'u32, 0x4ed8aa4a'u32, 0x5b9cca4f'u32, 0x682e6ff3'u32,
    0x748f82ee'u32, 0x78a5636f'u32, 0x84c87814'u32, 0x8cc70208'u32, 0x90befffa'u32, 0xa4506ceb'u32, 0xbef9a3f7'u32, 0xc67178f2'u32
  ]

const k512: array[80, uint64] = [
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

template encode32[N: static[int]](input: lent array[8, uint32], output: var array[N, uint8]): void =
  for i in static(0 ..< (N div 4)):
    var buffer: array[4, uint8]
    toBytesBE(input[i], buffer)
    for j in static(0 ..< 4):
      output[i * 4 + j] = buffer[j]

template encode64[N: static[int]](input: lent array[8, uint64], output: var array[N, uint8]): void =
  var full: array[64, uint8]
  for i in static(0 ..< 8):
    var buffer: array[8, uint8]
    toBytesBE(input[i], buffer)
    for j in static(0 ..< 8):
      full[i * 8 + j] = buffer[j]

  for i in static(0 ..< N):
    output[i] = full[i]

template padding256(input: var seq[uint8], bitLen: lent uint64): void =
   # declaring and initializing value of bit length
   # let bitLen = uint64(input.len * 8)

  # append a single '1' bit 0x80
  input.add(0x80'u8)

  # append K '0' bits (as bytes) until length = 56 mod 64
  while (input.len mod 64) != 56:
    input.add(0x00'u8)

  # append original length as 64-bits big-endian integer
  for i in countdown(7, 0):
    input.add(uint8((bitLen shr (i * 8)) and 0xFF))

template padding512(input: var seq[uint8], bitLen: lent uint64): void =
  # declaring and initializing value of bit length
  # let bitLen = uint64(input.len * 8)

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

template process256(chunk: var array[64, uint8], H: var array[8, uint32], k: array[64, uint32]): void =
  var w: array[64, uint32]

  for i in static(0..<16):
    w[i] = (uint32(chunk[i * 4]) shl 24) or
    (uint32(chunk[i * 4 + 1]) shl 16) or
    (uint32(chunk[i * 4 + 2]) shl 8) or
    uint32(chunk[i * 4 + 3])

  for i in static(16..<64):
    let s0 = rightRotate(w[i - 15], 7) xor rightRotate(w[i - 15], 18) xor (w[i - 15] shr 3)
    let s1 = rightRotate(w[i - 2], 17) xor rightRotate(w[i - 2], 19) xor (w[i - 2] shr 10)
    w[i] = w[i - 16] + s0 + w[i - 7] + s1

  var a: uint32 = H[0]
  var b: uint32 = H[1]
  var c: uint32 = H[2]
  var d: uint32 = H[3]
  var e: uint32 = H[4]
  var f: uint32 = H[5]
  var g: uint32 = H[6]
  var h: uint32 = H[7]

  for i in static(0..<64):
    let S1 = rightRotate(e, 6) xor rightRotate(e, 11) xor rightRotate(e, 25)
    let ch = (e and f) xor ((not e) and g)
    let temp1 = h + S1 + ch + k[i] + w[i]
    let S0 = rightRotate(a, 2) xor rightRotate(a, 13) xor rightRotate(a, 22)
    let maj = (a and b) xor (a and c) xor (b and c)
    let temp2 = S0 + maj

    h = g
    g = f
    f = e
    e = d + temp1
    d = c
    c = b
    b = a
    a = temp1 + temp2

  H[0] += a
  H[1] += b
  H[2] += c
  H[3] += d
  H[4] += e
  H[5] += f
  H[6] += g
  H[7] += h

template process512(chunk: var array[128, uint8], H: var array[8, uint64], k: array[80, uint64]): void =
  var w: array[80, uint64]

  for i in static(0..<16):
    w[i] = (uint64(chunk[i * 8]) shl 56) or
    (uint64(chunk[i * 8 + 1]) shl 48) or
    (uint64(chunk[i * 8 + 2]) shl 40) or
    (uint64(chunk[i * 8 + 3]) shl 32) or
    (uint64(chunk[i * 8 + 4]) shl 24) or
    (uint64(chunk[i * 8 + 5]) shl 16) or
    (uint64(chunk[i * 8 + 6]) shl 8) or
    uint64(chunk[i * 8 + 7])

  for i in static(16..<80):
    let s0 = rightRotate(w[i - 15], 1) xor rightRotate(w[i - 15], 8) xor (w[i - 15] shr 7)
    let s1 = rightRotate(w[i - 2], 19) xor rightRotate(w[i - 2], 61) xor (w[i - 2] shr 6)
    w[i] = w[i - 16] + s0 + w[i - 7] + s1

  var a: uint64 = H[0]
  var b: uint64 = H[1]
  var c: uint64 = H[2]
  var d: uint64 = H[3]
  var e: uint64 = H[4]
  var f: uint64 = H[5]
  var g: uint64 = H[6]
  var h: uint64 = H[7]

  for i in static(0..<80):
    let S1 = rightRotate(e,14) xor rightRotate(e,18) xor rightRotate(e,41)
    let ch = (e and f) xor ((not e) and g)
    let temp1 = h + S1 + ch + k[i] + w[i]
    let S0 = rightRotate(a,28) xor rightRotate(a,34) xor rightRotate(a,39)
    let maj = (a and b) xor (a and c) xor (b and c)
    let temp2 = S0 + maj

    h = g
    g = f
    f = e
    e = d + temp1
    d = c
    c = b
    b = a
    a = temp1 + temp2

  H[0] += a
  H[1] += b
  H[2] += c
  H[3] += d
  H[4] += e
  H[5] += f
  H[6] += g
  H[7] += h

template chunking256(input: lent seq[uint8], H: var array[8, uint32]): void =
  let chunkCount = input.len div 64

  for chunkIdx in 0 ..< chunkCount:
    var chunk: array[64, uint8]
    for i in static(0 ..< 64):
      chunk[i] = input[chunkIdx * 64 + i]
    process256(chunk, H, k256)

template chunking512(input: lent seq[uint8], H: var array[8, uint64]): void =
  let chunkCount = input.len div 128

  for chunkIdx in 0 ..< chunkCount:
    var chunk: array[128, uint8]
    for i in static(0 ..< 128):
      chunk[i] = input[chunkIdx * 128 + i]
    process512(chunk, H, k512)

template sha2_224OneC(msg: lent openArray[uint8]): array[28, uint8] =
  var output: array[28, uint8]
  var input: seq[uint8]
  for i in 0 ..< msg.len:
    input.add(msg[i])
  var H: array[8, uint32] = [
  0xc1059ed8'u32, 0x367cd507'u32, 0x3070dd17'u32, 0xf70e5939'u32, 0xffc00b31'u32, 0x68581511'u32, 0x64f98fa7'u32, 0xbefa4fa4'u32
  ]

  padding256(input, uint64(msg.len * 8))

  chunking256(input, H)

  encode32(H, output)

  output

template sha2_256OneC(msg: lent openArray[uint8]): array[32, uint8] =
  var output: array[32, uint8]
  var input: seq[uint8]
  for i in 0 ..< msg.len:
    input.add(msg[i])
  var H: array[8, uint32] = [
  0x6a09e667'u32, 0xbb67ae85'u32, 0x3c6ef372'u32, 0xa54ff53a'u32, 0x510e527f'u32, 0x9b05688c'u32, 0x1f83d9ab'u32, 0x5be0cd19'u32
  ]

  padding256(input, uint64(msg.len * 8))

  chunking256(input, H)

  encode32(H, output)

  output

template sha2_384OneC(msg: lent openArray[uint8]): array[48, uint8] =
  var output: array[48, uint8]
  var input: seq[uint8]
  for i in 0 ..< msg.len:
    input.add(msg[i])
  var H: array[8, uint64] = [
  0xcbbb9d5dc1059ed8'u64, 0x629a292a367cd507'u64, 0x9159015a3070dd17'u64, 0x152fecd8f70e5939'u64,
  0x67332667ffc00b31'u64, 0x8eb44a8768581511'u64, 0xdb0c2e0d64f98fa7'u64, 0x47b5481dbefa4fa4'u64
  ]

  padding512(input, uint64(msg.len * 8))

  chunking512(input, H)

  encode64(H, output)

  output

template sha2_512OneC(msg: lent openArray[uint8]): array[64, uint8] =
  var output: array[64, uint8]
  var input: seq[uint8]
  for i in 0 ..< msg.len:
    input.add(msg[i])
  var H: array[8, uint64] = [
  0x6a09e667f3bcc908'u64, 0xbb67ae8584caa73b'u64, 0x3c6ef372fe94f82b'u64, 0xa54ff53a5f1d36f1'u64,
  0x510e527fade682d1'u64, 0x9b05688c2b3e6c1f'u64, 0x1f83d9abfb41bd6b'u64, 0x5be0cd19137e2179'u64
  ]

  padding512(input, uint64(msg.len * 8))

  chunking512(input, H)

  encode64(H, output)

  output

template sha2_512_224OneC(msg: lent openArray[uint8]): array[28, uint8] =
  var output: array[28, uint8]
  var input: seq[uint8]
  for i in 0 ..< msg.len:
    input.add(msg[i])
  var H: array[8, uint64] = [
  0x8c3d37c819544da2'u64, 0x73e1996689dcd4d6'u64, 0x1dfab7ae32ff9c82'u64, 0x679dd514582f9fcf'u64,
  0x0f6d2b697bd44da8'u64, 0x77e36f7304C48942'u64, 0x3f9d85a86a1d36C8'u64, 0x1112e6ad91d692a1'u64
  ]

  padding512(input, uint64(msg.len * 8))

  chunking512(input, H)

  encode64(H, output)

  output

template sha2_512_256OneC(msg: lent openArray[uint8]): array[32, uint8] =
  var output: array[32, uint8]
  var input: seq[uint8]
  for i in 0 ..< msg.len:
    input.add(msg[i])
  var H: array[8, uint64] = [
  0x22312194fc2bf72c'u64, 0x9f555fa3c84c64c2'u64, 0x2393b86b6f53b151'u64, 0x963877195940eabd'u64,
  0x96283ee2a88effe3'u64, 0xbe5e1e2553863992'u64, 0x2b0199fc2c85b8aa'u64, 0x0eb72ddC81c52ca2'u64
  ]

  padding512(input, uint64(msg.len * 8))

  chunking512(input, H)

  encode64(H, output)

  output

const
  SHA2_224_DIGEST_SIZE*: int = 224 div 8
  SHA2_256_DIGEST_SIZE*: int = 256 div 8
  SHA2_384_DIGEST_SIZE*: int = 384 div 8
  SHA2_512_DIGEST_SIZE*: int = 512 div 8

  SHA2_256_BLOCK_SIZE*: int = 512 div 8
  SHA2_512_BLOCK_SIZE*: int = 1024 div 8
  SHA2_224_BLOCK_SIZE*: int = SHA2_256_BLOCK_SIZE
  SHA2_384_BLOCK_SIZE*: int = SHA2_512_BLOCK_SIZE
  SHA2_512_224_BLOCK_SIZE*: int = SHA2_512_BLOCK_SIZE
  SHA2_512_256_BLOCK_SIZE*: int = SHA2_512_BLOCK_SIZE

type
  SHA2_256Ctx* = object
    totLen*: uint64
    len*: uint64
    hashBlock*: array[2 * SHA2_256_BLOCK_SIZE, uint8]
    h*: array[8, uint32]
  SHA2_224Ctx* = object
    totLen*: uint64
    len*: uint64
    hashBlock*: array[2 * SHA2_224_BLOCK_SIZE, uint8]
    h*: array[8, uint32]
  SHA2_512Ctx* = object
    totLen*: uint64
    len*: uint64
    hashBlock*: array[2 * SHA2_512_BLOCK_SIZE, uint8]
    h*: array[8, uint64]
  SHA2_384Ctx* = object
    totLen*: uint64
    len*: uint64
    hashBlock*: array[2 * SHA2_384_BLOCK_SIZE, uint8]
    h*: array[8, uint64]
  SHA2_512_224Ctx* = object
    totLen*: uint64
    len*: uint64
    hashBlock*: array[2 * SHA2_512_224_BLOCK_SIZE, uint8]
    h*: array[8, uint64]
  SHA2_512_256Ctx* = object
    totLen*: uint64
    len*: uint64
    hashBlock*: array[2 * SHA2_512_256_BLOCK_SIZE, uint8]
    h*: array[8, uint64]

template streamProcess[T](ctx: var T, message: lent openArray[uint8], blockSize: int): void =
  let tmpLen: uint64 = blockSize.uint64 - ctx.len
  var remLen: uint64 = if message.len.uint64 < tmpLen: message.len.uint64 else: tmpLen

  for i in 0 ..< remLen:
    ctx.hashBlock[ctx.len + i] = message[i]

  if ctx.len + message.len.uint64 < blockSize.uint64:
    ctx.len += message.len.uint64
    return

  var newLen = message.len.uint64 - remLen
  let blockNb = newLen div blockSize.uint64

  var shiftedMessage: seq[uint8] = message[remLen ..< message.len]

  when ctx.h[0] is uint32:
    for i in 0 ..< int(ctx.hashBlock.len div 64):
      var buffer: array[64, uint8]
      for j in static(0 ..< 64):
        buffer[j] = ctx.hashBlock[i * 64 + j]

    for i in 0 ..< blockNb:
      var buffer: array[64, uint8]
      for j in static(0 ..< 64):
        buffer[j] = shiftedMessage[int(i * 64) + j]
      process256(buffer, ctx.h, k256)
  elif ctx.h[0] is uint64:
    for i in 0 ..< int(ctx.hashBlock.len div 128):
      var buffer: array[128, uint8]
      for j in static(0 ..< 128):
        buffer[j] = shiftedMessage[int(i * 128) + j]
      process512(buffer, ctx.h, k512)

  remLen = newLen mod blockSize.uint64

  for i in 0 ..< remLen:
    ctx.hashBlock[i] = shiftedMessage[blockNb.int * blockSize + i.int]

  ctx.len = remLen
  ctx.totLen += (blockNb + 1) * blockSize.uint64

template streamFinal[T, N](ctx: var T, output: var array[N, uint8]): void =
  var finalBlock: seq[uint8] = newSeq[uint8](ctx.len)
  for i in 0 ..< ctx.len:
    finalBlock[i] = ctx.hashBlock[i]

  var bitLen = (ctx.totLen + ctx.len) * 8
  ctx.totLen = ctx.totLen + ctx.len

  when ctx.h[0] is uint32:
    padding256(finalBlock, bitLen)
    for i in 0 ..< (finalBlock.len div 64):
      var buffer: array[64, uint8]
      for j in static(0 ..< 64):
        buffer[j] = finalBlock[i * 64 + j]
      process256(buffer, ctx.h, k256)

    encode32(ctx.h, output)
  elif ctx.h[0] is uint64:
    padding512(finalBlock, bitLen)

    for i in 0 ..< (finalBlock.len div 128):
      var buffer: array[128, uint8]
      for j in static(0 ..< 128):
        buffer[j] = finalBlock[i * 128 + j]
      process512(buffer, ctx.h, k512)

    encode64(ctx.h, output)

  ctx.len = 0

template sha2_224InitC(ctx: var SHA2_224Ctx): void =
  var H: array[8, uint32] = [
    0xc1059ed8'u32, 0x367cd507'u32, 0x3070dd17'u32, 0xf70e5939'u32, 0xffc00b31'u32, 0x68581511'u32, 0x64f98fa7'u32, 0xbefa4fa4'u32
    ]

  copyArray(H, ctx.h)

  ctx.len = 0
  ctx.tot_len = 0

template sha2_224InputC(ctx: var SHA2_224Ctx, message: openArray[uint8]): void =
  streamProcess(ctx, message, SHA2_224_BLOCK_SIZE)

template sha2_224FinalC(ctx: var SHA2_224Ctx): array[28, uint8] =
  var output: array[28, uint8]
  streamFinal(ctx, output)
  output

template sha2_256InitC(ctx: var SHA2_256Ctx): void =
  var H: array[8, uint32] = [
  0x6a09e667'u32, 0xbb67ae85'u32, 0x3c6ef372'u32, 0xa54ff53a'u32, 0x510e527f'u32, 0x9b05688c'u32, 0x1f83d9ab'u32, 0x5be0cd19'u32
  ]

  copyArray(H, ctx.h)

  ctx.len = 0
  ctx.totLen = 0

template sha2_256InputC(ctx: var SHA2_256Ctx, message: lent openArray[uint8]): void =
  streamProcess(ctx, message, SHA2_256_BLOCK_SIZE)

template sha2_256FinalC(ctx: var SHA2_256Ctx): array[32, uint8] =
  var output: array[32, uint8]
  streamFinal(ctx, output)
  output

template sha2_384InitC(ctx: var SHA2_384Ctx): void =
  var H: array[8, uint64] = [
  0xcbbb9d5dc1059ed8'u64, 0x629a292a367cd507'u64, 0x9159015a3070dd17'u64, 0x152fecd8f70e5939'u64,
  0x67332667ffc00b31'u64, 0x8eb44a8768581511'u64, 0xdb0c2e0d64f98fa7'u64, 0x47b5481dbefa4fa4'u64
  ]

  copyArray(H, ctx.h)

  ctx.len = 0
  ctx.totLen = 0

template sha2_384InputC(ctx: var SHA2_384Ctx, message: lent openArray[uint8]): void =
  streamProcess(ctx, message, SHA2_384_BLOCK_SIZE)

template sha2_384FinalC(ctx: var SHA2_384Ctx): array[48, uint8] =
  var output: array[48, uint8]
  streamFinal(ctx, output)
  output

template sha2_512InitC(ctx: var SHA2_512Ctx): void =
  var H: array[8, uint64] = [
  0x6a09e667f3bcc908'u64, 0xbb67ae8584caa73b'u64, 0x3c6ef372fe94f82b'u64, 0xa54ff53a5f1d36f1'u64,
  0x510e527fade682d1'u64, 0x9b05688c2b3e6c1f'u64, 0x1f83d9abfb41bd6b'u64, 0x5be0cd19137e2179'u64
  ]

  copyArray(H, ctx.h)

  ctx.len = 0
  ctx.totLen = 0

template sha2_512InputC(ctx: var SHA2_512Ctx, message: lent openArray[uint8]): void =
  streamProcess(ctx, message, SHA2_512_BLOCK_SIZE)

template sha2_512FinalC(ctx: var SHA2_512Ctx): array[64, uint8] =
  var output: array[64, uint8]
  streamFinal(ctx, output)
  output

template sha2_512_224InitC(ctx: var SHA2_512_224Ctx): void =
  var H: array[8, uint64] = [
  0x8c3d37c819544da2'u64, 0x73e1996689dcd4d6'u64, 0x1dfab7ae32ff9c82'u64, 0x679dd514582f9fcf'u64,
  0x0f6d2b697bd44da8'u64, 0x77e36f7304C48942'u64, 0x3f9d85a86a1d36C8'u64, 0x1112e6ad91d692a1'u64
  ]

  copyArray(H, ctx.h)

  ctx.len = 0
  ctx.totLen = 0

template sha2_512_224InputC(ctx: var SHA2_512_224Ctx, message: lent openArray[uint8]): void =
  streamProcess(ctx, message, SHA2_512_224_BLOCK_SIZE)

template sha2_512_224FinalC(ctx: var SHA2_512_224Ctx): array[28, uint8] =
  var output: array[28, uint8]
  streamFinal(ctx, output)
  output

template sha2_512_256InitC(ctx: var SHA2_512_256Ctx): void =
  var H: array[8, uint64] = [
  0x22312194fc2bf72c'u64, 0x9f555fa3c84c64c2'u64, 0x2393b86b6f53b151'u64, 0x963877195940eabd'u64,
  0x96283ee2a88effe3'u64, 0xbe5e1e2553863992'u64, 0x2b0199fc2c85b8aa'u64, 0x0eb72ddC81c52ca2'u64
  ]

  copyArray(H, ctx.h)

  ctx.len = 0
  ctx.totLen = 0

template sha2_512_256InputC(ctx: var SHA2_512_256Ctx, message: lent openArray[uint8]): void =
  streamProcess(ctx, message, SHA2_512_256_BLOCK_SIZE)

template sha2_512_256FinalC(ctx: var SHA2_512_256Ctx): array[32, uint8] =
  var output: array[32, uint8]
  streamFinal(ctx, output)
  output

when defined(templateOpt):
  # SHA2-224
  template sha2_224Init*(ctx: var SHA2_224Ctx): void = sha2_224InitC(ctx)
  template sha2_224Input*(ctx: var SHA2_224Ctx, input: lent openArray[uint8]): void = sha2_224InputC(ctx, input)

  # SHA2-256
  template sha2_256Init*(ctx: var SHA2_256Ctx): void = sha2_256InitC(ctx)
  template sha2_256Input*(ctx: var SHA2_256Ctx, input: lent openArray[uint8]): void = sha2_256InputC(ctx, input)

  # SHA2-384
  template sha2_384Init*(ctx: var SHA2_384Ctx): void = sha2_384InitC(ctx)
  template sha2_384Input*(ctx: var SHA2_384Ctx, input: lent openArray[uint8]): void = sha2_384InputC(ctx, input)

  # SHA2-512
  template sha2_512Init*(ctx: var SHA2_512Ctx): void = sha2_512InitC(ctx)
  template sha2_512Input*(ctx: var SHA2_512Ctx, input: lent openArray[uint8]): void = sha2_512InputC(ctx, input)

  # SHA2-512/224 & 256
  template sha2_512_224Init*(ctx: var SHA2_512_224Ctx): void = sha2_512_224InitC(ctx)
  template sha2_512_224Input*(ctx: var SHA2_512_224Ctx, input: lent openArray[uint8]): void = sha2_512_224InputC(ctx, input)
  template sha2_512_256Init*(ctx: var SHA2_512_256Ctx): void = sha2_512_256InitC(ctx)
  template sha2_512_256Input*(ctx: var SHA2_512_256Ctx, input: lent openArray[uint8]): void = sha2_512_256InputC(ctx, input)

  # Final Wrappers with varOpt
  when defined(varOpt):
    template sha2_224Final*(ctx: var SHA2_224Ctx, output: var array[28, uint8]): void = output = sha2_224FinalC(ctx)
    template sha2_256Final*(ctx: var SHA2_256Ctx, output: var array[32, uint8]): void = output = sha2_256FinalC(ctx)
    template sha2_384Final*(ctx: var SHA2_384Ctx, output: var array[48, uint8]): void = output = sha2_384FinalC(ctx)
    template sha2_512Final*(ctx: var SHA2_512Ctx, output: var array[64, uint8]): void = output = sha2_512FinalC(ctx)
    template sha2_512_224Final*(ctx: var SHA2_512_224Ctx, output: var array[28, uint8]): void = output = sha2_512_224FinalC(ctx)
    template sha2_512_256Final*(ctx: var SHA2_512_256Ctx, output: var array[32, uint8]): void = output = sha2_512_256FinalC(ctx)
    template sha2_224One*(input: lent openArray[uint8], output: var array[28, uint8]): void = output = sha2_224OneC(input)
    template sha2_256One*(input: lent openArray[uint8], output: var array[32, uint8]): void = output = sha2_256OneC(input)
    template sha2_384One*(input: lent openArray[uint8], output: var array[48, uint8]): void = output = sha2_384OneC(input)
    template sha2_512One*(input: lent openArray[uint8], output: var array[64, uint8]): void = output = sha2_512OneC(input)
    template sha2_512_224One*(input: lent openArray[uint8], output: var array[28, uint8]): void = output = sha2_512_224OneC(input)
    template sha2_512_256One*(input: lent openArray[uint8], output: var array[32, uint8]): void = output = sha2_512_256OneC(input)
  else:
    template sha2_224Final*(ctx: var SHA2_224Ctx): array[28, uint8] = sha2_224FinalC(ctx)
    template sha2_256Final*(ctx: var SHA2_256Ctx): array[32, uint8] = sha2_256FinalC(ctx)
    template sha2_384Final*(ctx: var SHA2_384Ctx): array[48, uint8] = sha2_384FinalC(ctx)
    template sha2_512Final*(ctx: var SHA2_512Ctx): array[64, uint8] = sha2_512FinalC(ctx)
    template sha2_512_224Final*(ctx: var SHA2_512_224Ctx): array[28, uint8] = sha2_512_224FinalC(ctx)
    template sha2_512_256Final*(ctx: var SHA2_512_256Ctx): array[32, uint8] = sha2_512_256FinalC(ctx)
    template sha2_224One*(input: lent openArray[uint8]): array[28, uint8] = sha2_224OneC(input)
    template sha2_256One*(input: lent openArray[uint8]): array[32, uint8] = sha2_256OneC(input)
    template sha2_384One*(input: lent openArray[uint8]): array[48, uint8] = sha2_384OneC(input)
    template sha2_512One*(input: lent openArray[uint8]): array[64, uint8] = sha2_512OneC(input)
    template sha2_512_224One*(input: lent openArray[uint8]): array[28, uint8] = sha2_512_224OneC(input)
    template sha2_512_256One*(input: lent openArray[uint8]): array[32, uint8] = sha2_512_256OneC(input)
else:
  # Procs for runtime stability
  proc sha2_224Init*(ctx: var SHA2_224Ctx): void = sha2_224InitC(ctx)
  proc sha2_224Input*(ctx: var SHA2_224Ctx, input: openArray[uint8]): void = sha2_224InputC(ctx, input)

  proc sha2_256Init*(ctx: var SHA2_256Ctx): void = sha2_256InitC(ctx)
  proc sha2_256Input*(ctx: var SHA2_256Ctx, input: openArray[uint8]): void = sha2_256InputC(ctx, input)

  proc sha2_384Init*(ctx: var SHA2_384Ctx): void = sha2_384InitC(ctx)
  proc sha2_384Input*(ctx: var SHA2_384Ctx, input: openArray[uint8]): void = sha2_384InputC(ctx, input)

  proc sha2_512Init*(ctx: var SHA2_512Ctx): void = sha2_512InitC(ctx)
  proc sha2_512Input*(ctx: var SHA2_512Ctx, input: openArray[uint8]): void = sha2_512InputC(ctx, input)

  proc sha2_512_224Init*(ctx: var SHA2_512_224Ctx): void = sha2_512_224InitC(ctx)
  proc sha2_512_224Input*(ctx: var SHA2_512_224Ctx, input: openArray[uint8]): void = sha2_512_224InputC(ctx, input)
  proc sha2_512_256Init*(ctx: var SHA2_512_256Ctx): void = sha2_512_256InitC(ctx)
  proc sha2_512_256Input*(ctx: var SHA2_512_256Ctx, input: openArray[uint8]): void = sha2_512_256InputC(ctx, input)

  when defined(varOpt):
    proc sha2_224Final*(ctx: var SHA2_224Ctx, output: var array[28, uint8]): void = output = sha2_224FinalC(ctx)
    proc sha2_256Final*(ctx: var SHA2_256Ctx, output: var array[32, uint8]): void = output = sha2_256FinalC(ctx)
    proc sha2_384Final*(ctx: var SHA2_384Ctx, output: var array[48, uint8]): void = output = sha2_384FinalC(ctx)
    proc sha2_512Final*(ctx: var SHA2_512Ctx, output: var array[64, uint8]): void = output = sha2_512FinalC(ctx)
    proc sha2_512_224Final*(ctx: var SHA2_512_224Ctx, output: var array[28, uint8]): void = output = sha2_512_224FinalC(ctx)
    proc sha2_512_256Final*(ctx: var SHA2_512_256Ctx, output: var array[32, uint8]): void = output = sha2_512_256FinalC(ctx)
    proc sha2_224One*(input: openArray[uint8], output: var array[28, uint8]): void = output = sha2_224OneC(input)
    proc sha2_256One*(input: openArray[uint8], output: var array[32, uint8]): void = output = sha2_256OneC(input)
    proc sha2_384One*(input: openArray[uint8], output: var array[48, uint8]): void = output = sha2_384OneC(input)
    proc sha2_512One*(input: openArray[uint8], output: var array[64, uint8]): void = output = sha2_512OneC(input)
    proc sha2_512_224One*(input: openArray[uint8], output: var array[28, uint8]): void = output = sha2_512_224OneC(input)
    proc sha2_512_256One*(input: openArray[uint8], output: var array[32, uint8]): void = output = sha2_512_256OneC(input)
  else:
    proc sha2_224Final*(ctx: var SHA2_224Ctx): array[28, uint8] = return sha2_224FinalC(ctx)
    proc sha2_256Final*(ctx: var SHA2_256Ctx): array[32, uint8] = return sha2_256FinalC(ctx)
    proc sha2_384Final*(ctx: var SHA2_384Ctx): array[48, uint8] = return sha2_384FinalC(ctx)
    proc sha2_512Final*(ctx: var SHA2_512Ctx): array[64, uint8] = return sha2_512FinalC(ctx)
    proc sha2_512_224Final*(ctx: var SHA2_512_224Ctx): array[28, uint8] = return sha2_512_224FinalC(ctx)
    proc sha2_512_256Final*(ctx: var SHA2_512_256Ctx): array[32, uint8] = return sha2_512_256FinalC(ctx)
    proc sha2_224One*(input: openArray[uint8]): array[28, uint8] = sha2_224OneC(input)
    proc sha2_256One*(input: openArray[uint8]): array[32, uint8] = sha2_256OneC(input)
    proc sha2_384One*(input: openArray[uint8]): array[48, uint8] = sha2_384OneC(input)
    proc sha2_512One*(input: openArray[uint8]): array[64, uint8] = sha2_512OneC(input)
    proc sha2_512_224One*(input: openArray[uint8]): array[28, uint8] = sha2_512_224OneC(input)
    proc sha2_512_256One*(input: openArray[uint8]): array[32, uint8] = sha2_512_256OneC(input)


var s: seq[uint8] = charToBin("Hello, World!")
echo binToHex(sha2_256One(s))
