import strutils
import sequtils
import ../../../../Utility/src/Utility/codeutils/indexutils
import ../../../../Utility/src/Utility/codeutils/bits
import ../../../../Utility/src/Utility/codeutils/errorutils
import ../../../../Utility/src/Utility/dataformat/dataformat
import bitops
import std/[monotimes, times]

# declare keccak types
type
  # keccak kind enum
  KeccakKind* = enum
    SHA3
    Keccak
    Shake

  # keccak general context
  KeccakCtx*[bits: static[int], kind: static[KeccakKind]] = object
    state*: array[25 * 8, uint8] # 200 bytes, 1600 bits
    pt*: int

  # Keccak/SHA-3/Shake context
  Keccak224Ctx* = KeccakCtx[224, Keccak]
  Keccak256Ctx* = KeccakCtx[256, Keccak]
  Keccak384Ctx* = KeccakCtx[384, Keccak]
  Keccak512Ctx* = KeccakCtx[512, Keccak]
  SHA3_224Ctx* = KeccakCtx[224, SHA3]
  SHA3_256Ctx* = KeccakCtx[256, SHA3]
  SHA3_384Ctx* = KeccakCtx[384, SHA3]
  SHA3_512Ctx* = KeccakCtx[512, SHA3]
  Shake128Ctx* = KeccakCtx[128, Shake]
  Shake256Ctx* = KeccakCtx[256, Shake]

  # concept of Keccak and SHA-3 List
  KeccakList* = Keccak224Ctx | Keccak256Ctx | Keccak384Ctx | Keccak512Ctx | SHA3_224Ctx | SHA3_256Ctx | SHA3_384Ctx | SHA3_512Ctx

# declare constant
const
  RNDC = [
    0x0000000000000001'u64, 0x0000000000008082'u64, 0x800000000000808A'u64,
    0x8000000080008000'u64, 0x000000000000808B'u64, 0x0000000080000001'u64,
    0x8000000080008081'u64, 0x8000000000008009'u64, 0x000000000000008A'u64,
    0x0000000000000088'u64, 0x0000000080008009'u64, 0x000000008000000A'u64,
    0x000000008000808B'u64, 0x800000000000008B'u64, 0x8000000000008089'u64,
    0x8000000000008003'u64, 0x8000000000008002'u64, 0x8000000000000080'u64,
    0x000000000000800A'u64, 0x800000008000000A'u64, 0x8000000080008081'u64,
    0x8000000000008080'u64, 0x0000000080000001'u64, 0x8000000080008008'u64
  ]

# calculate column's parity by xor each column's 5 data
template theta1(a: var openArray[uint64], b: openArray[uint64], c: int): void =
  a[c] = b[c] xor b[c + 5] xor b[c + 10] xor b[c + 15] xor b[c + 20]

# mix current column with left/right side column's data
template theta2(a: var uint64, b: openArray[uint64], c: int): void =
  a = b[(c + 4) mod 5] xor rotateLeftBits(uint64(b[(c + 1) mod 5]), 1)

# update value by applying calculated parity to state's row
template theta3(a: var openARray[uint64], b: int, c: uint64): void =
  a[b] = a[b] xor c
  a[b + 5] = a[b + 5] xor c
  a[b + 10] = a[b + 10] xor c
  a[b + 15] = a[b + 15] xor c
  a[b + 20] = a[b + 20] xor c

# left rotate each lane's bits as specific ount
# replace each lane's location under 5 x 5 matrix
template rhopi(a: var openArray[uint64], b: var openArray[uint64], c: var uint64, d, e: int): void =
  a[0] = b[d]
  b[d] = rotateLeftBits(c, e)
  c = a[0]

# inject non-linearity
template chi(a: var openArray[uint64], b: var openArray[uint64], c: int): void =
  a[0] = b[c]
  a[1] = b[c + 1]
  a[2] = b[c + 2]
  a[3] = b[c + 3]
  a[4] = b[c + 4]
  b[c] = b[c] xor (not(a[1]) and a[2])
  b[c + 1] = b[c + 1] xor (not(a[2]) and a[3])
  b[c + 2] = b[c + 2] xor (not(a[3]) and a[4])
  b[c + 3] = b[c + 3] xor (not(a[4]) and a[0])
  b[c + 4] = b[c + 4] xor (not(a[0]) and a[1])

# round template for keccak
template keccakRound(a: var openArray[uint64], b: var openArray[uint64], c: var uint64, r: int): void =
  theta1(b, a, 0)
  theta1(b, a, 1)
  theta1(b, a, 2)
  theta1(b, a, 3)
  theta1(b, a, 4)

  theta2(c, b, 0)
  theta3(a, 0, c)
  theta2(c, b, 1)
  theta3(a, 1, c)
  theta2(c, b, 2)
  theta3(a, 2, c)
  theta2(c, b, 3)
  theta3(a, 3, c)
  theta2(c, b, 4)
  theta3(a, 4, c)

  c = a[1]
  rhopi(b, a, c, 10, 1)
  rhopi(b, a, c, 7, 3)
  rhopi(b, a, c, 11, 6)
  rhopi(b, a, c, 17, 10)
  rhopi(b, a, c, 18, 15)
  rhopi(b, a, c, 3, 21)
  rhopi(b, a, c, 5, 28)
  rhopi(b, a, c, 16, 36)
  rhopi(b, a, c, 8, 45)
  rhopi(b, a, c, 21, 55)
  rhopi(b, a, c, 24, 2)
  rhopi(b, a, c, 4, 14)
  rhopi(b, a, c, 15, 27)
  rhopi(b, a, c, 23, 41)
  rhopi(b, a, c, 19, 56)
  rhopi(b, a, c, 13, 8)
  rhopi(b, a, c, 12, 25)
  rhopi(b, a, c, 2, 43)
  rhopi(b, a, c, 20, 62)
  rhopi(b, a, c, 14, 18)
  rhopi(b, a, c, 22, 39)
  rhopi(b, a, c, 9, 61)
  rhopi(b, a, c, 6, 20)
  rhopi(b, a, c, 1, 44)

  chi(b, a, 0)
  chi(b, a, 5)
  chi(b, a, 10)
  chi(b, a, 15)
  chi(b, a, 20)

  a[0] = a[0] xor RNDC[r]

# keccak transform part
template keccakTransform(data: var array[200, uint8]): void =
  # declare variables
  var bc: array[5, uint64]
  var state: array[25, uint64]
  var t: uint64

  # decode state to data
  decodeLE(data, state)

  # call keccak round template
  for i in static(0 ..< 24):
    keccakRound(state, bc, t, i)

  encodeLE(state, data)

# get size of block
template sizeBlock*(ctx: lent KeccakCtx): uint =
  (200)

# get size of r
template rsize(ctx: lent KeccakCtx): int =
  200 - 2 * (ctx.bits div 8)

# get size of digest
template sizeDigest*(r: lent typedesc[KeccakList | Shake128Ctx | Shake256Ctx]): int =
  when r is Shake128:
    (16)
  elif r is Keccak224 or r is SHA3_224:
    (28)
  elif r is Keccak256 or r is SHA3_256 or r is Shake256:
    (32)
  elif r is Keccak384 or r is SHA3_384:
    (48)
  elif r is Keccak512 or r is SHA3_512:
    (64)

# sha3 init core
template sha3InitC[bits: static[int], kind: static[KeccakKind]](ctx: var KeccakCtx[bits, kind]): void =
  # initialize state
  for i in static(0 ..< 200):
    ctx.state[i] = 0x00'u8
  # initialize index
  ctx.pt = 0

# sha3 input core
template sha3InputC[bits: static[int], kind: static[KeccakKind]](ctx: var KeccakCtx[bits, kind], input: lent openArray[uint8]): void =
  var j = ctx.pt
  if input.len > 0:
    # copy input to state
    for i in 0 ..< input.len:
      ctx.state[j] = ctx.state[j] xor input[i]
      j.inc

      if j >= ctx.rsize:
        # call transform template
        keccakTransform(ctx.state)
        j = 0
    # set index
    ctx.pt = j

# sha3 final core
template sha3FinalC[bits: static int, kind: static KeccakKind](ctx: var KeccakCtx[bits, kind]): array[bits div 8, uint8] =
  # declare output
  var output: array[bits div 8, uint8]
  # add kind padding
  when kind == SHA3:
    ctx.state[ctx.pt] = ctx.state[ctx.pt] xor 0x06'u8
  else:
    ctx.state[ctx.pt] = ctx.state[ctx.pt] xor 0x01'u8

  # add padding
  ctx.state[ctx.rsize - 1] = ctx.state[ctx.rsize - 1] xor 0x80'u8

  # call keccak transform
  keccakTransform(ctx.state)

  # copy state to output
  for i in static(0 ..< (bits div 8)):
    output[i] = ctx.state[i]

  output

# shake xof core
template shakeXofC[bits: static int, kind: static KeccakKind](ctx: var KeccakCtx[bits, kind]): void =
  # check ctx kind in compile time
  static:
    doAssert kind == Shake, "xof's ctx must be shake"

  # add pading
  ctx.state[ctx.pt] = ctx.state[ctx.pt] xor 0x1F'u8
  ctx.state[ctx.rsize - 1] = ctx.state[ctx.rsize - 1] xor 0x80'u8

  # call keccak transform template
  keccakTransform(ctx.state)

  # set index to zero
  ctx.pt = 0

template shakeFinalC*[bits: static int, kind: static KeccakKind](ctx: var KeccakCtx[bits, kind], output: var openArray[uint8]): void =
  # check ctx kind in compile time
  static:
    doAssert kind == Shake, "xof's ctx must be shake"

  var j = ctx.pt
  for i in 0 ..< output.len:
    if j >= ctx.rsize:
      # call keccak transform template
      keccakTransform(ctx.state)
      j = 0

    # copy state to output
    output[i] = ctx.state[j]
    inc(j)

  # set index to j
  ctx.pt = j

# export wrappers
when defined(templateOpt):
  # Keccak-224
  template keccak224Init*(ctx: var Keccak224Ctx): void = sha3InitC(ctx)
  template keccak224Input*(ctx: var Keccak224Ctx, input: lent openArray[uint8]): void = sha3InputC(ctx, input)
  template keccak224Final*(ctx: var Keccak224Ctx): array[28, uint8] = sha3FinalC(ctx)

  # Keccak-256
  template keccak256Init*(ctx: var Keccak256Ctx): void = sha3InitC(ctx)
  template keccak256Input*(ctx: var Keccak256Ctx, input: lent openArray[uint8]): void = sha3InputC(ctx, input)
  template keccak256Final*(ctx: var Keccak256Ctx): array[32, uint8] = sha3FinalC(ctx)

  # Keccak-384
  template keccak384Init*(ctx: var Keccak384Ctx): void = sha3InitC(ctx)
  template keccak384Input*(ctx: var Keccak384Ctx, input: lent openArray[uint8]): void = sha3InputC(ctx, input)
  template keccak384Final*(ctx: var Keccak384Ctx): array[48, uint8] = sha3FinalC(ctx)

  # Keccak-512
  template keccak512Init*(ctx: var Keccak512Ctx): void = sha3InitC(ctx)
  template keccak512Input*(ctx: var Keccak512Ctx, input: lent openArray[uint8]): void = sha3InputC(ctx, input)
  template keccak512Final*(ctx: var Keccak512Ctx): array[64, uint8] = sha3FinalC(ctx)

  # SHA3-224
  template sha3_224Init*(ctx: var SHA3_224Ctx): void = sha3InitC(ctx)
  template sha3_224Input*(ctx: var SHA3_224Ctx, input: lent openArray[uint8]): void = sha3InputC(ctx, input)
  template sha3_224Final*(ctx: var SHA3_224Ctx): array[28, uint8] = sha3FinalC(ctx)

  # SHA3-256
  template sha3_256Init*(ctx: var SHA3_256Ctx): void = sha3InitC(ctx)
  template sha3_256Input*(ctx: var SHA3_256Ctx, input: lent openArray[uint8]): void = sha3InputC(ctx, input)
  template sha3_256Final*(ctx: var SHA3_256Ctx): array[32, uint8] = sha3FinalC(ctx)

  # SHA3-384
  template sha3_384Init*(ctx: var SHA3_384Ctx): void = sha3InitC(ctx)
  template sha3_384Input*(ctx: var SHA3_384Ctx, input: lent openArray[uint8]): void = sha3InputC(ctx, input)
  template sha3_384Final*(ctx: var SHA3_384Ctx): array[48, uint8] = sha3FinalC(ctx)

  # SHA3-512
  template sha3_512Init*(ctx: var SHA3_512Ctx): void = sha3InitC(ctx)
  template sha3_512Input*(ctx: var SHA3_512Ctx, input: lent openArray[uint8]): void = sha3InputC(ctx, input)
  template sha3_512Final*(ctx: var SHA3_512Ctx): array[64, uint8] = sha3FinalC(ctx)

  # Shake-128
  template shake128Init*(ctx: var Shake128Ctx): void = sha3InitC(ctx)
  template shake128Input*(ctx: var Shake128Ctx, input: lent openArray[uint8]): void = sha3InputC(ctx, input)
  template shake128Xof*(ctx: var Shake128Ctx): void = shakeXofC(ctx)
  template shake128Final*(ctx: var Shake128Ctx, output: var openArray[uint8]): void = shakeFinalC(ctx, output)

  # Shake-256
  template shake256Init*(ctx: var Shake256Ctx): void = sha3InitC(ctx)
  template shake256Input*(ctx: var Shake256Ctx, input: lent openArray[uint8]): void = sha3InputC(ctx, input)
  template shake256Xof*(ctx: var Shake256Ctx): void = shakeXofC(ctx)
  template shake256Final*(ctx: var Shake256Ctx, output: var openArray[uint8]): void = shakeFinalC(ctx, output)
else:
  # Keccak-224
  proc keccak224Init*(ctx: var Keccak224Ctx): void = sha3InitC(ctx)
  proc keccak224Input*(ctx: var Keccak224Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
  proc keccak224Final*(ctx: var Keccak224Ctx): array[28, uint8] = return sha3FinalC(ctx)

  # Keccak-256
  proc keccak256Init*(ctx: var Keccak256Ctx): void = sha3InitC(ctx)
  proc keccak256Input*(ctx: var Keccak256Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
  proc keccak256Final*(ctx: var Keccak256Ctx): array[32, uint8] = return sha3FinalC(ctx)

  # Keccak-384
  proc keccak384Init*(ctx: var Keccak384Ctx): void = sha3InitC(ctx)
  proc keccak384Input*(ctx: var Keccak384Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
  proc keccak384Final*(ctx: var Keccak384Ctx): array[48, uint8] = return sha3FinalC(ctx)

  # Keccak-512
  proc keccak512Init*(ctx: var Keccak512Ctx): void = sha3InitC(ctx)
  proc keccak512Input*(ctx: var Keccak512Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
  proc keccak512Final*(ctx: var Keccak512Ctx): array[64, uint8] = return sha3FinalC(ctx)

  # SHA3-224
  proc sha3_224Init*(ctx: var SHA3_224Ctx): void = sha3InitC(ctx)
  proc sha3_224Input*(ctx: var SHA3_224Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
  proc sha3_224Final*(ctx: var SHA3_224Ctx): array[28, uint8] = return sha3FinalC(ctx)

  # SHA3-256
  proc sha3_256Init*(ctx: var SHA3_256Ctx): void = sha3InitC(ctx)
  proc sha3_256Input*(ctx: var SHA3_256Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
  proc sha3_256Final*(ctx: var SHA3_256Ctx): array[32, uint8] = return sha3FinalC(ctx)

  # SHA3-384
  proc sha3_384Init*(ctx: var SHA3_384Ctx): void = sha3InitC(ctx)
  proc sha3_384Input*(ctx: var SHA3_384Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
  proc sha3_384Final*(ctx: var SHA3_384Ctx): array[48, uint8] = return sha3FinalC(ctx)

  # SHA3-512
  proc sha3_512Init*(ctx: var SHA3_512Ctx): void = sha3InitC(ctx)
  proc sha3_512Input*(ctx: var SHA3_512Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
  proc sha3_512Final*(ctx: var SHA3_512Ctx): array[64, uint8] = return sha3FinalC(ctx)

  # Shake-128
  proc shake128Init*(ctx: var Shake128Ctx): void = sha3InitC(ctx)
  proc shake128Input*(ctx: var Shake128Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
  proc shake128Xof*(ctx: var Shake128Ctx): void = shakeXofC(ctx)
  proc shake128Final*(ctx: var Shake128Ctx, output: var openArray[uint8]): void = shakeFinalC(ctx, output)

  # Shake-256
  proc shake256Init*(ctx: var Shake256Ctx): void = sha3InitC(ctx)
  proc shake256Input*(ctx: var Shake256Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
  proc shake256Xof*(ctx: var Shake256Ctx): void = shakeXofC(ctx)
  proc shake256Final*(ctx: var Shake256Ctx, output: var openArray[uint8]): void = shakeFinalC(ctx, output)


when defined(test):
  var s: seq[uint8] = charToBin("Hello, World!")
  var sha3_224: SHA3_224Ctx
  sha3_224Init(sha3_224)
  sha3_224Input(sha3_224, s)
  echo "SHA3-224 Stream : ", binToHex(sha3_224Final(sha3_224))
  echo "SHA3-224 Standard : 853048FB8B11462B6100385633C0CC8DCDC6E2B8E376C28102BC84F2"
  var sha3_256: SHA3_256Ctx
  sha3_256Init(sha3_256)
  sha3_256Input(sha3_256, s)
  echo "SHA3-256 Stream : ", binToHex(sha3_256Final(sha3_256))
  echo "SHA3-256 Standard : 1AF17A664E3FA8E419B8BA05C2A173169DF76162A5A286E0C405B460D478F7EF"
  var sha3_384: SHA3_384Ctx
  sha3_384Init(sha3_384)
  sha3_384Input(sha3_384, s)
  echo "SHA3-384 Stream : ", binToHex(sha3_384Final(sha3_384))
  echo "SHA3-384 Standard : AA9AD8A49F31D2DDCABBB7010A1566417CFF803FEF50EBA239558826F872E468C5743E7F026B0A8E5B2D7A1CC465CDBE"
  var sha3_512: SHA3_512Ctx
  sha3_512Init(sha3_512)
  sha3_512Input(sha3_512, s)
  echo "SHA3-512 Stream : ", binToHex(sha3_512Final(sha3_512))
  echo "SHA3-512 Standard : 38E05C33D7B067127F217D8C856E554FCFF09C9320B8A5979CE2FF5D95DD27BA35D1FBA50C562DFD1D6CC48BC9C5BAA4390894418CC942D968F97BCB659419ED"

  var keccak224: Keccak224Ctx
  keccak224Init(keccak224)
  keccak224Input(keccak224, s)
  echo "Keccak-224 Stream : ", binToHex(keccak224Final(keccak224))
  echo "Keccak-224 Standard : 4EAAF0E7A1E400EFBA71130722E1CB4D59B32AFB400E654AFEC4F8CE"
  var keccak256: Keccak256Ctx
  keccak256Init(keccak256)
  keccak256Input(keccak256, s)
  echo "Keccak-256 Stream : ", binToHex(keccak256Final(keccak256))
  echo "Keccak-256 Standard : ACAF3289D7B601CBD114FB36C4D29C85BBFD5E133F14CB355C3FD8D99367964F"
  var keccak384: Keccak384Ctx
  keccak384Init(keccak384)
  keccak384Input(keccak384, s)
  echo "Keccak-384 Stream : ", binToHex(keccak384Final(keccak384))
  echo "Keccak-384 Standard : 4D60892FDE7F967BCABDC47C73122AE6311FA1F9BE90D721DA32030F7467A2E3DB3F9CCB3C746483F9D2B876E39DEF17"
  var keccak512: Keccak512Ctx
  keccak512Init(keccak512)
  keccak512Input(keccak512, s)
  echo "Keccak-512 Stream : ", binToHex(keccak512Final(keccak512))
  echo "Keccak-512 Standard : EDA765576C84C600ED7F5D97510E92703B61F5215DEF2A161037FD9DD1F5B6ED4F86CE46073C0E3F34B52DE0289E9C618798FFF9DD4B1BFE035BDB8645FC6E37"

  var k224: array[28, uint8]
  var k256: array[32, uint8]
  var k384: array[48, uint8]
  var k512: array[64, uint8]
  var s224: array[28, uint8]
  var s256: array[32, uint8]
  var s384: array[48, uint8]
  var s512: array[64, uint8]

  var ctxK224: Keccak224Ctx
  var ctxK256: Keccak256Ctx
  var ctxK384: Keccak384Ctx
  var ctxK512: Keccak512Ctx
  var ctxS224: SHA3_224Ctx
  var ctxS256: SHA3_256Ctx
  var ctxS384: SHA3_384Ctx
  var ctxS512: SHA3_512Ctx

  template benchmark(name: string, code: untyped) =
    let start = getMonoTime()
    code
    let elapsed = getMonoTime() - start
    echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

  # --- Keccak Benchmarks ---

  benchmark("Keccak-224 Benchmark"):
    for i in 1 .. 1_000_000:
      keccak224Init(ctxK224)
      keccak224Input(ctxK224, k224)
      k224 = keccak224Final(ctxK224)

  benchmark("Keccak-256 Benchmark"):
    for i in 1 .. 1_000_000:
      keccak256Init(ctxK256)
      keccak256Input(ctxK256, k256)
      k256 = keccak256Final(ctxK256)

  benchmark("Keccak-384 Benchmark"):
    for i in 1 .. 1_000_000:
      keccak384Init(ctxK384)
      keccak384Input(ctxK384, k384)
      k384 = keccak384Final(ctxK384)

  benchmark("Keccak-512 Benchmark"):
    for i in 1 .. 1_000_000:
      keccak512Init(ctxK512)
      keccak512Input(ctxK512, k512)
      k512 = keccak512Final(ctxK512)

  # --- SHA3 Benchmarks ---

  benchmark("SHA3-224 Benchmark"):
    for i in 1 .. 1_000_000:
      sha3_224Init(ctxS224)
      sha3_224Input(ctxS224, s224)
      s224 = sha3_224Final(ctxS224)

  benchmark("SHA3-256 Benchmark"):
    for i in 1 .. 1_000_000:
      sha3_256Init(ctxS256)
      sha3_256Input(ctxS256, s256)
      s256 = sha3_256Final(ctxS256)

  benchmark("SHA3-384 Benchmark"):
    for i in 1 .. 1_000_000:
      sha3_384Init(ctxS384)
      sha3_384Input(ctxS384, s384)
      s384 = sha3_384Final(ctxS384)

  benchmark("SHA3-512 Benchmark"):
    for i in 1 .. 1_000_000:
      sha3_512Init(ctxS512)
      sha3_512Input(ctxS512, s512)
      s512 = sha3_512Final(ctxS512)
