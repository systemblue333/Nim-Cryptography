import ../../../../Utility/src/Utility/codeutils/indexutils
import ../../../../Utility/src/Utility/codeutils/bits
import ../../../../Utility/src/Utility/codeutils/errorutils
import ../../../../Utility/src/Utility/dataformat/dataformat
import std/[monotimes, times]

type
  MD2Ctx* = object
    state*: array[48, uint8]
    checksum*: array[16, uint8]
    buffer*: array[16, uint8]
    count*: int

# constant
# PISubst : PI based constant
const
  PISubst: array[256, uint8] = [
  41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 19,
  98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188, 76, 130, 202,
  30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24, 138, 23, 229, 18,
  190, 78, 196, 214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47, 238, 122,
  169, 104, 121, 145, 21, 178, 7, 63, 148, 194, 16, 137, 11, 34, 95, 33,
  128, 127, 93, 154, 90, 144, 50, 39, 53, 62, 204, 231, 191, 247, 151, 3,
  255, 25, 48, 179, 72, 165, 181, 209, 215, 94, 146, 42, 172, 86, 170, 198,
  79, 184, 56, 210, 150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241,
  69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2,
  27, 96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
  85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197, 234, 38,
  44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65, 129, 77, 82,
  106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123, 8, 12, 189, 177, 74,
  120, 136, 149, 139, 227, 99, 232, 109, 233, 203, 213, 254, 59, 0, 29, 57,
  242, 239, 183, 14, 102, 88, 208, 228, 166, 119, 114, 248, 235, 117, 75, 10,
  49, 68, 80, 180, 143, 237, 31, 26, 219, 153, 141, 51, 159, 17, 131, 20
  ]

# Padding : pre calculated padding list
# block makes constant in compile time
const Padding: array[16, array[16, uint8]] = (block:
  var p: array[16, array[16, uint8]]
  for i in 1..16:
    for j in 0 ..< i:
      p[i-1][j] = i.uint8
  p
)
#[
# md2 transform part
template md2Transform(ctx: var MD2Ctx, input: lent openArray[uint8]): void =
  for i in static(0 ..< 16):
    ctx.state[i + 16] = input[i]
    ctx.state[i + 32] = ctx.state[i] xor input[i]

  var t: uint8 = 0.uint8
  for i in static(0 ..< 18):
    for j in static(0 ..< 48):
      ctx.state[j] = ctx.state[j] xor PISubst[t.int]
      t = ctx.state[j]
    t = (t + i.uint8) and 0xFF'u8

  var l: uint8 = ctx.checksum[15]
  for i in static(0 ..< 16):
    ctx.checksum[i] = ctx.checksum[i] xor PISubst[(input[i] xor l).int]
    l = ctx.checksum[i]
]#
# md2 transform part
template md2Transform(ctx: var MD2Ctx, input: ptr UncheckedArray[uint8]): void =
  for i in static(0 ..< 16):
    ctx.state[i + 16] = input[i]
    ctx.state[i + 32] = ctx.state[i] xor input[i]

  var t: uint8 = 0.uint8
  for i in static(0 ..< 18):
    for j in static(0 ..< 48):
      ctx.state[j] = ctx.state[j] xor PISubst[t.int]
      t = ctx.state[j]
    t = (t + i.uint8) and 0xFF'u8

  var l: uint8 = ctx.checksum[15]
  for i in static(0 ..< 16):
    ctx.checksum[i] = ctx.checksum[i] xor PISubst[(input[i] xor l).int]
    l = ctx.checksum[i]

# md2 init core
template md2InitC(ctx: var MD2Ctx): void =
  ctx.count = 0
  for i in static(0 ..< 48):
    ctx.state[i] = 0

  for i in static(0 ..< 16):
    ctx.checksum[i] = 0

# md2 input core
template md2InputC(ctx: var MD2Ctx, input: lent openArray[uint8]): void =
  var i: int = 0
  let inputLen: int = input.len

  while i < inputLen:
    let index: int = ctx.count
    ctx.buffer[index] = input[i]
    ctx.count = (index + 1)

    if ctx.count == 16:
      md2Transform(ctx, cast[ptr UncheckedArray[uint8]](addr ctx.buffer))
      ctx.count = 0

    i.inc

# md2 final core
template md2FinalC(ctx: var MD2Ctx): array[16, uint8] =
  var output: array[16, uint8]
  let padLen = 16 - ctx.count
  let pad = Padding[padLen - 1]
  md2InputC(ctx, pad)

  md2Transform(ctx, cast[ptr UncheckedArray[uint8]](addr ctx.checksum))

  for i in static(0 ..< 16):
    output[i] = ctx.state[i]

  # if --defined(antiForensic) is valid, initialize ctx for security
  when defined(antiForensic):
    md2InitC(ctx)

  output

# export wrappers
when defined(templateOpt):
  template md2Init*(ctx: var MD2Ctx): void =
    md2InitC(ctx)
  template md2Input*(ctx: var MD2Ctx, input: lent openArray[uint8]): void =
    md2InputC(ctx, input)
  template md2Final*(ctx: var MD2Ctx): array[16, uint8] =
    md2FinalC(ctx)
else:
  proc md2Init*(ctx: var MD2Ctx): void =
    md2InitC(ctx)
    return
  proc md2Input*(ctx: var MD2Ctx, input: openArray[uint8]): void =
    md2InputC(ctx, input)
    return
  proc md2Final*(ctx: var MD2Ctx): array[16, uint8] =
    return md2FinalC(ctx)

# test code
when defined(test):
  var s: seq[uint8] = charToBin("Hello, World!")
  var ctx1: MD2Ctx
  md2Init(ctx1)
  md2Input(ctx1, s)
  echo "MD2Stream : ", binToHex(md2Final(ctx1))
  echo "MD2 Standard : 1C8F1E6A94AAA7145210BF90BB52871A"
  echo "Input : Hello, World!"
  template benchmark(name: string, code: untyped) =
    let start = getMonoTime()
    code
    let elapsed = getMonoTime() - start
    echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"
  var a: array[16, uint8]
  var ctx2: MD2Ctx
  md2Init(ctx2)
  benchmark("MD2 Benchamark"):
    for i in 1 .. 1_000_000:
      md2Input(ctx2, a)
      a = md2Final(ctx2)
