import strutils
import sequtils
import ../../../../Utility/src/Utility/codeutils/indexutils
import ../../../../Utility/src/Utility/codeutils/bits
import ../../../../Utility/src/Utility/codeutils/errorutils
import ../../../../Utility/src/Utility/dataformat/dataformat
import std/[monotimes, times]
import std/bitops

# CPu's bits
const
  Bits* = sizeof(int) * 8

const
  # lea rounds constant
  LEA128Rounds*: int = 24
  LEA192Rounds*: int = 28
  LEA256Rounds*: int = 32

  # lea Delta constant
  Delta: array[8, uint32] = [
    0xc3efe9db'u32, 0x44626b02'u32, 0x79e27c8a'u32, 0x78df30ec'u32,
    0x715ea49e'u32, 0xc785da0a'u32, 0xe04ef22a'u32, 0xe5c40957'u32
  ]

# get key size
template keySize(keyBits: static int): static int =
  when keyBits == 128:
    24 * 6
  elif keyBits == 192:
    28 * 6
  else:
    32 * 6

# get round number
template roundNumber(keyBits: static int): static int =
  when keyBits == 128:
    24
  elif keyBits == 192:
    28
  else:
    32

type
  # lea generic context
  # set roundKey's length with keyBits
  LEACtx*[keyBits: static int] = object
    roundKey*: array[keySize(keyBits), uint32]

  # lea 128/192/256 context
  LEA128Ctx* {.exportc: "AES128Ctx", completeStruct.} = LEACtx[128]
  LEA192Ctx* {.exportc: "AES192Ctx", completeStruct.} = LEACtx[192]
  LEA256Ctx* {.exportc: "AES256Ctx", completeStruct.} = LEACtx[256]

# lea init core
template leaInitC*(ctx: var LEACtx, input: ptr UncheckedArray[uint8]): void =
  # declare temporary buffer
  when ctx.keyBits == 128:
    var buffer: array[4, uint32]
  elif ctx.keyBits == 192:
    var buffer: array[6, uint32]
  else:
    var buffer: array[8, uint32]

  # keybit's uint32 count
  const CountU32: int = ctx.keyBits div 32

  # copy input to buffer
  for i in static(0 ..< CountU32):
    buffer[i] = cast[ptr uint32](addr input[i * 4])[]

  # loop while round number
  for i in static(0 ..< roundNumber(ctx.keyBits)):
    # calculate round key base
    let rkBase: int = i * 6

    # when keyBits is 128 bits
    when ctx.keyBits == 128:
      # add, rotate and word-wise circular shift
      let temp: uint32 = rotateLeftBits(Delta[i and 3], i)
      buffer[0] = rotateLeftBits(buffer[0] + temp, 1)
      buffer[1] = rotateLeftBits(buffer[1] + rotateLeftBits(temp, 1), 3)
      buffer[2] = rotateLeftBits(buffer[2] + rotateLeftBits(temp, 2), 6)
      buffer[3] = rotateLeftBits(buffer[3] + rotateLeftBits(temp, 3), 11)

      # copy buffer to roundKey
      ctx.roundKey[rkBase + 0] = buffer[0]
      ctx.roundKey[rkBase + 1] = buffer[1]
      ctx.roundKey[rkBase + 2] = buffer[2]
      ctx.roundKey[rkBase + 3] = buffer[1]
      ctx.roundKey[rkBase + 4] = buffer[3]
      ctx.roundKey[rkBase + 5] = buffer[1]

    # when keyBits is 192 bits
    elif ctx.keyBits == 192:
      # add, rotate and word-wise circular shift
      let temp: uint32 = rotateLeftBits(Delta[i mod 6], i)
      buffer[0] = rotateLeftBits(buffer[0] + temp, 1)
      buffer[1] = rotateLeftBits(buffer[1] + rotateLeftBits(temp, 1), 3)
      buffer[2] = rotateLeftBits(buffer[2] + rotateLeftBits(temp, 2), 6)
      buffer[3] = rotateLeftBits(buffer[3] + rotateLeftBits(temp, 3), 11)
      buffer[4] = rotateLeftBits(buffer[4] + rotateLeftBits(temp, 4), 13)
      buffer[5] = rotateLeftBits(buffer[5] + rotateLeftBits(temp, 5), 17)

      # copy buffer to roundKey
      for j in static(0 ..< 6):
        ctx.roundKey[rkBase + j] = buffer[j]

    # when keyBits is 256 bits
    elif ctx.keyBits == 256:
      # add, rotate and word-wise circular shift
      let temp: uint32 = rotateLeftBits(Delta[i and 7], i and 0x1F)
      buffer[(6 * i + 0) and 7] = rotateLeftBits(buffer[(6 * i + 0) and 7] + temp, 1)
      buffer[(6 * i + 1) and 7] = rotateLeftBits(buffer[(6 * i + 1) and 7] + rotateLeftBits(temp, 1), 3)
      buffer[(6 * i + 2) and 7] = rotateLeftBits(buffer[(6 * i + 2) and 7] + rotateLeftBits(temp, 2), 6)
      buffer[(6 * i + 3) and 7] = rotateLeftBits(buffer[(6 * i + 3) and 7] + rotateLeftBits(temp, 3), 11)
      buffer[(6 * i + 4) and 7] = rotateLeftBits(buffer[(6 * i + 4) and 7] + rotateLeftBits(temp, 4), 13)
      buffer[(6 * i + 5) and 7] = rotateLeftBits(buffer[(6 * i + 5) and 7] + rotateLeftBits(temp, 5), 17)

      # copy buffer to roundKey
      for j in static(0 ..< 6):
        ctx.roundKey[rkBase + j] = buffer[(6 * i + j) and 7]

# lea encrypt core
template leaEncryptC(ctx: LEACtx, input: ptr UncheckedArray[uint8]): void =
  # cast input to value
  let value: ptr array[4, uint32] = cast[ptr array[4, uint32]](input)

  # loop for roundNumber div 4(process 4 round for one loop)
  for i in static(0 ..< roundNumber(ctx.keyBits) div 4):
    let r: int = i * 4

    # add, rotate, xor operating
    value[3] = rotateRightBits((value[2] xor ctx.roundKey[r*6 + 4]) + (value[3] xor ctx.roundKey[r*6 + 5]), 3)
    value[2] = rotateRightBits((value[1] xor ctx.roundKey[r*6 + 2]) + (value[2] xor ctx.roundKey[r*6 + 3]), 5)
    value[1] = rotateLeftBits((value[0] xor ctx.roundKey[r*6 + 0]) + (value[1] xor ctx.roundKey[r*6 + 1]), 9)

    value[0] = rotateRightBits((value[3] xor ctx.roundKey[(r+1)*6 + 4]) + (value[0] xor ctx.roundKey[(r+1)*6 + 5]), 3)
    value[3] = rotateRightBits((value[2] xor ctx.roundKey[(r+1)*6 + 2]) + (value[3] xor ctx.roundKey[(r+1)*6 + 3]), 5)
    value[2] = rotateLeftBits((value[1] xor ctx.roundKey[(r+1)*6 + 0]) + (value[2] xor ctx.roundKey[(r+1)*6 + 1]), 9)

    value[1] = rotateRightBits((value[0] xor ctx.roundKey[(r+2)*6 + 4]) + (value[1] xor ctx.roundKey[(r+2)*6 + 5]), 3)
    value[0] = rotateRightBits((value[3] xor ctx.roundKey[(r+2)*6 + 2]) + (value[0] xor ctx.roundKey[(r+2)*6 + 3]), 5)
    value[3] = rotateLeftBits((value[2] xor ctx.roundKey[(r+2)*6 + 0]) + (value[3] xor ctx.roundKey[(r+2)*6 + 1]), 9)

    value[2] = rotateRightBits((value[1] xor ctx.roundKey[(r+3)*6 + 4]) + (value[2] xor ctx.roundKey[(r+3)*6 + 5]), 3)
    value[1] = rotateRightBits((value[0] xor ctx.roundKey[(r+3)*6 + 2]) + (value[1] xor ctx.roundKey[(r+3)*6 + 3]), 5)
    value[0] = rotateLeftBits((value[3] xor ctx.roundKey[(r+3)*6 + 0]) + (value[0] xor ctx.roundKey[(r+3)*6 + 1]), 9)

template leaDecryptC*(ctx: LEACtx, input: ptr UncheckedArray[uint8]): void =
  # cast input to value
  let value: ptr array[4, uint32] = cast[ptr array[4, uint32]](input)

  # loop for roundNumber div 4(process 4 round for one loop)
  for i in static(0 ..< roundNumber(ctx.keyBits) div 4):
    var r: int = roundNumber(ctx.keyBits) - 1 - (i * 4)

    # add, rotate, xor operating
    value[0] = rotateRightBits(value[0], 9) - (value[3] xor ctx.roundKey[r*6 + 0]) xor ctx.roundKey[r*6 + 1]
    value[1] = rotateLeftBits(value[1], 5) - (value[0] xor ctx.roundKey[r*6 + 2]) xor ctx.roundKey[r*6 + 3]
    value[2] = rotateLeftBits(value[2], 3) - (value[1] xor ctx.roundKey[r*6 + 4]) xor ctx.roundKey[r*6 + 5]

    r -= 1
    value[3] = rotateRightBits(value[3], 9) - (value[2] xor ctx.roundKey[r*6 + 0]) xor ctx.roundKey[r*6 + 1]
    value[0] = rotateLeftBits(value[0], 5) - (value[3] xor ctx.roundKey[r*6 + 2]) xor ctx.roundKey[r*6 + 3]
    value[1] = rotateLeftBits(value[1], 3) - (value[0] xor ctx.roundKey[r*6 + 4]) xor ctx.roundKey[r*6 + 5]

    r -= 1
    value[2] = rotateRightBits(value[2], 9) - (value[1] xor ctx.roundKey[r*6 + 0]) xor ctx.roundKey[r*6 + 1]
    value[3] = rotateLeftBits(value[3], 5) - (value[2] xor ctx.roundKey[r*6 + 2]) xor ctx.roundKey[r*6 + 3]
    value[0] = rotateLeftBits(value[0], 3) - (value[3] xor ctx.roundKey[r*6 + 4]) xor ctx.roundKey[r*6 + 5]

    r -= 1
    value[1] = rotateRightBits(value[1], 9) - (value[0] xor ctx.roundKey[r*6 + 0]) xor ctx.roundKey[r*6 + 1]
    value[2] = rotateLeftBits(value[2], 5) - (value[1] xor ctx.roundKey[r*6 + 2]) xor ctx.roundKey[r*6 + 3]
    value[3] = rotateLeftBits(value[3], 3) - (value[2] xor ctx.roundKey[r*6 + 4]) xor ctx.roundKey[r*6 + 5]

# export wrappers
when defined(templateOpt):
  template lea128Init*(ctx: var LEA128Ctx, input: openArray[uint8]): void =
    leaInitC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input))
  template lea128Init*(ctx: var LEA128Ctx, input: array[16, uint8]): void =
    leaInitC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  template lea128Init*(ctx: var LEA128Ctx, input: ptr array[16, uint8]): void =
    leaInitC(ctx, cast[ptr UncheckedArray[uint8]](input))
  template lea128Init*(ctx: var LEA128Ctx, input: ptr UncheckedArray[uint8]): void =
    leaInitC(ctx, input)

  template lea128Encrypt*(ctx: LEA128Ctx, input: var openArray[uint8]): void =
    leaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input))
  template lea128Encrypt*(ctx: LEA128Ctx, input: var array[16, uint8]): void =
    leaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  template lea128Encrypt*(ctx: LEA128Ctx, input: ptr array[16, uint8]): void =
    leaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](input))
  template lea128Encrypt*(ctx: LEA128Ctx, input: ptr UncheckedArray[uint8]): void =
    leaEncryptC(ctx, input)

  template lea128Decrypt*(ctx: LEA128Ctx, input: var openArray[uint8]): void =
    leaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input))
  template lea128Decrypt*(ctx: LEA128Ctx, input: var array[16, uint8]): void =
    leaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  template lea128Decrypt*(ctx: LEA128Ctx, input: ptr array[16, uint8]): void =
    leaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](input))
  template lea128Decrypt*(ctx: LEA128Ctx, input: ptr UncheckedArray[uint8]): void =
    leaDecryptC(ctx, input)

  template lea192Init*(ctx: var LEA192Ctx, input: openArray[uint8]): void =
    leaInitC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input))
  template lea192Init*(ctx: var LEA192Ctx, input: array[24, uint8]): void =
    leaInitC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  template lea192Init*(ctx: var LEA192Ctx, input: ptr array[24, uint8]): void =
    leaInitC(ctx, cast[ptr UncheckedArray[uint8]](input))
  template lea192Init*(ctx: var LEA192Ctx, input: ptr UncheckedArray[uint8]): void =
    leaInitC(ctx, input)

  template lea192Encrypt*(ctx: LEA192Ctx, input: var openArray[uint8]): void =
    leaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input))
  template lea192Encrypt*(ctx: LEA192Ctx, input: var array[16, uint8]): void =
    leaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  template lea192Encrypt*(ctx: LEA192Ctx, input: ptr array[16, uint8]): void =
    leaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](input))
  template lea192Encrypt*(ctx: LEA192Ctx, input: ptr UncheckedArray[uint8]): void =
    leaEncryptC(ctx, input)

  template lea192Decrypt*(ctx: LEA192Ctx, input: var openArray[uint8]): void =
    leaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input))
  template lea192Decrypt*(ctx: LEA192Ctx, input: var array[16, uint8]): void =
    leaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  template lea192Decrypt*(ctx: LEA192Ctx, input: ptr array[16, uint8]): void =
    leaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](input))
  template lea192Decrypt*(ctx: LEA192Ctx, input: ptr UncheckedArray[uint8]): void =
    leaDecryptC(ctx, input)

  template lea256Init*(ctx: var LEA256Ctx, input: openArray[uint8]): void =
    leaInitC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input))
  template lea256Init*(ctx: var LEA256Ctx, input: array[32, uint8]): void =
    leaInitC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  template lea256Init*(ctx: var LEA256Ctx, input: ptr array[32, uint8]): void =
    leaInitC(ctx, cast[ptr UncheckedArray[uint8]](input))
  template lea256Init*(ctx: var LEA256Ctx, input: ptr UncheckedArray[uint8]): void =
    leaInitC(ctx, input)

  template lea256Encrypt*(ctx: LEA256Ctx, input: var openArray[uint8]): void =
    leaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input))
  template lea256Encrypt*(ctx: LEA256Ctx, input: var array[16, uint8]): void =
    leaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  template lea256Encrypt*(ctx: LEA256Ctx, input: ptr array[16, uint8]): void =
    leaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](input))
  template lea256Encrypt*(ctx: LEA256Ctx, input: ptr UncheckedArray[uint8]): void =
    leaEncryptC(ctx, input)

  template lea256Decrypt*(ctx: LEA256Ctx, input: var openArray[uint8]): void =
    leaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input))
  template lea256Decrypt*(ctx: LEA256Ctx, input: var array[16, uint8]): void =
    leaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  template lea256Decrypt*(ctx: LEA256Ctx, input: ptr array[16, uint8]): void =
    leaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](input))
  template lea256Decrypt*(ctx: LEA256Ctx, input: ptr UncheckedArray[uint8]): void =
    leaDecryptC(ctx, input)
else:
  proc lea128Init*(ctx: var LEA128Ctx, input: openArray[uint8]): void =
    leaInitC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input))
  proc lea128Init*(ctx: var LEA128Ctx, input: array[16, uint8]): void =
    leaInitC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  proc lea128Init*(ctx: var LEA128Ctx, input: ptr array[16, uint8]): void {.exportc: "lea128Init", cdecl.} =
    leaInitC(ctx, cast[ptr UncheckedArray[uint8]](input))
  proc lea128Init*(ctx: var LEA128Ctx, input: ptr UncheckedArray[uint8]): void {.exportc: "lea128Init_unchecked", cdecl.} =
    leaInitC(ctx, input)

  proc lea128Encrypt*(ctx: LEA128Ctx, input: var openArray[uint8]): void =
    leaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input))
  proc lea128Encrypt*(ctx: LEA128Ctx, input: var array[16, uint8]): void =
    leaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  proc lea128Encrypt*(ctx: LEA128Ctx, input: ptr array[16, uint8]): void {.exportc: "lea128Encrypt", cdecl.} =
    leaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](input))
  proc lea128Encrypt*(ctx: LEA128Ctx, input: ptr UncheckedArray[uint8]): void {.exportc: "lea128Encrypt_unchecked", cdecl.} =
    leaEncryptC(ctx, input)

  proc lea128Decrypt*(ctx: LEA128Ctx, input: var openArray[uint8]): void =
    leaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input))
  proc lea128Decrypt*(ctx: LEA128Ctx, input: var array[16, uint8]): void =
    leaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  proc lea128Decrypt*(ctx: LEA128Ctx, input: ptr array[16, uint8]): void {.exportc: "lea128Decrypt", cdecl.} =
    leaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](input))
  proc lea128Decrypt*(ctx: LEA128Ctx, input: ptr UncheckedArray[uint8]): void {.exportc: "lea128Decrypt_unchecked", cdecl.} =
    leaDecryptC(ctx, input)

  proc lea192Init*(ctx: var LEA192Ctx, input: openArray[uint8]): void =
    leaInitC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input))
  proc lea192Init*(ctx: var LEA192Ctx, input: array[16, uint8]): void =
    leaInitC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  proc lea192Init*(ctx: var LEA192Ctx, input: ptr array[16, uint8]): void {.exportc: "lea192Init", cdecl.} =
    leaInitC(ctx, cast[ptr UncheckedArray[uint8]](input))
  proc lea192Init*(ctx: var LEA192Ctx, input: ptr UncheckedArray[uint8]): void {.exportc: "lea192Init_unchecked", cdecl.} =
    leaInitC(ctx, input)

  proc lea192Encrypt*(ctx: LEA192Ctx, input: var openArray[uint8]): void =
    leaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input))
  proc lea192Encrypt*(ctx: LEA192Ctx, input: var array[16, uint8]): void =
    leaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  proc lea192Encrypt*(ctx: LEA192Ctx, input: ptr array[16, uint8]): void {.exportc: "lea192Encrypt", cdecl.} =
    leaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](input))
  proc lea192Encrypt*(ctx: LEA192Ctx, input: ptr UncheckedArray[uint8]): void {.exportc: "lea192Encrypt_unchecked", cdecl.} =
    leaEncryptC(ctx, input)

  proc lea192Decrypt*(ctx: LEA192Ctx, input: var openArray[uint8]): void =
    leaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input))
  proc lea192Decrypt*(ctx: LEA192Ctx, input: var array[16, uint8]): void =
    leaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  proc lea192Decrypt*(ctx: LEA192Ctx, input: ptr array[16, uint8]): void {.exportc: "lea192Decrypt", cdecl.} =
    leaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](input))
  proc lea192Decrypt*(ctx: LEA192Ctx, input: ptr UncheckedArray[uint8]): void {.exportc: "lea192Decrypt_unchecked", cdecl.} =
    leaDecryptC(ctx, input)

  proc lea256Init*(ctx: var LEA256Ctx, input: openArray[uint8]): void =
    leaInitC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input))
  proc lea256Init*(ctx: var LEA256Ctx, input: array[16, uint8]): void =
    leaInitC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  proc lea256Init*(ctx: var LEA256Ctx, input: ptr array[16, uint8]): void {.exportc: "lea256Init", cdecl.} =
    leaInitC(ctx, cast[ptr UncheckedArray[uint8]](input))
  proc lea256Init*(ctx: var LEA256Ctx, input: ptr UncheckedArray[uint8]): void {.exportc: "lea256Init_unchecked", cdecl.} =
    leaInitC(ctx, input)

  proc lea256Encrypt*(ctx: LEA256Ctx, input: var openArray[uint8]): void =
    leaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input))
  proc lea256Encrypt*(ctx: LEA256Ctx, input: var array[16, uint8]): void =
    leaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  proc lea256Encrypt*(ctx: LEA256Ctx, input: ptr array[16, uint8]): void {.exportc: "lea256Encrypt", cdecl.} =
    leaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](input))
  proc lea256Encrypt*(ctx: LEA256Ctx, input: ptr UncheckedArray[uint8]): void {.exportc: "lea256Encrypt_unchecked", cdecl.} =
    leaEncryptC(ctx, input)

  proc lea256Decrypt*(ctx: LEA256Ctx, input: var openArray[uint8]): void =
    leaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input))
  proc lea256Decrypt*(ctx: LEA256Ctx, input: var array[16, uint8]): void =
    leaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  proc lea256Decrypt*(ctx: LEA256Ctx, input: ptr array[16, uint8]): void {.exportc: "lea256Decrypt", cdecl.} =
    leaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](input))
  proc lea256Decrypt*(ctx: LEA256Ctx, input: ptr UncheckedArray[uint8]): void {.exportc: "lea256Decrypt_unchecked", cdecl.} =
    leaDecryptC(ctx, input)

# test code
when defined(test):
  var ctx128: LEA128Ctx
  var key128: array[16, uint8] = [
    0x07'u8, 0xAB'u8, 0x63'u8, 0x05'u8, 0xB0'u8, 0x25'u8, 0xD8'u8, 0x3F'u8, 0x79'u8, 0xAD'u8, 0xDA'u8, 0xA6'u8, 0x3A'u8, 0xC8'u8, 0xAD'u8, 0x00'u8
  ]
  var text128: array[16, uint8] = [
    0xF2'u8, 0x8A'u8, 0xE3'u8, 0x25'u8, 0x6A'u8, 0xAD'u8, 0x23'u8, 0xB4'u8, 0x15'u8, 0xE0'u8, 0x28'u8, 0x06'u8, 0x3B'u8, 0x61'u8, 0x0C'u8, 0x60'u8
  ]

  lea128Init(ctx128, key128)
  echo "--- Test : LEA-128 ---"
  echo "LEA-128 Key : 07AB6305B025D83F79ADDAA63AC8AD00"
  lea128Encrypt(ctx128, text128)
  echo "LEA-128 Encrypt Cipher Text : ", binToHex(text128)
  echo "LEA-128 Standard Cipher Text : 64D908FCB7EBFEF90FD670106DE7C7C5"
  lea128Decrypt(ctx128, text128)
  echo "LEA-128 Decrypt Plain Text : ", binToHex(text128)
  echo "Standard Plain Text : F28AE3256AAD23B415E028063B610C60"

  var ctx192: LEA192Ctx
  var key192: array[24, uint8] = [
    0x14'u8, 0x37, 0xAF, 0x53, 0x30, 0x69, 0xBD, 0x75, 0x25, 0xC1, 0x56, 0x0C, 0x78, 0xBA, 0xD2, 0xA1, 0xE5, 0x34, 0x67, 0x1C, 0x00, 0x7E, 0xF2, 0x7C
  ]
  var text192: array[16, uint8] = [
    0x1C'u8, 0xB4, 0xF4, 0xCB, 0x6C, 0x4B, 0xDB, 0x51, 0x68, 0xEA, 0x84, 0x09, 0x72, 0x7B, 0xFD, 0x51
  ]

  lea192Init(ctx192, key192)
  echo "--- Test : LEA-192 ---"
  echo "LEA-192 Key : 1437AF533069BD7525C1560C78BAD2A1E534671C007EF27C"
  lea192Encrypt(ctx192, text192)
  echo "LEA-192 Encrypt Cipher Text : ", binToHex(text192)
  echo "LEA-192 Standard Cipher Text : 69725C6DF912F8B70EB511E6663C5870"
  lea192Decrypt(ctx192, text192)
  echo "LEA-192 Decrypt Plain Text : ", binToHex(text192)
  echo "Standard Plain Text : 1CB4F4CB6C4BDB5168EA8409727BFD51"

  var ctx256: LEA256Ctx
  var key256: array[32, uint8] = [
    0x4F'u8, 0x67, 0x79, 0xE2, 0xBD, 0x1E, 0x93, 0x19, 0xC6, 0x30, 0x15, 0xAC, 0xFF, 0xEF, 0xD7, 0xA7,
    0x91'u8, 0xF0, 0xED, 0x59, 0xDF, 0x1B, 0x70, 0x07, 0x69, 0xFE, 0x82, 0xE2, 0xF0, 0x66, 0x8C, 0x35
  ]
  var text256: array[16, uint8] = [
    0xDC'u8, 0x31, 0xCA, 0xE3, 0xDA, 0x5E, 0x0A, 0x11, 0xC9, 0x66, 0xB0, 0x20, 0xD7, 0xCF, 0xFE, 0xDE
  ]

  lea256Init(ctx256, key256)
  echo "--- Test : LEA-256 ---"
  echo "LEA-256 Key : 4F6779E2BD1E9319C63015ACFFEFD7A791F0ED59DF1B700769FE82E2F0668C35"
  lea256Encrypt(ctx256, text256)
  echo "LEA-256 Encrypt Cipher Text : ", binToHex(text256)
  echo "LEA-256 Standard Cipher Text : EDA2042098F667E857A02DB8CAA7DFF2"
  lea256Decrypt(ctx256, text256)
  echo "LEA-256 Decrypt Plain Text : ", binToHex(text256)
  echo "Standard Plain Text : DC31CAE3DA5E0A11C966B020D7CFFEDE"

  template benchmark(name: string, code: untyped) =
    let start = getMonoTime()
    code
    let elapsed = getMonoTime() - start
    echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

  benchmark("LEA-128 Init"):
    for i in 1 .. 1_000_000:
      lea128Init(ctx128, key128)

  benchmark("LEA-128 Encrypt"):
    for i in 1 .. 1_000_000:
      lea128Encrypt(ctx128, text128)

  benchmark("LEA-128 Decrypt"):
    for i in 1 .. 1_000_000:
      lea128Decrypt(ctx128, text128)

  benchmark("LEA-192 Init"):
    for i in 1 .. 1_000_000:
      lea192Init(ctx192, key192)

  benchmark("LEA-192 Encrypt"):
    for i in 1 .. 1_000_000:
      lea192Encrypt(ctx192, text192)

  benchmark("LEA-192 Decrypt"):
    for i in 1 .. 1_000_000:
      lea192Decrypt(ctx192, text192)

  benchmark("LEA-256 Init"):
    for i in 1 .. 1_000_000:
      lea256Init(ctx256, key256)

  benchmark("LEA-256 Encrypt"):
    for i in 1 .. 1_000_000:
      lea256Encrypt(ctx256, text256)

  benchmark("LEA-256 Decrypt"):
    for i in 1 .. 1_000_000:
      lea256Decrypt(ctx256, text256)
