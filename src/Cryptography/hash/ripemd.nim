import sequtils
import strutils
import ../../../../Utility/src/Utility/codeutils/indexutils
import ../../../../Utility/src/Utility/codeutils/bits
import ../../../../Utility/src/Utility/codeutils/errorutils
import ../../../../Utility/src/Utility/dataformat/dataformat
import std/bitops
import std/[monotimes, times]

type
  # declare RIPEMD generic context
  RIPEMDCtx*[bits: static int] = object
    length*: array[2, uint32]
    state*: array[bits div 32, uint32]
    buffer*: array[64, uint8]

  # declare RIPEMD 128/160/256/320 Context
  RIPEMD128Ctx* = RIPEMDCtx[128]
  RIPEMD160Ctx* = RIPEMDCtx[160]
  RIPEMD256Ctx* = RIPEMDCtx[256]
  RIPEMD320Ctx* = RIPEMDCtx[320]

  # declare RIPEMD list
  RIPEMDList* = RIPEMD128Ctx | RIPEMD160Ctx | RIPEMD256Ctx | RIPEMD320Ctx

# declare F sub template
template F(x, y, z: uint32): uint32 =
  x xor y xor z

# declare G sub template
template G(x, y, z: uint32): uint32 =
  (x and y) or ((not x) and z)

# declare H sub template
template H(x, y, z: uint32): uint32 =
  (x or (not y)) xor z

# declare I sub template
template I(x, y, z: uint32): uint32 =
  (x and z) or (y and (not z))

# declare J sub tempalte
template J(x, y, z: uint32): uint32 =
  x xor (y or (not z))

# 128 series : RIPEMD-128, RIPEMD-256
# 160 series : RIPEMD-160, RIPEMD-320

# declare FF left round template for 128 series
template FF128(a: var uint32, b, c, d, x: uint32, s: int): void =
  a = a + F(b, c, d) + x
  a = rotateLeftBits(a, s)

# declare GG left round template for 128 series
template GG128(a: var uint32, b, c, d, x: uint32, s: int): void =
  a = a + G(b, c, d) + x + 0x5A827999'u32
  a = rotateLeftBits(a, s)

# declare HH left round template for 128 series
template HH128(a: var uint32, b, c, d, x: uint32, s: int): void =
  a = a + H(b, c, d) + x + 0x6ED9EBA1'u32
  a = rotateLeftBits(a, s)

# declare II left round template for 128 series
template II128(a: var uint32, b, c, d, x: uint32, s: int): void =
  a = a + I(b, c, d) + x + 0x8F1BBCDC'u32
  a = rotateLeftBits(a, s)

# declare FFF right round template for 128 series
template FFF128(a: var uint32, b, c, d, x: uint32, s: int): void =
  a = a + F(b, c, d) + x
  a = rotateLeftBits(a, s)

# declare GGG right round template for 128 series
template GGG128(a: var uint32, b, c, d, x: uint32, s: int): void =
  a = a + G(b, c, d) + x + 0x6D703EF3'u32
  a = rotateLeftBits(a, s)

# declare HHH right round template for 128 series
template HHH128(a: var uint32, b, c, d, x: uint32, s: int): void =
  a = a + H(b, c, d) + x + 0x5C4DD124'u32
  a = rotateLeftBits(a, s)

# declare III right round template for 128 series
template III128(a: var uint32, b, c, d, x: uint32, s: int): void =
  a = a + I(b, c, d) + x + 0x50A28BE6'u32
  a = rotateLeftBits(a, s)

# declare FF left round template for 160 series
template FF160(a: var uint32, b: uint32, c: var uint32, d, e, x: uint32, s: int): void =
  a = a + F(b, c, d) + (x)
  a = rotateLeftBits(a, s) + e
  c = rotateLeftBits(c, 10)

# declare GG left round template for 160 series
template GG160(a: var uint32, b: uint32, c: var uint32, d, e, x: uint32, s: int): void =
  a = a + G(b, c, d) + x + 0x5A827999'u32
  a = rotateLeftBits(a, s) + e
  c = rotateLeftBits(c, 10)

# declare HH left round template for 160 series
template HH160(a: var uint32, b: uint32, c: var uint32, d, e, x: uint32, s: int): void =
  a = a + H(b, c, d) + x + 0x6ED9EBA1'u32
  a = rotateLeftBits(a, s) + e
  c = rotateLeftBits(c, 10)

# declare II left round template for 160 series
template II160(a: var uint32, b: uint32, c: var uint32, d, e, x: uint32, s: int): void =
  a = a + I(b, c, d) + x + 0x8F1BBCDC'u32
  a = rotateLeftBits(a, s) + e
  c = rotateLeftBits(c, 10)

# declare JJ left round template for 160 series
template JJ160(a: var uint32, b: uint32, c: var uint32, d, e, x: uint32, s: int): void =
  a = a + J(b, c, d) + x + 0xA953FD4E'u32
  a = rotateLeftBits(a, s) + e
  c = rotateLeftBits(c, 10)

# declare FFF right round template for 160 series
template FFF160(a: var uint32, b: uint32, c: var uint32, d, e, x: uint32, s: int): void =
  a = a + F(b, c, d) + x
  a = rotateLeftBits(a, s) + e
  c = rotateLeftBits(c, 10)

# declare GGG right round template for 160 series
template GGG160(a: var uint32, b: uint32, c: var uint32, d, e, x: uint32, s: int): void =
  a = a + G(b, c, d) + x + 0x7A6D76E9'u32
  a = rotateLeftBits(a, s) + e
  c = rotateLeftBits(c, 10)

# declare HHH right round template for 160 series
template HHH160(a: var uint32, b: uint32, c: var uint32, d, e, x: uint32, s: int): void =
  a = a + H(b, c, d) + x + 0x6D703EF3'u32
  a = rotateLeftBits(a, s) + e
  c = rotateLeftBits(c, 10)

# declare III right round template for 160 series
template III160(a: var uint32, b: uint32, c: var uint32, d, e, x: uint32, s: int): void =
  a = a + I(b, c, d) + x + 0x5C4DD124'u32
  a = rotateLeftBits(a, s) + e
  c = rotateLeftBits(c, 10)

# declare JJJ right round template for 160 series
template JJJ160(a: var uint32, b: uint32, c: var uint32, d, e, x: uint32, s: int): void =
  a = a + J(b, c, d) + x + 0x50A28BE6'u32
  a = rotateLeftBits(a, s) + e
  c = rotateLeftBits(c, 10)

# declare 1th left round template for 128 series
template leftRound128n1(a, b, c, d: var uint32, x: lent array[16, uint32]): void =
  FF128(a, b, c, d, x[ 0], 11)
  FF128(d, a, b, c, x[ 1], 14)
  FF128(c, d, a, b, x[ 2], 15)
  FF128(b, c, d, a, x[ 3], 12)
  FF128(a, b, c, d, x[ 4],  5)
  FF128(d, a, b, c, x[ 5],  8)
  FF128(c, d, a, b, x[ 6],  7)
  FF128(b, c, d, a, x[ 7],  9)
  FF128(a, b, c, d, x[ 8], 11)
  FF128(d, a, b, c, x[ 9], 13)
  FF128(c, d, a, b, x[10], 14)
  FF128(b, c, d, a, x[11], 15)
  FF128(a, b, c, d, x[12],  6)
  FF128(d, a, b, c, x[13],  7)
  FF128(c, d, a, b, x[14],  9)
  FF128(b, c, d, a, x[15],  8)

# declare 2th left round template for 128 series
template leftRound128n2(a, b, c, d: var uint32, x: lent array[16, uint32]): void =
  GG128(a, b, c, d, x[ 7],  7)
  GG128(d, a, b, c, x[ 4],  6)
  GG128(c, d, a, b, x[13],  8)
  GG128(b, c, d, a, x[ 1], 13)
  GG128(a, b, c, d, x[10], 11)
  GG128(d, a, b, c, x[ 6],  9)
  GG128(c, d, a, b, x[15],  7)
  GG128(b, c, d, a, x[ 3], 15)
  GG128(a, b, c, d, x[12],  7)
  GG128(d, a, b, c, x[ 0], 12)
  GG128(c, d, a, b, x[ 9], 15)
  GG128(b, c, d, a, x[ 5],  9)
  GG128(a, b, c, d, x[ 2], 11)
  GG128(d, a, b, c, x[14],  7)
  GG128(c, d, a, b, x[11], 13)
  GG128(b, c, d, a, x[ 8], 12)

# decare 3th left round template for 128 series
template leftRound128n3(a, b, c, d: var uint32, x: lent array[16, uint32]): void =
  HH128(a, b, c, d, x[ 3], 11)
  HH128(d, a, b, c, x[10], 13)
  HH128(c, d, a, b, x[14],  6)
  HH128(b, c, d, a, x[ 4],  7)
  HH128(a, b, c, d, x[ 9], 14)
  HH128(d, a, b, c, x[15],  9)
  HH128(c, d, a, b, x[ 8], 13)
  HH128(b, c, d, a, x[ 1], 15)
  HH128(a, b, c, d, x[ 2], 14)
  HH128(d, a, b, c, x[ 7],  8)
  HH128(c, d, a, b, x[ 0], 13)
  HH128(b, c, d, a, x[ 6],  6)
  HH128(a, b, c, d, x[13],  5)
  HH128(d, a, b, c, x[11], 12)
  HH128(c, d, a, b, x[ 5],  7)
  HH128(b, c, d, a, x[12],  5)

# declare 4th left round template for 128 series
template leftRound128n4(a, b, c, d: var uint32, x: lent array[16, uint32]): void =
  II128(a, b, c, d, x[ 1], 11)
  II128(d, a, b, c, x[ 9], 12)
  II128(c, d, a, b, x[11], 14)
  II128(b, c, d, a, x[10], 15)
  II128(a, b, c, d, x[ 0], 14)
  II128(d, a, b, c, x[ 8], 15)
  II128(c, d, a, b, x[12],  9)
  II128(b, c, d, a, x[ 4],  8)
  II128(a, b, c, d, x[13],  9)
  II128(d, a, b, c, x[ 3], 14)
  II128(c, d, a, b, x[ 7],  5)
  II128(b, c, d, a, x[15],  6)
  II128(a, b, c, d, x[14],  8)
  II128(d, a, b, c, x[ 5],  6)
  II128(c, d, a, b, x[ 6],  5)
  II128(b, c, d, a, x[ 2], 12)

# declare 1th right round template for 128 series
template rightRound128n1(a, b, c, d: var uint32, x: lent array[16, uint32]): void =
  III128(a, b, c, d, x[ 5],  8)
  III128(d, a, b, c, x[14],  9)
  III128(c, d, a, b, x[ 7],  9)
  III128(b, c, d, a, x[ 0], 11)
  III128(a, b, c, d, x[ 9], 13)
  III128(d, a, b, c, x[ 2], 15)
  III128(c, d, a, b, x[11], 15)
  III128(b, c, d, a, x[ 4],  5)
  III128(a, b, c, d, x[13],  7)
  III128(d, a, b, c, x[ 6],  7)
  III128(c, d, a, b, x[15],  8)
  III128(b, c, d, a, x[ 8], 11)
  III128(a, b, c, d, x[ 1], 14)
  III128(d, a, b, c, x[10], 14)
  III128(c, d, a, b, x[ 3], 12)
  III128(b, c, d, a, x[12],  6)

# declare 2th right round template for 128 series
template rightRound128n2(a, b, c, d: var uint32, x: lent array[16, uint32]): void =
  HHH128(a, b, c, d, x[ 6],  9)
  HHH128(d, a, b, c, x[11], 13)
  HHH128(c, d, a, b, x[ 3], 15)
  HHH128(b, c, d, a, x[ 7],  7)
  HHH128(a, b, c, d, x[ 0], 12)
  HHH128(d, a, b, c, x[13],  8)
  HHH128(c, d, a, b, x[ 5],  9)
  HHH128(b, c, d, a, x[10], 11)
  HHH128(a, b, c, d, x[14],  7)
  HHH128(d, a, b, c, x[15],  7)
  HHH128(c, d, a, b, x[ 8], 12)
  HHH128(b, c, d, a, x[12],  7)
  HHH128(a, b, c, d, x[ 4],  6)
  HHH128(d, a, b, c, x[ 9], 15)
  HHH128(c, d, a, b, x[ 1], 13)
  HHH128(b, c, d, a, x[ 2], 11)

# declare 3th right round template for 128 series
template rightRound128n3(a, b, c, d: var uint32, x: lent array[16, uint32]): void =
  GGG128(a, b, c, d, x[15],  9)
  GGG128(d, a, b, c, x[ 5],  7)
  GGG128(c, d, a, b, x[ 1], 15)
  GGG128(b, c, d, a, x[ 3], 11)
  GGG128(a, b, c, d, x[ 7],  8)
  GGG128(d, a, b, c, x[14],  6)
  GGG128(c, d, a, b, x[ 6],  6)
  GGG128(b, c, d, a, x[ 9], 14)
  GGG128(a, b, c, d, x[11], 12)
  GGG128(d, a, b, c, x[ 8], 13)
  GGG128(c, d, a, b, x[12],  5)
  GGG128(b, c, d, a, x[ 2], 14)
  GGG128(a, b, c, d, x[10], 13)
  GGG128(d, a, b, c, x[ 0], 13)
  GGG128(c, d, a, b, x[ 4],  7)
  GGG128(b, c, d, a, x[13],  5)

# declare 4th right round template for 128 series
template rightRound128n4(a, b, c, d: var uint32, x: lent array[16, uint32]): void =
  FFF128(a, b, c, d, x[ 8], 15)
  FFF128(d, a, b, c, x[ 6],  5)
  FFF128(c, d, a, b, x[ 4],  8)
  FFF128(b, c, d, a, x[ 1], 11)
  FFF128(a, b, c, d, x[ 3], 14)
  FFF128(d, a, b, c, x[11], 14)
  FFF128(c, d, a, b, x[15],  6)
  FFF128(b, c, d, a, x[ 0], 14)
  FFF128(a, b, c, d, x[ 5],  6)
  FFF128(d, a, b, c, x[12],  9)
  FFF128(c, d, a, b, x[ 2], 12)
  FFF128(b, c, d, a, x[13],  9)
  FFF128(a, b, c, d, x[ 9], 12)
  FFF128(d, a, b, c, x[ 7],  5)
  FFF128(c, d, a, b, x[10], 15)
  FFF128(b, c, d, a, x[14],  8)

# declare 1th left round template for 160 series
template leftRound160n1(a, b, c, d, e: var uint32, x: lent array[16, uint32]): void =
  FF160(a, b, c, d, e, x[ 0], 11)
  FF160(e, a, b, c, d, x[ 1], 14)
  FF160(d, e, a, b, c, x[ 2], 15)
  FF160(c, d, e, a, b, x[ 3], 12)
  FF160(b, c, d, e, a, x[ 4],  5)
  FF160(a, b, c, d, e, x[ 5],  8)
  FF160(e, a, b, c, d, x[ 6],  7)
  FF160(d, e, a, b, c, x[ 7],  9)
  FF160(c, d, e, a, b, x[ 8], 11)
  FF160(b, c, d, e, a, x[ 9], 13)
  FF160(a, b, c, d, e, x[10], 14)
  FF160(e, a, b, c, d, x[11], 15)
  FF160(d, e, a, b, c, x[12],  6)
  FF160(c, d, e, a, b, x[13],  7)
  FF160(b, c, d, e, a, x[14],  9)
  FF160(a, b, c, d, e, x[15],  8)

# declare 2th left round template for 160 series
template leftRound160n2(a, b, c, d, e: var uint32, x: lent array[16, uint32]): void =
  GG160(e, a, b, c, d, x[ 7],  7)
  GG160(d, e, a, b, c, x[ 4],  6)
  GG160(c, d, e, a, b, x[13],  8)
  GG160(b, c, d, e, a, x[ 1], 13)
  GG160(a, b, c, d, e, x[10], 11)
  GG160(e, a, b, c, d, x[ 6],  9)
  GG160(d, e, a, b, c, x[15],  7)
  GG160(c, d, e, a, b, x[ 3], 15)
  GG160(b, c, d, e, a, x[12],  7)
  GG160(a, b, c, d, e, x[ 0], 12)
  GG160(e, a, b, c, d, x[ 9], 15)
  GG160(d, e, a, b, c, x[ 5],  9)
  GG160(c, d, e, a, b, x[ 2], 11)
  GG160(b, c, d, e, a, x[14],  7)
  GG160(a, b, c, d, e, x[11], 13)
  GG160(e, a, b, c, d, x[ 8], 12)

# declare 3th left round template for 160 series
template leftRound160n3(a, b, c, d, e: var uint32, x: lent array[16, uint32]): void =
  HH160(d, e, a, b, c, x[ 3], 11)
  HH160(c, d, e, a, b, x[10], 13)
  HH160(b, c, d, e, a, x[14],  6)
  HH160(a, b, c, d, e, x[ 4],  7)
  HH160(e, a, b, c, d, x[ 9], 14)
  HH160(d, e, a, b, c, x[15],  9)
  HH160(c, d, e, a, b, x[ 8], 13)
  HH160(b, c, d, e, a, x[ 1], 15)
  HH160(a, b, c, d, e, x[ 2], 14)
  HH160(e, a, b, c, d, x[ 7],  8)
  HH160(d, e, a, b, c, x[ 0], 13)
  HH160(c, d, e, a, b, x[ 6],  6)
  HH160(b, c, d, e, a, x[13],  5)
  HH160(a, b, c, d, e, x[11], 12)
  HH160(e, a, b, c, d, x[ 5],  7)
  HH160(d, e, a, b, c, x[12],  5)

# declare 4th left round template for 160 series
template leftRound160n4(a, b, c, d, e: var uint32, x: lent array[16, uint32]): void =
  II160(c, d, e, a, b, x[ 1], 11)
  II160(b, c, d, e, a, x[ 9], 12)
  II160(a, b, c, d, e, x[11], 14)
  II160(e, a, b, c, d, x[10], 15)
  II160(d, e, a, b, c, x[ 0], 14)
  II160(c, d, e, a, b, x[ 8], 15)
  II160(b, c, d, e, a, x[12],  9)
  II160(a, b, c, d, e, x[ 4],  8)
  II160(e, a, b, c, d, x[13],  9)
  II160(d, e, a, b, c, x[ 3], 14)
  II160(c, d, e, a, b, x[ 7],  5)
  II160(b, c, d, e, a, x[15],  6)
  II160(a, b, c, d, e, x[14],  8)
  II160(e, a, b, c, d, x[ 5],  6)
  II160(d, e, a, b, c, x[ 6],  5)
  II160(c, d, e, a, b, x[ 2], 12)

# declare 5th left round template for 160 series
template leftRound160n5(a, b, c, d, e: var uint32, x: lent array[16, uint32]): void =
  JJ160(b, c, d, e, a, x[ 4],  9)
  JJ160(a, b, c, d, e, x[ 0], 15)
  JJ160(e, a, b, c, d, x[ 5],  5)
  JJ160(d, e, a, b, c, x[ 9], 11)
  JJ160(c, d, e, a, b, x[ 7],  6)
  JJ160(b, c, d, e, a, x[12],  8)
  JJ160(a, b, c, d, e, x[ 2], 13)
  JJ160(e, a, b, c, d, x[10], 12)
  JJ160(d, e, a, b, c, x[14],  5)
  JJ160(c, d, e, a, b, x[ 1], 12)
  JJ160(b, c, d, e, a, x[ 3], 13)
  JJ160(a, b, c, d, e, x[ 8], 14)
  JJ160(e, a, b, c, d, x[11], 11)
  JJ160(d, e, a, b, c, x[ 6],  8)
  JJ160(c, d, e, a, b, x[15],  5)
  JJ160(b, c, d, e, a, x[13],  6)

# declare 1th right round template for 160 series
template rightRound160n1(a, b, c, d, e: var uint32, x: lent array[16, uint32]): void =
  JJJ160(a, b, c, d, e, x[ 5],  8)
  JJJ160(e, a, b, c, d, x[14],  9)
  JJJ160(d, e, a, b, c, x[ 7],  9)
  JJJ160(c, d, e, a, b, x[ 0], 11)
  JJJ160(b, c, d, e, a, x[ 9], 13)
  JJJ160(a, b, c, d, e, x[ 2], 15)
  JJJ160(e, a, b, c, d, x[11], 15)
  JJJ160(d, e, a, b, c, x[ 4],  5)
  JJJ160(c, d, e, a, b, x[13],  7)
  JJJ160(b, c, d, e, a, x[ 6],  7)
  JJJ160(a, b, c, d, e, x[15],  8)
  JJJ160(e, a, b, c, d, x[ 8], 11)
  JJJ160(d, e, a, b, c, x[ 1], 14)
  JJJ160(c, d, e, a, b, x[10], 14)
  JJJ160(b, c, d, e, a, x[ 3], 12)
  JJJ160(a, b, c, d, e, x[12],  6)

# declare 2th right round template for 160 series
template rightRound160n2(a, b, c, d, e: var uint32, x: lent array[16, uint32]): void =
  III160(e, a, b, c, d, x[ 6],  9)
  III160(d, e, a, b, c, x[11], 13)
  III160(c, d, e, a, b, x[ 3], 15)
  III160(b, c, d, e, a, x[ 7],  7)
  III160(a, b, c, d, e, x[ 0], 12)
  III160(e, a, b, c, d, x[13],  8)
  III160(d, e, a, b, c, x[ 5],  9)
  III160(c, d, e, a, b, x[10], 11)
  III160(b, c, d, e, a, x[14],  7)
  III160(a, b, c, d, e, x[15],  7)
  III160(e, a, b, c, d, x[ 8], 12)
  III160(d, e, a, b, c, x[12],  7)
  III160(c, d, e, a, b, x[ 4],  6)
  III160(b, c, d, e, a, x[ 9], 15)
  III160(a, b, c, d, e, x[ 1], 13)
  III160(e, a, b, c, d, x[ 2], 11)

# declare 3th right round template for 160 series
template rightRound160n3(a, b, c, d, e: var uint32, x: lent array[16, uint32]): void =
  HHH160(d, e, a, b, c, x[15],  9)
  HHH160(c, d, e, a, b, x[ 5],  7)
  HHH160(b, c, d, e, a, x[ 1], 15)
  HHH160(a, b, c, d, e, x[ 3], 11)
  HHH160(e, a, b, c, d, x[ 7],  8)
  HHH160(d, e, a, b, c, x[14],  6)
  HHH160(c, d, e, a, b, x[ 6],  6)
  HHH160(b, c, d, e, a, x[ 9], 14)
  HHH160(a, b, c, d, e, x[11], 12)
  HHH160(e, a, b, c, d, x[ 8], 13)
  HHH160(d, e, a, b, c, x[12],  5)
  HHH160(c, d, e, a, b, x[ 2], 14)
  HHH160(b, c, d, e, a, x[10], 13)
  HHH160(a, b, c, d, e, x[ 0], 13)
  HHH160(e, a, b, c, d, x[ 4],  7)
  HHH160(d, e, a, b, c, x[13],  5)

# declare 4th right round template for 160 series
template rightRound160n4(a, b, c, d, e: var uint32, x: lent array[16, uint32]): void =
  GGG160(c, d, e, a, b, x[ 8], 15)
  GGG160(b, c, d, e, a, x[ 6],  5)
  GGG160(a, b, c, d, e, x[ 4],  8)
  GGG160(e, a, b, c, d, x[ 1], 11)
  GGG160(d, e, a, b, c, x[ 3], 14)
  GGG160(c, d, e, a, b, x[11], 14)
  GGG160(b, c, d, e, a, x[15],  6)
  GGG160(a, b, c, d, e, x[ 0], 14)
  GGG160(e, a, b, c, d, x[ 5],  6)
  GGG160(d, e, a, b, c, x[12],  9)
  GGG160(c, d, e, a, b, x[ 2], 12)
  GGG160(b, c, d, e, a, x[13],  9)
  GGG160(a, b, c, d, e, x[ 9], 12)
  GGG160(e, a, b, c, d, x[ 7],  5)
  GGG160(d, e, a, b, c, x[10], 15)
  GGG160(c, d, e, a, b, x[14],  8)

# declare 5th right round template for 160 series
template rightRound160n5(a, b, c, d, e: var uint32, x: lent array[16, uint32]): void =
  FFF160(b, c, d, e, a, x[12],  8)
  FFF160(a, b, c, d, e, x[15],  5)
  FFF160(e, a, b, c, d, x[10], 12)
  FFF160(d, e, a, b, c, x[ 4],  9)
  FFF160(c, d, e, a, b, x[ 1], 12)
  FFF160(b, c, d, e, a, x[ 5],  5)
  FFF160(a, b, c, d, e, x[ 8], 14)
  FFF160(e, a, b, c, d, x[ 7],  6)
  FFF160(d, e, a, b, c, x[ 6],  8)
  FFF160(c, d, e, a, b, x[ 2], 13)
  FFF160(b, c, d, e, a, x[13],  6)
  FFF160(a, b, c, d, e, x[14],  5)
  FFF160(e, a, b, c, d, x[ 0], 15)
  FFF160(d, e, a, b, c, x[ 3], 13)
  FFF160(c, d, e, a, b, x[ 9], 11)
  FFF160(b, c, d, e, a, x[11], 11)

# ripemd 128  transform part
template ripemd128Transform(state: var array[4, uint32], input: lent openArray[uint8]): void =
  # declare left temporary variables
  var aL: uint32 = state[0]
  var bL: uint32 = state[1]
  var cL: uint32 = state[2]
  var dL: uint32 = state[3]
  # declare right temporary variabls
  var aR: uint32 = state[0]
  var bR: uint32 = state[1]
  var cR: uint32 = state[2]
  var dR: uint32 = state[3]
  # declare temporary chunk
  var chunk: array[16, uint32]

  # decode input to chunk by little endian
  # 16 is for static parameter to define loop range in compile time
  decodeLE(input, chunk, 16)

  # calling round template
  leftRound128n1(aL, bL, cL, dL, chunk)
  leftRound128n2(aL, bL, cL, dL, chunk)
  leftRound128n3(aL, bL, cL, dL, chunk)
  leftRound128n4(aL, bL, cL, dL, chunk)
  rightRound128n1(aR, bR, cR, dR, chunk)
  rightRound128n2(aR, bR, cR, dR, chunk)
  rightRound128n3(aR, bR, cR, dR, chunk)
  rightRound128n4(aR, bR, cR, dR, chunk)

  # assign and add temporary variable to state
  dR = dR + cL + state[1]
  state[1] = state[2] + dL + aR
  state[2] = state[3] + aL + bR
  state[3] = state[0] + bL + cR
  state[0] = dR

# ripemd 256 transform part
template ripemd256Transform(state: var array[8, uint32], input: lent openArray[uint8]): void =
  # declare left temporary variables
  var aL: uint32 = state[0]
  var bL: uint32 = state[1]
  var cL: uint32 = state[2]
  var dL: uint32 = state[3]
  # declare right temporary variables
  var aR: uint32 = state[4]
  var bR: uint32 = state[5]
  var cR: uint32 = state[6]
  var dR: uint32 = state[7]
  # declare temporary chunk
  var chunk: array[16, uint32]

  # decode input to chunk by little endian
  decodeLE(input, chunk, 16)

  # callindg round template
  leftRound128n1(aL, bL, cL, dL, chunk)
  rightRound128n1(aR, bR, cR, dR, chunk)
  swap(aL, aR)
  leftRound128n2(aL, bL, cL, dL, chunk)
  rightRound128n2(aR, bR, cR, dR, chunk)
  swap(bL, bR)
  leftRound128n3(aL, bL, cL, dL, chunk)
  rightRound128n3(aR, bR, cR, dR, chunk)
  swap(cL, cR)
  leftRound128n4(aL, bL, cL, dL, chunk)
  rightRound128n4(aR, bR, cR, dR, chunk)
  swap(dL, dR)

  # assign and add temporary variables to state
  state[0] += aL
  state[1] += bL
  state[2] += cL
  state[3] += dL
  state[4] += aR
  state[5] += bR
  state[6] += cR
  state[7] += dR

# ripemd 160 transform part
template ripemd160Transform(state: var array[5, uint32], input: lent openArray[uint8]): void =
  # declare left temporary variables
  var aL: uint32 = state[0]
  var bL: uint32 = state[1]
  var cL: uint32 = state[2]
  var dL: uint32 = state[3]
  var eL: uint32 = state[4]
  # declare right temporary variables
  var aR: uint32 = state[0]
  var bR: uint32 = state[1]
  var cR: uint32 = state[2]
  var dR: uint32 = state[3]
  var eR: uint32 = state[4]
  # declare temporary chunk
  var chunk: array[16, uint32]

  # decode input to chunk by little endian
  decodeLE(input, chunk, 16)

  # calling round template
  leftRound160n1(aL, bL, cL, dL, eL, chunk)
  leftRound160n2(aL, bL, cL, dL, eL, chunk)
  leftRound160n3(aL, bL, cL, dL, eL, chunk)
  leftRound160n4(aL, bL, cL, dL, eL, chunk)
  leftRound160n5(aL, bL, cL, dL, eL, chunk)
  rightRound160n1(aR, bR, cR, dR, eR, chunk)
  rightRound160n2(aR, bR, cR, dR, eR, chunk)
  rightRound160n3(aR, bR, cR, dR, eR, chunk)
  rightRound160n4(aR, bR, cR, dR, eR, chunk)
  rightRound160n5(aR, bR, cR, dR, eR, chunk)

  # assign and add temporary variables to state
  dR = dR + cL + state[1]
  state[1] = state[2] + dL + eR
  state[2] = state[3] + eL + aR
  state[3] = state[4] + aL + bR
  state[4] = state[0] + bL + cR
  state[0] = dR

# ripemd 320 transform part
template ripemd320Transform(state: var array[10, uint32], input: lent openArray[uint8]): void =
  # declare left temporary variables
  var aL: uint32 = state[0]
  var bL: uint32 = state[1]
  var cL: uint32 = state[2]
  var dL: uint32 = state[3]
  var eL: uint32 = state[4]
  # declare right temporary variables
  var aR: uint32 = state[5]
  var bR: uint32 = state[6]
  var cR: uint32 = state[7]
  var dR: uint32 = state[8]
  var eR: uint32 = state[9]
  # declare temporary chunk
  var chunk: array[16, uint32]

  # decode input to chunk by little endian
  decodeLE(input, chunk, 16)

  # calling round template
  leftRound160n1(aL, bL, cL, dL, eL, chunk)
  rightRound160n1(aR, bR, cR, dR, eR, chunk)
  swap(aL, aR)
  leftRound160n2(aL, bL, cL, dL, eL, chunk)
  rightRound160n2(aR, bR, cR, dR, eR, chunk)
  swap(bL, bR)
  leftRound160n3(aL, bL, cL, dL, eL, chunk)
  rightRound160n3(aR, bR, cR, dR, eR, chunk)
  swap(cL, cR)
  leftRound160n4(aL, bL, cL, dL, eL, chunk)
  rightRound160n4(aR, bR, cR, dR, eR, chunk)
  swap(dL, dR)
  leftRound160n5(aL, bL, cL, dL, eL, chunk)
  rightRound160n5(aR, bR, cR, dR, eR, chunk)
  swap(eL, eR)

  # assign and add temporary variables to state
  state[0] += aL
  state[1] += bL
  state[2] += cL
  state[3] += dL
  state[4] += eL
  state[5] += aR
  state[6] += bR
  state[7] += cR
  state[8] += dR
  state[9] += eR

# get block size of ripemd context
template sizeBlock*(ctx: typedesc[RIPEMDList]): int =
  (64)

# get digest size of ripemd context
template sizeDigest*(ctx: typedesc[RIPEMDList]): int =
  when r is RIPEMD128Ctx:
    (16)
  elif r is RIPEMD160Ctx:
    (20)
  elif r is RIPEMD256Ctx:
    (32)
  elif r is RIPEMD320Ctx:
    (40)

# ripemd generic init core
template ripemdInitC(ctx: var RIPEMDCtx): void =
  # set length to zero
  ctx.length[0] = 0x00'u32
  ctx.length[1] = 0x00'u32

  # set buffer to zero
  for i in static(0 ..< 64):
    ctx.buffer[i] = 0x00'u8

  # initialize state to state constant
  when ctx.bits == 128:
    ctx.state[0] = 0x67452301'u32
    ctx.state[1] = 0xEFCDAB89'u32
    ctx.state[2] = 0x98BADCFE'u32
    ctx.state[3] = 0x10325476'u32
  elif ctx.bits == 160:
    ctx.state[0] = 0x67452301'u32
    ctx.state[1] = 0xEFCDAB89'u32
    ctx.state[2] = 0x98BADCFE'u32
    ctx.state[3] = 0x10325476'u32
    ctx.state[4] = 0xC3D2E1F0'u32
  elif ctx.bits == 256:
    ctx.state[0] = 0x67452301'u32
    ctx.state[1] = 0xEFCDAB89'u32
    ctx.state[2] = 0x98BADCFE'u32
    ctx.state[3] = 0x10325476'u32
    ctx.state[4] = 0x76543210'u32
    ctx.state[5] = 0xFEDCBA98'u32
    ctx.state[6] = 0x89ABCDEF'u32
    ctx.state[7] = 0x01234567'u32
  elif ctx.bits == 320:
    ctx.state[0] = 0x67452301'u32
    ctx.state[1] = 0xEFCDAB89'u32
    ctx.state[2] = 0x98BADCFE'u32
    ctx.state[3] = 0x10325476'u32
    ctx.state[4] = 0xC3D2E1F0'u32
    ctx.state[5] = 0x76543210'u32
    ctx.state[6] = 0xFEDCBA98'u32
    ctx.state[7] = 0x89ABCDEF'u32
    ctx.state[8] = 0x01234567'u32
    ctx.state[9] = 0x3C2D1E0F'u32

# ripemd clear core
template ripemdClearC(ctx: var RIPEMDCtx): void =

  for i in static(0 ..< 2):
    ctx.length[i] = 0x00'u32

  for i in static(0 ..< ctx.state.len):
    ctx.state[i] = 0x00'u32

  for i in static(0 ..< 64):
    ctx.buffer[i] = 0x00'u8

# ripemd input core
template ripemdInputC[bits: static int](ctx: var RIPEMDCtx[bits], input: openArray[uint8]): void =
  var inputLen: int = input.len
  var pos: int = 0

  while inputLen > 0:
    # set index
    let index: int = int(ctx.length[0] and 0x3F)
    let size = min(64 - index, inputLen)

    copyMem(addr(ctx.buffer[index]), addr(input[pos]), size)

    pos += size
    inputLen -= size

    # add length
    let oldLow = ctx.length[0]
    ctx.length[0] += uint32(size)
    if ctx.length[0] < oldLow:
      ctx.length[1] += 1'u32

    # call transform template
    if (ctx.count[0] and 0x3F'u32) == 0:
      when bits == 128:
        ripemd128Transform(ctx.state, ctx.buffer)
      elif bits == 160:
        ripemd160Transform(ctx.state, ctx.buffer)
      elif bits == 256:
        ripemd256Transform(ctx.state, ctx.buffer)
      elif bits == 320:
        ripemd320Transform(ctx.state, ctx.buffer)

# ripemd final core
template ripemdFinalC[bits: static int](ctx: var RIPEMDCtx[bits]): array[bits div 8, uint8] =
  # set index
  let index: int = int(ctx.count[0] and 0x3F'u32)

  # add padding
  ctx.buffer[index] = 0x80'u8

  if index < 56:
    # zerofill left space
    zeroMem(ctx.buffer[index + 1], 56 - index - 1)
  else:
    # zerofill left space
    zeroMem(ctx.buffer[index + 1], 64 - index - 1)

    # call transform template
    when bits == 128:
      ripemd128Transform(ctx.state, ctx.buffer)
    elif bits == 160:
      ripemd160Transform(ctx.state, ctx.buffer)
    elif bits == 256:
      ripemd256Transform(ctx.state, ctx.buffer)
    elif bits == 320:
      ripemd320Transform(ctx.state, ctx.buffer)

    # zerofill left space
    zeroMem(addr ctx.buffer[0], 56)

  # set bit length
  let bitLen: array[2, uint32] = [ctx.length[0] shl 3, (ctx.length[0] shr 29) or (ctx.length[1] shl 3)]

  # copy bit len to ctx's buffer by little endian
  encodeLE(bitLen[0..1], ctx.buffer.toOpenArray(56, 63), 2)

  # call transform template
  when bits == 128:
    ripemd128Transform(ctx.state, ctx.buffer)
  elif bits == 160:
    ripemd160Transform(ctx.state, ctx.buffer)
  elif bits == 256:
    ripemd256Transform(ctx.state, ctx.buffer)
  elif bits == 320:
    ripemd320Transform(ctx.state, ctx.buffer)

  # declare output
  var output: array[bits div 8, uint8]

  # encode state to output by little endian
  encodeLE(ctx.state, output)

  # return output
  output

# export wrappers
when defined(templateOpt):
  # RIPEMD-128
  template ripemd128Init*(ctx: var RIPEMD128Ctx): void =
    ripemdInitC(ctx)
  template ripemd128Input*(ctx: var RIPEMD128Ctx, input: lent openArray[uint8]): void =
    ripemdInputC(ctx, input)
  template ripemd128Final*(ctx: var RIPEMD128Ctx): array[16, uint8] =
    ripemdFinalC(ctx)

  # RIPEMD-160
  template ripemd160Init*(ctx: var RIPEMD160Ctx): void =
    ripemdInitC(ctx)
  template ripemd160Input*(ctx: var RIPEMD160Ctx, input: lent openArray[uint8]): void =
    ripemdInputC(ctx, input)
  template ripemd160Final*(ctx: var RIPEMD160Ctx): array[20, uint8] =
    ripemdFinalC(ctx)

  # RIPEMD-256
  template ripemd256Init*(ctx: var RIPEMD256Ctx): void =
    ripemdInitC(ctx)
  template ripemd256Input*(ctx: var RIPEMD256Ctx, input: lent openArray[uint8]): void =
    ripemdInputC(ctx, input)
  template ripemd256Final*(ctx: var RIPEMD256Ctx): array[32, uint8] =
    ripemdFinalC(ctx)

  # RIPEMD-320
  template ripemd320Init*(ctx: var RIPEMD320Ctx): void =
    ripemdInitC(ctx)
  template ripemd320Input*(ctx: var RIPEMD320Ctx, input: lent openArray[uint8]): void =
    ripemdInputC(ctx, input)
  template ripemd320Final*(ctx: var RIPEMD320Ctx): array[40, uint8] =
    ripemdFinalC(ctx)
else:
  # RIPEMD-128
  proc ripemd128Init*(ctx: var RIPEMD128Ctx): void =
    ripemdInitC(ctx)
  proc ripemd128Input*(ctx: var RIPEMD128Ctx, input: openArray[uint8]): void =
    ripemdInputC(ctx, input)
  proc ripemd128Final*(ctx: var RIPEMD128Ctx): array[16, uint8] =
    return ripemdFinalC(ctx)

  # RIPEMD-160
  proc ripemd160Init*(ctx: var RIPEMD160Ctx): void =
    ripemdInitC(ctx)
  proc ripemd160Input*(ctx: var RIPEMD160Ctx, input: openArray[uint8]): void =
    ripemdInputC(ctx, input)
  proc ripemd160Final*(ctx: var RIPEMD160Ctx): array[20, uint8] =
    return ripemdFinalC(ctx)

  # RIPEMD-256
  proc ripemd256Init*(ctx: var RIPEMD256Ctx): void =
    ripemdInitC(ctx)
  proc ripemd256Input*(ctx: var RIPEMD256Ctx, input: openArray[uint8]): void =
    ripemdInputC(ctx, input)
  proc ripemd256Final*(ctx: var RIPEMD256Ctx): array[32, uint8] =
    return ripemdFinalC(ctx)

  # RIPEMD-320
  proc ripemd320Init*(ctx: var RIPEMD320Ctx): void =
    ripemdInitC(ctx)
  proc ripemd320Input*(ctx: var RIPEMD320Ctx, input: openArray[uint8]): void =
    ripemdInputC(ctx, input)
  proc ripemd320Final*(ctx: var RIPEMD320Ctx): array[40, uint8] =
    return ripemdFinalC(ctx)

# test code
when defined(test):
  var input: seq[uint8] = charToBin("Hello, World!")
  var ctx128: RIPEMD128Ctx
  echo "Test String : 'Hello, World!'"
  ripemd128Init(ctx128)
  ripemd128Input(ctx128, input)
  echo "RIPEMD-128 Stream : ", binToHex(ripemd128Final(ctx128))
  echo "RIPEMD-128 Standard : 67F9FE75CA2886DC76AD00F7276BDEBA"
  var ctx160: RIPEMD160Ctx
  ripemd160Init(ctx160)
  ripemd160Input(ctx160, input)
  echo "RIPEMD-160 Stream : ", binToHex(ripemd160Final(ctx160))
  echo "RIPEMD-160 Standard : 527A6A4B9A6DA75607546842E0E00105350B1AAF"
  var ctx256: RIPEMD256Ctx
  ripemd256Init(ctx256)
  ripemd256Input(ctx256, input)
  echo "RIPEMD-256 Stream : ", binToHex(ripemd256Final(ctx256))
  echo "RIPEMD-256 Standard : 567750C6D34DCBA7AE038A80016F3CA3260EC25BFDB0B68BBB8E730B00B2447D"
  var ctx320: RIPEMD320Ctx
  ripemd320Init(ctx320)
  ripemd320Input(ctx320, input)
  echo "RIPEMD-320 Stream : ", binToHex(ripemd320Final(ctx320))
  echo "RIPEMD-320 Standard : F9832E5BB00576FC56C2221F404EB77ADDEAFE49843C773F0DF3FC5A996D5934F3C96E94AEB80E89"

  template benchmark(name: string, code: untyped) =
    let start = getMonoTime()
    code
    let elapsed = getMonoTime() - start
    echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"
  var temp128: array[16, uint8]
  var temp160: array[20, uint8]
  var temp256: array[32, uint8]
  var temp320: array[40, uint8]
  benchmark("RIPEMD-128 Benchamark"):
    for i in 1 .. 1_000_000:
      ripemd128Init(ctx128)
      ripemd128Input(ctx128, temp128)
      temp128 = ripemd128Final(ctx128)
  benchmark("RIPEMD-160 Benchamark"):
    for i in 1 .. 1_000_000:
      ripemd160Init(ctx160)
      ripemd160Input(ctx160, temp160)
      temp160 = ripemd160Final(ctx160)
  benchmark("RIPEMD-256 Benchamark"):
    for i in 1 .. 1_000_000:
      ripemd256Init(ctx256)
      ripemd256Input(ctx256, temp256)
      temp256 = ripemd256Final(ctx256)
  benchmark("RIPEMD-320 Benchamark"):
    for i in 1 .. 1_000_000:
      ripemd320Init(ctx320)
      ripemd320Input(ctx320, temp320)
      temp320 = ripemd320Final(ctx320)
