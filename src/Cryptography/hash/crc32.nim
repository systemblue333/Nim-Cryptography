{.experimental: "strictNotNil".}

import ../../../../Utility/src/Utility/codeutils/indexutils
import ../../../../Utility/src/Utility/codeutils/bits
import ../../../../Utility/src/Utility/codeutils/errorutils
import ../../../../Utility/src/Utility/dataformat/dataformat

# 0x82f63b78
const CRC32Tables = block:
  var
    tables: array[8, array[256, uint32]]
    c: uint32
  for i in static(0 ..< 256):
    c = i.uint32
    for j in static(0 ..< 8):
      c = (c shr 1) xor ((c and 1) * 0x04C11DB7.uint32)
    tables[0][i] = c
  for i in static(0 ..< 256):
    tables[1][i] = (tables[0][i] shr 8) xor tables[0][tables[0][i] and 255]
    tables[2][i] = (tables[1][i] shr 8) xor tables[0][tables[1][i] and 255]
    tables[3][i] = (tables[2][i] shr 8) xor tables[0][tables[2][i] and 255]
    tables[4][i] = (tables[3][i] shr 8) xor tables[0][tables[3][i] and 255]
    tables[5][i] = (tables[4][i] shr 8) xor tables[0][tables[4][i] and 255]
    tables[6][i] = (tables[5][i] shr 8) xor tables[0][tables[5][i] and 255]
    tables[7][i] = (tables[6][i] shr 8) xor tables[0][tables[6][i] and 255]
  tables

type
  CRC32Ctx* = object
    buffer*: uint32

template crc32InitC(ctx: var CRC32Ctx): void =
  ctx.buffer = 0xFFFFFFFF'u32

template crc32InputC(ctx: var CRC32Ctx, input: lent openArray[uint8]): void =
  let length: int = input.len
  var temp: uint32 = ctx.buffer

  var i: int = 0
  for j in 0 ..< length div 8:
    var ctxTemp: array[2, uint32]
    decodeLE(input[i ..< i + 8], ctxTemp)
    ctxTemp[0] = ctxTemp[0] xor temp
    temp =
      CRC32Tables[7][ctxTemp[0] and 255] xor
      CRC32Tables[6][(ctxTemp[0] shr 8) and 255] xor
      CRC32Tables[5][(ctxTemp[0] shr 16) and 255] xor
      CRC32Tables[4][ctxTemp[0] shr 24] xor
      CRC32Tables[3][ctxTemp[1] and 255] xor
      CRC32Tables[2][(ctxTemp[1] shr 8) and 255] xor
      CRC32Tables[1][(ctxTemp[1] shr 16) and 255] xor
      CRC32Tables[0][ctxTemp[1] shr 24]
    i += 8

  for j in i ..< length:
    #temp = CRCTables[0][(temp xor input[j]) and 255] xor (temp shr 8)
    temp = CRC32Tables[0][(temp and 255) xor input[j]] xor (temp shr 8)
  ctx.buffer = temp

template crc32FinalC(ctx: var CRC32Ctx): array[4, uint8] =
  var output: array[4, uint8]
  var finalValue: uint32 = ctx.buffer xor 0xFFFFFFFF'u32
  toBytesLE(bitref(finalValue), output)
  output

when defined(templateOpt):
  template crc32Init*(ctx: var CRC32Ctx): void =
    crc32InitC(ctx)
  template crc32Input*(ctx: var CRC32Ctx, input: lent openArray[uint8]): void =
    crc32InputC(ctx, input)
  when defined(varOpt):
    template crc32Final*(ctx: var CRC32Ctx, output: var array[4, uint8]): void =
      output = crc32FinalC(ctx)
  else:
    template crc32Final*(ctx: var CRC32Ctx): array[4, uint8] =
      crc32FinalC(ctx)
else:
  proc crc32Init*(ctx: var CRC32Ctx): void =
    crc32InitC(ctx)
  proc crc32Input*(ctx: var CRC32Ctx, input: openArray[uint8]): void =
    crc32InputC(ctx, input)
  when defined(varOpt):
    proc crc32Final*(ctx: var CRC32Ctx, output: var array[4, uint8]): void =
      output = crc32FinalC(ctx)
  else:
    proc crc32Final*(ctx: var CRC32Ctx): array[4, uint8] =
      crc32FinalC(ctx)

when defined(test):
  var S: seq[uint8] = charToBin("Hello, World!")
  var ctx: CRC32Ctx
  crc32Init(ctx)
  crc32Input(ctx, S)
  echo "CRC32Stream : ", binToHex(crc32Final(ctx))
  echo "CRC32 Standard : EC4AC3D0"
  echo "Input : Hello, World!"

#[
Result 	Check 	Poly 	Init 	RefIn 	RefOut 	XorOut
CRC-8/AUTOSAR
	0xDF 	0xDF 	0x2F 	0xFF 	false 	false 	0xFF
CRC-8/BLUETOOTH
	0x26 	0x26 	0xA7 	0x00 	true 	true 	0x00
CRC-8/CDMA2000
	0xDA 	0xDA 	0x9B 	0xFF 	false 	false 	0x00
CRC-8/DARC
	0x15 	0x15 	0x39 	0x00 	true 	true 	0x00
CRC-8/DVB-S2
	0xBC 	0xBC 	0xD5 	0x00 	false 	false 	0x00
CRC-8/GSM-A
	0x37 	0x37 	0x1D 	0x00 	false 	false 	0x00
CRC-8/GSM-B
	0x94 	0x94 	0x49 	0x00 	false 	false 	0xFF
CRC-8/HITAG
	0xB4 	0xB4 	0x1D 	0xFF 	false 	false 	0x00
CRC-8/I-432-1
	0xA1 	0xA1 	0x07 	0x00 	false 	false 	0x55
CRC-8/I-CODE
	0x7E 	0x7E 	0x1D 	0xFD 	false 	false 	0x00
CRC-8/LTE
	0xEA 	0xEA 	0x9B 	0x00 	false 	false 	0x00
CRC-8/MAXIM-DOW
	0xA1 	0xA1 	0x31 	0x00 	true 	true 	0x00
CRC-8/MIFARE-MAD
	0x99 	0x99 	0x1D 	0xC7 	false 	false 	0x00
CRC-8/NRSC-5
	0xF7 	0xF7 	0x31 	0xFF 	false 	false 	0x00
CRC-8/OPENSAFETY
	0x3E 	0x3E 	0x2F 	0x00 	false 	false 	0x00
CRC-8/ROHC
	0xD0 	0xD0 	0x07 	0xFF 	true 	true 	0x00
CRC-8/SAE-J1850
	0x4B 	0x4B 	0x1D 	0xFF 	false 	false 	0xFF
CRC-8/SMBUS
	0xF4 	0xF4 	0x07 	0x00 	false 	false 	0x00
CRC-8/TECH-3250
	0x97 	0x97 	0x1D 	0xFF 	true 	true 	0x00
CRC-8/WCDMA
	0x25 	0x25 	0x9B 	0x00 	true 	true 	0x00
CRC-16/ARC
	0xBB3D 	0xBB3D 	0x8005 	0x0000 	true 	true 	0x0000
CRC-16/CDMA2000
	0x4C06 	0x4C06 	0xC867 	0xFFFF 	false 	false 	0x0000
CRC-16/CMS
	0xAEE7 	0xAEE7 	0x8005 	0xFFFF 	false 	false 	0x0000
CRC-16/DDS-110
	0x9ECF 	0x9ECF 	0x8005 	0x800D 	false 	false 	0x0000
CRC-16/DECT-R
	0x007E 	0x007E 	0x0589 	0x0000 	false 	false 	0x0001
CRC-16/DECT-X
	0x007F 	0x007F 	0x0589 	0x0000 	false 	false 	0x0000
CRC-16/DNP
	0xEA82 	0xEA82 	0x3D65 	0x0000 	true 	true 	0xFFFF
CRC-16/EN-13757
	0xC2B7 	0xC2B7 	0x3D65 	0x0000 	false 	false 	0xFFFF
CRC-16/GENIBUS
	0xD64E 	0xD64E 	0x1021 	0xFFFF 	false 	false 	0xFFFF
CRC-16/GSM
	0xCE3C 	0xCE3C 	0x1021 	0x0000 	false 	false 	0xFFFF
CRC-16/IBM-3740
	0x29B1 	0x29B1 	0x1021 	0xFFFF 	false 	false 	0x0000
CRC-16/IBM-SDLC
	0x906E 	0x906E 	0x1021 	0xFFFF 	true 	true 	0xFFFF
CRC-16/ISO-IEC-14443-3-A
	0xBF05 	0xBF05 	0x1021 	0xC6C6 	true 	true 	0x0000
CRC-16/KERMIT
	0x2189 	0x2189 	0x1021 	0x0000 	true 	true 	0x0000
CRC-16/LJ1200
	0xBDF4 	0xBDF4 	0x6F63 	0x0000 	false 	false 	0x0000
CRC-16/M17
	0x772B 	0x772B 	0x5935 	0xFFFF 	false 	false 	0x0000
CRC-16/MAXIM-DOW
	0x44C2 	0x44C2 	0x8005 	0x0000 	true 	true 	0xFFFF
CRC-16/MCRF4XX
	0x6F91 	0x6F91 	0x1021 	0xFFFF 	true 	true 	0x0000
CRC-16/MODBUS
	0x4B37 	0x4B37 	0x8005 	0xFFFF 	true 	true 	0x0000
CRC-16/NRSC-5
	0xA066 	0xA066 	0x080B 	0xFFFF 	true 	true 	0x0000
CRC-16/OPENSAFETY-A
	0x5D38 	0x5D38 	0x5935 	0x0000 	false 	false 	0x0000
CRC-16/OPENSAFETY-B
	0x20FE 	0x20FE 	0x755B 	0x0000 	false 	false 	0x0000
CRC-16/PROFIBUS
	0xA819 	0xA819 	0x1DCF 	0xFFFF 	false 	false 	0xFFFF
CRC-16/RIELLO
	0x63D0 	0x63D0 	0x1021 	0xB2AA 	true 	true 	0x0000
CRC-16/SPI-FUJITSU
	0xE5CC 	0xE5CC 	0x1021 	0x1D0F 	false 	false 	0x0000
CRC-16/T10-DIF
	0xD0DB 	0xD0DB 	0x8BB7 	0x0000 	false 	false 	0x0000
CRC-16/TELEDISK
	0x0FB3 	0x0FB3 	0xA097 	0x0000 	false 	false 	0x0000
CRC-16/TMS37157
	0x26B1 	0x26B1 	0x1021 	0x89EC 	true 	true 	0x0000
CRC-16/UMTS
	0xFEE8 	0xFEE8 	0x8005 	0x0000 	false 	false 	0x0000
CRC-16/USB
	0xB4C8 	0xB4C8 	0x8005 	0xFFFF 	true 	true 	0xFFFF
CRC-16/XMODEM
	0x31C3 	0x31C3 	0x1021 	0x0000 	false 	false 	0x0000
CRC-32/AIXM
	0x3010BF7F 	0x3010BF7F 	0x814141AB 	0x00000000 	false 	false 	0x00000000
CRC-32/AUTOSAR
	0x1697D06A 	0x1697D06A 	0xF4ACFB13 	0xFFFFFFFF 	true 	true 	0xFFFFFFFF
CRC-32/BASE91-D
	0x87315576 	0x87315576 	0xA833982B 	0xFFFFFFFF 	true 	true 	0xFFFFFFFF
CRC-32/BZIP2
	0xFC891918 	0xFC891918 	0x04C11DB7 	0xFFFFFFFF 	false 	false 	0xFFFFFFFF
CRC-32/CD-ROM-EDC
	0x6EC2EDC4 	0x6EC2EDC4 	0x8001801B 	0x00000000 	true 	true 	0x00000000
CRC-32/CKSUM
	0x765E7680 	0x765E7680 	0x04C11DB7 	0x00000000 	false 	false 	0xFFFFFFFF
CRC-32/ISCSI
	0xE3069283 	0xE3069283 	0x1EDC6F41 	0xFFFFFFFF 	true 	true 	0xFFFFFFFF
CRC-32/ISO-HDLC
	0xCBF43926 	0xCBF43926 	0x04C11DB7 	0xFFFFFFFF 	true 	true 	0xFFFFFFFF
CRC-32/JAMCRC
	0x340BC6D9 	0x340BC6D9 	0x04C11DB7 	0xFFFFFFFF 	true 	true 	0x00000000
CRC-32/MEF
	0xD2C22F51 	0xD2C22F51 	0x741B8CD7 	0xFFFFFFFF 	true 	true 	0x00000000
CRC-32/MPEG-2
	0x0376E6E7 	0x0376E6E7 	0x04C11DB7 	0xFFFFFFFF 	false 	false 	0x00000000
CRC-32/XFER
	0xBD0BE338 	0xBD0BE338 	0x000000AF 	0x00000000 	false 	false 	0x00000000
]#
