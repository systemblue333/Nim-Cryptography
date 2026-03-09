type
  # TEA context
  TEACtx* {.exportc: "TEACtx", completeStruct.} = object
    key*: array[16, uint8]
  # XTEA context
  XTEACtx* {.exportc: "XTEACtx", completeStruct.} = object
    key*: array[16, uint8]
  # XXTEA context
  XXTEACtx* {.exportc: "XXTEACtx", completeScript.} = object
    key*: array[16, uint8]

# tea encrypt core
template teaEncryptC(ctx: TEACtx, input: ptr UncheckedArray[uint8]): void =
  # cast array[16, uint8] to ptr array[4, uint32]
  # tea's key size : 16 bytes(128 bits)
  let key: ptr array[4, uint32] = cast[ptr array[4, uint32]](addr ctx.key[0])
  # cast ptr UncheckedArray[uint8] to ptr array[2, uint32]
  # tea's block size : 8 bytes(64 bits)
  let value: ptr array[2, uint32] = cast[ptr array[2, uint32]](input)

  # declare temporary variables and initialise it with value
  var v0: uint32 = value[0]
  var v1: uint32 = value[1]
  # declare sum and initialise
  var sum: uint32 = 0

  # main encryption loop(for 32)
  # use static to unroll it in compile time
  for i in static(0 ..< 32):
    # add constant delta to sum
    sum += 0x9E3779B9'u32
    # feistel network structure
    # exchange v0 and v1 after calculating
    v0 += ((v1 shl 4) + key[0]) xor (v1 + sum) xor ((v1 shr 5) + key[1])
    v1 += ((v0 shl 4) + key[2]) xor (v0 + sum) xor ((v0 shr 5) + key[3])

  # store temporary variables to value
  value[0] = v0
  value[1] = v1

# tea decrypt core
template teaDecryptC(ctx: TEACtx, input: ptr UncheckedArray[uint8]): void =
  # cast array[16, uint8] to ptr array[4, uint32]
  # tea's key size : 16 bytes(128 bits)
  let key: ptr array[4, uint32] = cast[ptr array[4, uint32]](addr ctx.key[0])
  # cast ptr UncheckedArray[uint8] to ptr array[2, uint32]
  # tea's block size : 8 bytes(64 bits)
  let value: ptr array[2, uint32] = cast[ptr array[2, uint32]](input)

  # declare temporary variables and initialise it with value
  var v0: uint32 = value[0]
  var v1: uint32 = value[1]
  # declare sum and initialise
  var sum: uint32 = 0xC6EF3720'u32

  # main encryption loop(for 32)
  # use static to unroll it in compile time
  for i in static(0 ..< 32):
    # feistel network structure
    # exchange v0 and v1 after calculating
    v1 -= ((v0 shl 4) + key[2]) xor (v0 + sum) xor ((v0 shr 5) + key[3])
    v0 -= ((v1 shl 4) + key[0]) xor (v1 + sum) xor ((v1 shr 5) + key[1])
    # sub constant delta to sum
    sum -= 0x9E3779B9'u32

  # store temporary variables to value
  value[0] = v0
  value[1] = v1

template xteaEncryptC(ctx: XTEACtx, input: ptr UncheckedArray[uint8], round: int): void =
  # cast ptr array[16, uint8] to ptr array[4, uint32]
  # xtea's key size : 16 bytes(128 bits)
  let key: ptr array[4, uint32] = cast[ptr array[4, uint32]](addr ctx.key[0])
  # cast ptr UncheckedArray[uint8] to ptr array[2, uint32]
  # xtea's block size : 8 bytes(64 bits)
  let value: ptr array[2, uint32] = cast[ptr array[2, uint32]](input)

  # declare temporary variables and initialise it with value
  var v0: uint32 = value[0]
  var v1: uint32 = value[1]
  # declare sum and initialise
  var sum: uint32 = 0

  # main encryption loop(for round)
  for i in 0 ..< round:
    # feistel network structure
    # exchange v0 and v1 after calculating
    # add constant delta to sum in middle
    v0 += ((v1 shl 4) xor (v1 shr 5) + v1) xor (sum + key[sum and 3])
    sum += 0x9E3779B9'u32
    v1 += ((v0 shl 4) xor (v0 shr 5) + v0) xor (sum + key[(sum shr 11) and 3])

  # store temporary variables to value
  value[0] = v0
  value[1] = v1

# xtea decrypt core
template xteaDecryptC(ctx: XTEACtx, input: ptr UncheckedArray[uint8], round: int): void =
  # cast ptr array[16, uint8] to ptr array[4, uint32]
  # xtea's key size : 16 bytes(128 bits)
  let key: ptr array[4, uint32] = cast[ptr array[4, uint32]](addr ctx.key[0])
  # cast ptr UncheckedArray[uint8] to ptr array[2, uint32]
  # xtea's block size : 8 bytes(64 bits)
  let value: ptr array[2, uint32] = cast[ptr array[2, uint32]](input)

  # declare temporary variables and initialise it with value
  var v0: uint32 = value[0]
  var v1: uint32 = value[1]
  # declare sum and initialise
  var sum: uint32 = 0

  # main encryption loop(for round)
  for i in 0 ..< round:
    # feistel network structure
    # exchange v0 and v1 after calculating
    # add constant delta to sum in middle
    v1 -= ((v0 shl 4) xor (v0 shr 5) + v0) xor (sum + key[(sum shr 11) and 3])
    sum -= 0x9E3779B9'u32
    v0 -= ((v1 shl 4) xor (v1 shr 5) + v1) xor (sum + key[sum and 3])

  # store temporary variables to value
  value[0] = v0
  value[1] = v1

# mx template
template mx(z, y, sum, p, e: uint32, key: ptr array[4, uint32]): uint32 =
  ((z shr 5) xor (y shl 2)) + ((y shr 3) xor (z shl 4)) xor ((sum xor y) + (key[p and 3 xor e] xor z))

# xxtea encrypt core
template xxteaEncryptC(ctx: XXTEACtx, input: openArray[uint8]): void =
  # calculate input length
  let inputLen: int = input.len
  # number of 32-bit words
  let n: int = inputLen div 4
  # dynamic rounds calculation
  var q = 6 + 52 div n

  # cast key and value for 32 bit word operations
  let key: ptr array[4, uint32] = cast[ptr array[4, uint32]](addr ctx.key[0])
  let value: ptr UncheckedArray[uint32] = cast[ptr UncheckedArray[uint32]](unsafeAddr input[0])

  # last element of the block
  var z: uint32 = value[n - 1]
  # first elemtn of the block
  var y: uint32 = value[0]
  # sum
  var sum: uint32  = 0
  var e: uint32 = 0

  # main encryption loop
  while (q > 0):
    sum += 0x9E3779B9'u32
    e = (sum shr 2) and 3

    # update all elements except the last one
    for i in 0 ..< n - 1:
      y = value[i + 1]
      value[i] += mx(z, y, sum, i.uint32, e, key)
      z = value[i]

    # final step : update the last element using the first element
    y = value[0]
    v[n - 1] += mx(z, y, sum, (n - 1).uint32, e, key)
    z = value[n - 1]
    q.dec

# xxtea decrypt core : openArray version
template xxteaDecryptC(ctx: XXTEACtx, input: openArray[uint8]): void =
  # input length
  let inputLen: int = input.len
  # number of 32 bit words
  let n: int = inputLen div 4
  # dynamic rounds calculation
  var q: int = 6 + 52 div n

  # cast key and value for 32bit operations
  let key: ptr array[4, uint32] = cast[ptr array[4, uint32]](addr ctx.key[0])
  let value: ptr UncheckedArray[uint32] = cast[ptr UncheckedArray[uint32]](unsafeAddr input[0])

  # store last element of block in temporary variables
  var z: uint32 = value[n - 1]
  # store first element of block in temporary variables
  var y: uint32 = value[0]
  # declare sum and initialise
  var sum: uint32 = 0x9E3779B9'u32 * q
  var e: uint32 = 0

  # main dcryption loop (reverse of encryption)
  while sum != 0:
    e = (sum shr 2) and 3

    # update elements in reverse order (from last to second)
    for i in countdown(n - 1, 1):
      z = value[i - 1]
      value[i] -= mx(z, y, sum, i.uint32, e, key)
      y = value[i]

    # final step : update the first element using the last element
    z = value[n - 1]
    value[0] -= mx(z, y, sum, 0.uint32, e, key)
    y = value[0]

    # de-accumulate delta
    sum -= 0x9E3779B9'u32

# xxtea decrypt core : UncheckedArray version(must need length)
template xxteaEncryptC(ctx: XXTEACtx, input: ptr UncheckedArray[uint8], inputLen: int): void =
  # number of 32 bit words
  let n: int = inputLen div 4
  # dynamic rounds calculation
  var q = 6 + 52 div n

  # cast key and value for 32bit operations
  let key: ptr array[4, uint32] = cast[ptr array[4, uint32]](addr ctx.key[0])
  let value: ptr UncheckedArray[uint32] = cast[ptr UncheckedArray[uint32]](input)

  # store last element of block in temporary variables
  var z: uint32 = value[n - 1]
  # store first element of block in temporary variables
  var y: uint32 = value[0]
  # declare sum and initialise
  var sum: uint32  = 0
  var e: uint32 = 0

  # main dcryption loop (reverse of encryption)
  while (q > 0):
    sum += 0x9E3779B9'u32
    e = (sum shr 2) and 3

    # update elements in reverse order (from last to second)
    for i in 0 ..< n - 1:
      y = value[i + 1]
      value[i] += mx(z, y, sum, i.uint32, e, key)
      z = value[i]

    # final step : update the first element using the last element
    y = value[0]
    value[n - 1] += mx(z, y, sum, (n - 1).uint32, e, key)
    z = value[n - 1]
    q.dec

template xxteaDecryptC(ctx: XXTEACtx, input: ptr UncheckedArray[uint8], inputLen: int): void =
  # number of 32 bit words
  let n: int = inputLen div 4
  # dynamic rounds calculation
  var q: int = 6 + 52 div n

  # cast key and value for 32bit operations
  let key: ptr array[4, uint32] = cast[ptr array[4, uint32]](addr ctx.key[0])
  let value: ptr UncheckedArray[uint32] = cast[ptr UncheckedArray[uint32]](input)

  # store last element of block in temporary variables
  var z: uint32 = value[n - 1]
  # store first element of block in temporary variables
  var y: uint32 = value[0]
  # declare sum and initialise
  var sum: uint32 = 0x9E3779B9'u32 * q
  var e: uint32 = 0

  # main dcryption loop (reverse of encryption)
  while sum != 0:
    e = (sum shr 2) and 3
    for i in countdown(n - 1, 1):
      z = value[i - 1]
      value[i] -= mx(z, y, sum, i.uint32, e, key)
      y = value[i]

    # final step : update the first element using the last element
    z = value[n - 1]
    value[0] -= mx(z, y, sum, 0.uint32, e, key)
    y = value[0]

    # de-accumulate delta
    sum -= 0x9E3779B9'u32

# export wrappers
when defined(templateOpt):
  template teaEncrypt*(ctx: TEACtx, input: var openArray[uint8]): void =
    teaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]))
  template teaEncrypt*(ctx: TEACtx, input: var array[8, uint8]): void =
    teaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  template teaEncrypt*(ctx: TEACtx, input: ptr UncheckedArray[uint8]): void =
    teaEncryptC(ctx, input)
  template teaEncrypt*(ctx: TEACtx, input: ptr array[8, uint8]): void =
    teaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))

  template teaDecrypt*(ctx: TEACtx, input: var openArray[uint8]): void =
    teaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]))
  template teaDecrypt*(ctx: TEACtx, input: var array[8, uint8]): void =
    teaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  template teaDecrypt*(ctx: TEACtx, input: ptr UncheckedArray[uint8]): void =
    teaDecryptC(ctx, input)
  template teaDecrypt*(ctx: TEACtx, input: ptr array[8, uint8]): void =
    teaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))

  template xteaEncrypt*(ctx: XTEACtx, input: var openArray[uint8], round: int): void =
    xteaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]))
  template xteaEncrypt*(ctx: XTEACtx, input: var array[8, uint8], round: int): void =
    xteaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  template xteaEncrypt*(ctx: XTEACtx, input: ptr UncheckedArray[uint8], round: int): void =
    xteaEncryptC(ctx, input)
  template xteaEncrypt*(ctx: XTEACtx, input: ptr array[8, uint8], round: int): void =
    xteaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))

  template xteaDecrypt*(ctx: XTEACtx, input: var openArray[uint8], round: int): void =
    xteaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]), round)
  template xteaDecrypt*(ctx: XTEACtx, input: var array[8, uint8], round: int): void =
    xteaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]), round)
  template xteaDecrypt*(ctx: XTEACtx, input: ptr UncheckedArray[uint8], round: int): void =
    xteaDecryptC(ctx, input, round)
  template xteaDecrypt*(ctx: XTEACtx, input: ptr array[8, uint8], round: int): void =
    xteaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]), round)

  template xxteaEncrypt*(ctx: XXTEACtx, input: var openArray[uint8]): void =
    xxteaEncryptC(ctx, input)
  template xxteaEncrypt*(ctx: XXTEACtx, input: ptr UncheckedArray[uint8], inputLen: int): void =
    xxteaEncryptC(ctx, input, inputLen)

  template xxteaDecrypt*(ctx: XXTEACtx, input: var openArray[uint8]): void =
    xxteaDecrypt(ctx, input)
  template xxteaDecrypt*(ctx: XXTEACtx, input: ptr UncheckedArray[uint8], inputLen: int): void =
    xxteaDecrypt(ctx, input, inputLen)
else:
  proc teaEncrypt*(ctx: TEACtx, input: var openArray[uint8]): void =
    teaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]))
  proc teaEncrypt*(ctx: TEACtx, input: var array[8, uint8]): void =
    teaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  proc teaEncrypt*(ctx: TEACtx, input: ptr UncheckedArray[uint8]): void {.exportc: "tea_encrypt_unchecked", cdecl.} =
    teaEncryptC(ctx, input)
  proc teaEncrypt*(ctx: TEACtx, input: ptr array[8, uint8]): void {.exportc: "tea_encrypt", cdecl.} =
    teaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))

  proc teaDecrypt*(ctx: TEACtx, input: var openArray[uint8]): void =
    teaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]))
  proc teaDecrypt*(ctx: TEACtx, input: var array[8, uint8]): void =
    teaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  proc teaDecrypt*(ctx: TEACtx, input: ptr UncheckedArray[uint8]): void {.exportc: "tea_decrypt_unchecked", cdecl.} =
    teaDecryptC(ctx, input)
  proc teaDecrypt*(ctx: TEACtx, input: ptr array[8, uint8]): void {.exportc: "tea_decrypt", cdecl.} =
    teaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))

  proc xteaEncrypt*(ctx: XTEACtx, input: var openArray[uint8], round: int): void =
    xteaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]))
  proc xteaEncrypt*(ctx: XTEACtx, input: var array[8, uint8], round: int): void =
    xteaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  proc xteaEncrypt*(ctx: XTEACtx, input: ptr UncheckedArray[uint8], round: int): void {.exportc: "xtea_encrypt_unchecked", cdecl.} =
    xteaEncryptC(ctx, input)
  proc xteaEncrypt*(ctx: XTEACtx, input: ptr array[8, uint8], round: int): void {.exportc: "xtea_encrypt", cdecl.} =
    xteaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))

  proc xteaDecrypt*(ctx: XTEACtx, input: var openArray[uint8], round: int): void =
    xteaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]), round)
  proc xteaDecrypt*(ctx: XTEACtx, input: var array[8, uint8], round: int): void =
    xteaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]), round)
  proc xteaDecrypt*(ctx: XTEACtx, input: ptr UncheckedArray[uint8], round: int): void {.exportc: "xtea_decrypt_unchecked", cdecl.}=
    xteaDecryptC(ctx, input, round)
  proc xteaDecrypt*(ctx: XTEACtx, input: ptr array[8, uint8], round: int): void {.exportc: "xtea_decrypt", cdecl.} =
    xteaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]), round)

  proc xxteaEncrypt*(ctx: XXTEACtx, input: var openArray[uint8]): void =
    xxteaEncryptC(ctx, input)
  proc xxteaEncrypt*(ctx: XXTEACtx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "xxtea_encrypt", cdecl.} =
    xxteaEncryptC(ctx, input, inputLen)

  proc xxteaDecrypt*(ctx: XXTEACtx, input: var openArray[uint8]): void =
    xxteaDecrypt(ctx, input)
  proc xxteaDecrypt*(ctx: XXTEACtx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "xxtea_decrypt", cdecl.} =
    xxteaDecrypt(ctx, input, inputLen)
