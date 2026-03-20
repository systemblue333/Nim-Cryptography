import ../../../../Utility/src/Utility/codeutils/bits
import ../../../../Utility/src/Utility/codeutils/bigtype
import ../../../../Utility/src/Utility/dataformat/dataformat
import std/[monotimes, times]
import std/bitops

const
  # declare S-Box 1/2/3/4
  SBox1: array[256, uint8] = [
    0x63'u8, 0x7c'u8, 0x77'u8, 0x7b'u8, 0xf2'u8, 0x6b'u8, 0x6f'u8, 0xc5'u8, 0x30'u8, 0x01'u8, 0x67'u8, 0x2b'u8, 0xfe'u8, 0xd7'u8, 0xab'u8, 0x76'u8,
    0xca'u8, 0x82'u8, 0xc9'u8, 0x7d'u8, 0xfa'u8, 0x59'u8, 0x47'u8, 0xf0'u8, 0xad'u8, 0xd4'u8, 0xa2'u8, 0xaf'u8, 0x9c'u8, 0xa4'u8, 0x72'u8, 0xc0'u8,
    0xb7'u8, 0xfd'u8, 0x93'u8, 0x26'u8, 0x36'u8, 0x3f'u8, 0xf7'u8, 0xcc'u8, 0x34'u8, 0xa5'u8, 0xe5'u8, 0xf1'u8, 0x71'u8, 0xd8'u8, 0x31'u8, 0x15'u8,
    0x04'u8, 0xc7'u8, 0x23'u8, 0xc3'u8, 0x18'u8, 0x96'u8, 0x05'u8, 0x9a'u8, 0x07'u8, 0x12'u8, 0x80'u8, 0xe2'u8, 0xeb'u8, 0x27'u8, 0xb2'u8, 0x75'u8,
    0x09'u8, 0x83'u8, 0x2c'u8, 0x1a'u8, 0x1b'u8, 0x6e'u8, 0x5a'u8, 0xa0'u8, 0x52'u8, 0x3b'u8, 0xd6'u8, 0xb3'u8, 0x29'u8, 0xe3'u8, 0x2f'u8, 0x84'u8,
    0x53'u8, 0xd1'u8, 0x00'u8, 0xed'u8, 0x20'u8, 0xfc'u8, 0xb1'u8, 0x5b'u8, 0x6a'u8, 0xcb'u8, 0xbe'u8, 0x39'u8, 0x4a'u8, 0x4c'u8, 0x58'u8, 0xcf'u8,
    0xd0'u8, 0xef'u8, 0xaa'u8, 0xfb'u8, 0x43'u8, 0x4d'u8, 0x33'u8, 0x85'u8, 0x45'u8, 0xf9'u8, 0x02'u8, 0x7f'u8, 0x50'u8, 0x3c'u8, 0x9f'u8, 0xa8'u8,
    0x51'u8, 0xa3'u8, 0x40'u8, 0x8f'u8, 0x92'u8, 0x9d'u8, 0x38'u8, 0xf5'u8, 0xbc'u8, 0xb6'u8, 0xda'u8, 0x21'u8, 0x10'u8, 0xff'u8, 0xf3'u8, 0xd2'u8,
    0xcd'u8, 0x0c'u8, 0x13'u8, 0xec'u8, 0x5f'u8, 0x97'u8, 0x44'u8, 0x17'u8, 0xc4'u8, 0xa7'u8, 0x7e'u8, 0x3d'u8, 0x64'u8, 0x5d'u8, 0x19'u8, 0x73'u8,
    0x60'u8, 0x81'u8, 0x4f'u8, 0xdc'u8, 0x22'u8, 0x2a'u8, 0x90'u8, 0x88'u8, 0x46'u8, 0xee'u8, 0xb8'u8, 0x14'u8, 0xde'u8, 0x5e'u8, 0x0b'u8, 0xdb'u8,
    0xe0'u8, 0x32'u8, 0x3a'u8, 0x0a'u8, 0x49'u8, 0x06'u8, 0x24'u8, 0x5c'u8, 0xc2'u8, 0xd3'u8, 0xac'u8, 0x62'u8, 0x91'u8, 0x95'u8, 0xe4'u8, 0x79'u8,
    0xe7'u8, 0xc8'u8, 0x37'u8, 0x6d'u8, 0x8d'u8, 0xd5'u8, 0x4e'u8, 0xa9'u8, 0x6c'u8, 0x56'u8, 0xf4'u8, 0xea'u8, 0x65'u8, 0x7a'u8, 0xae'u8, 0x08'u8,
    0xba'u8, 0x78'u8, 0x25'u8, 0x2e'u8, 0x1c'u8, 0xa6'u8, 0xb4'u8, 0xc6'u8, 0xe8'u8, 0xdd'u8, 0x74'u8, 0x1f'u8, 0x4b'u8, 0xbd'u8, 0x8b'u8, 0x8a'u8,
    0x70'u8, 0x3e'u8, 0xb5'u8, 0x66'u8, 0x48'u8, 0x03'u8, 0xf6'u8, 0x0e'u8, 0x61'u8, 0x35'u8, 0x57'u8, 0xb9'u8, 0x86'u8, 0xc1'u8, 0x1d'u8, 0x9e'u8,
    0xe1'u8, 0xf8'u8, 0x98'u8, 0x11'u8, 0x69'u8, 0xd9'u8, 0x8e'u8, 0x94'u8, 0x9b'u8, 0x1e'u8, 0x87'u8, 0xe9'u8, 0xce'u8, 0x55'u8, 0x28'u8, 0xdf'u8,
    0x8c'u8, 0xa1'u8, 0x89'u8, 0x0d'u8, 0xbf'u8, 0xe6'u8, 0x42'u8, 0x68'u8, 0x41'u8, 0x99'u8, 0x2d'u8, 0x0f'u8, 0xb0'u8, 0x54'u8, 0xbb'u8, 0x16'u8
  ]
  SBox2: array[256, uint8] = [
    0xe2'u8, 0x4e'u8, 0x54'u8, 0xfc'u8, 0x94'u8, 0xc2'u8, 0x4a'u8, 0xcc'u8, 0x62'u8, 0x0d'u8, 0x6a'u8, 0x46'u8, 0x3c'u8, 0x4d'u8, 0x8b'u8, 0xd1'u8,
    0x5e'u8, 0xfa'u8, 0x64'u8, 0xcb'u8, 0xb4'u8, 0x97'u8, 0xbe'u8, 0x2b'u8, 0xbc'u8, 0x77'u8, 0x2e'u8, 0x03'u8, 0xd3'u8, 0x19'u8, 0x59'u8, 0xc1'u8,
    0x1d'u8, 0x06'u8, 0x41'u8, 0x6b'u8, 0x55'u8, 0xf0'u8, 0x99'u8, 0x69'u8, 0xea'u8, 0x9c'u8, 0x18'u8, 0xae'u8, 0x63'u8, 0xdf'u8, 0xe7'u8, 0xbb'u8,
    0x00'u8, 0x73'u8, 0x66'u8, 0xfb'u8, 0x96'u8, 0x4c'u8, 0x85'u8, 0xe4'u8, 0x3a'u8, 0x09'u8, 0x45'u8, 0xaa'u8, 0x0f'u8, 0xee'u8, 0x10'u8, 0xeb'u8,
    0x2d'u8, 0x7f'u8, 0xf4'u8, 0x29'u8, 0xac'u8, 0xcf'u8, 0xad'u8, 0x91'u8, 0x8d'u8, 0x78'u8, 0xc8'u8, 0x95'u8, 0xf9'u8, 0x2f'u8, 0xce'u8, 0xcd'u8,
    0x08'u8, 0x7a'u8, 0x88'u8, 0x38'u8, 0x5c'u8, 0x83'u8, 0x2a'u8, 0x28'u8, 0x47'u8, 0xdb'u8, 0xb8'u8, 0xc7'u8, 0x93'u8, 0xa4'u8, 0x12'u8, 0x53'u8,
    0xff'u8, 0x87'u8, 0x0e'u8, 0x31'u8, 0x36'u8, 0x21'u8, 0x58'u8, 0x48'u8, 0x01'u8, 0x8e'u8, 0x37'u8, 0x74'u8, 0x32'u8, 0xca'u8, 0xe9'u8, 0xb1'u8,
    0xb7'u8, 0xab'u8, 0x0c'u8, 0xd7'u8, 0xc4'u8, 0x56'u8, 0x42'u8, 0x26'u8, 0x07'u8, 0x98'u8, 0x60'u8, 0xd9'u8, 0xb6'u8, 0xb9'u8, 0x11'u8, 0x40'u8,
    0xec'u8, 0x20'u8, 0x8c'u8, 0xbd'u8, 0xa0'u8, 0xc9'u8, 0x84'u8, 0x04'u8, 0x49'u8, 0x23'u8, 0xf1'u8, 0x4f'u8, 0x50'u8, 0x1f'u8, 0x13'u8, 0xdc'u8,
    0xd8'u8, 0xc0'u8, 0x9e'u8, 0x57'u8, 0xe3'u8, 0xc3'u8, 0x7b'u8, 0x65'u8, 0x3b'u8, 0x02'u8, 0x8f'u8, 0x3e'u8, 0xe8'u8, 0x25'u8, 0x92'u8, 0xe5'u8,
    0x15'u8, 0xdd'u8, 0xfd'u8, 0x17'u8, 0xa9'u8, 0xbf'u8, 0xd4'u8, 0x9a'u8, 0x7e'u8, 0xc5'u8, 0x39'u8, 0x67'u8, 0xfe'u8, 0x76'u8, 0x9d'u8, 0x43'u8,
    0xa7'u8, 0xe1'u8, 0xd0'u8, 0xf5'u8, 0x68'u8, 0xf2'u8, 0x1b'u8, 0x34'u8, 0x70'u8, 0x05'u8, 0xa3'u8, 0x8a'u8, 0xd5'u8, 0x79'u8, 0x86'u8, 0xa8'u8,
    0x30'u8, 0xc6'u8, 0x51'u8, 0x4b'u8, 0x1e'u8, 0xa6'u8, 0x27'u8, 0xf6'u8, 0x35'u8, 0xd2'u8, 0x6e'u8, 0x24'u8, 0x16'u8, 0x82'u8, 0x5f'u8, 0xda'u8,
    0xe6'u8, 0x75'u8, 0xa2'u8, 0xef'u8, 0x2c'u8, 0xb2'u8, 0x1c'u8, 0x9f'u8, 0x5d'u8, 0x6f'u8, 0x80'u8, 0x0a'u8, 0x72'u8, 0x44'u8, 0x9b'u8, 0x6c'u8,
    0x90'u8, 0x0b'u8, 0x5b'u8, 0x33'u8, 0x7d'u8, 0x5a'u8, 0x52'u8, 0xf3'u8, 0x61'u8, 0xa1'u8, 0xf7'u8, 0xb0'u8, 0xd6'u8, 0x3f'u8, 0x7c'u8, 0x6d'u8,
    0xed'u8, 0x14'u8, 0xe0'u8, 0xa5'u8, 0x3d'u8, 0x22'u8, 0xb3'u8, 0xf8'u8, 0x89'u8, 0xde'u8, 0x71'u8, 0x1a'u8, 0xaf'u8, 0xba'u8, 0xb5'u8, 0x81'u8
  ]
  SBox3: array[256, uint8] = [
    0x52'u8, 0x09'u8, 0x6a'u8, 0xd5'u8, 0x30'u8, 0x36'u8, 0xa5'u8, 0x38'u8, 0xbf'u8, 0x40'u8, 0xa3'u8, 0x9e'u8, 0x81'u8, 0xf3'u8, 0xd7'u8, 0xfb'u8,
    0x7c'u8, 0xe3'u8, 0x39'u8, 0x82'u8, 0x9b'u8, 0x2f'u8, 0xff'u8, 0x87'u8, 0x34'u8, 0x8e'u8, 0x43'u8, 0x44'u8, 0xc4'u8, 0xde'u8, 0xe9'u8, 0xcb'u8,
    0x54'u8, 0x7b'u8, 0x94'u8, 0x32'u8, 0xa6'u8, 0xc2'u8, 0x23'u8, 0x3d'u8, 0xee'u8, 0x4c'u8, 0x95'u8, 0x0b'u8, 0x42'u8, 0xfa'u8, 0xc3'u8, 0x4e'u8,
    0x08'u8, 0x2e'u8, 0xa1'u8, 0x66'u8, 0x28'u8, 0xd9'u8, 0x24'u8, 0xb2'u8, 0x76'u8, 0x5b'u8, 0xa2'u8, 0x49'u8, 0x6d'u8, 0x8b'u8, 0xd1'u8, 0x25'u8,
    0x72'u8, 0xf8'u8, 0xf6'u8, 0x64'u8, 0x86'u8, 0x68'u8, 0x98'u8, 0x16'u8, 0xd4'u8, 0xa4'u8, 0x5c'u8, 0xcc'u8, 0x5d'u8, 0x65'u8, 0xb6'u8, 0x92'u8,
    0x6c'u8, 0x70'u8, 0x48'u8, 0x50'u8, 0xfd'u8, 0xed'u8, 0xb9'u8, 0xda'u8, 0x5e'u8, 0x15'u8, 0x46'u8, 0x57'u8, 0xa7'u8, 0x8d'u8, 0x9d'u8, 0x84'u8,
    0x90'u8, 0xd8'u8, 0xab'u8, 0x00'u8, 0x8c'u8, 0xbc'u8, 0xd3'u8, 0x0a'u8, 0xf7'u8, 0xe4'u8, 0x58'u8, 0x05'u8, 0xb8'u8, 0xb3'u8, 0x45'u8, 0x06'u8,
    0xd0'u8, 0x2c'u8, 0x1e'u8, 0x8f'u8, 0xca'u8, 0x3f'u8, 0x0f'u8, 0x02'u8, 0xc1'u8, 0xaf'u8, 0xbd'u8, 0x03'u8, 0x01'u8, 0x13'u8, 0x8a'u8, 0x6b'u8,
    0x3a'u8, 0x91'u8, 0x11'u8, 0x41'u8, 0x4f'u8, 0x67'u8, 0xdc'u8, 0xea'u8, 0x97'u8, 0xf2'u8, 0xcf'u8, 0xce'u8, 0xf0'u8, 0xb4'u8, 0xe6'u8, 0x73'u8,
    0x96'u8, 0xac'u8, 0x74'u8, 0x22'u8, 0xe7'u8, 0xad'u8, 0x35'u8, 0x85'u8, 0xe2'u8, 0xf9'u8, 0x37'u8, 0xe8'u8, 0x1c'u8, 0x75'u8, 0xdf'u8, 0x6e'u8,
    0x47'u8, 0xf1'u8, 0x1a'u8, 0x71'u8, 0x1d'u8, 0x29'u8, 0xc5'u8, 0x89'u8, 0x6f'u8, 0xb7'u8, 0x62'u8, 0x0e'u8, 0xaa'u8, 0x18'u8, 0xbe'u8, 0x1b'u8,
    0xfc'u8, 0x56'u8, 0x3e'u8, 0x4b'u8, 0xc6'u8, 0xd2'u8, 0x79'u8, 0x20'u8, 0x9a'u8, 0xdb'u8, 0xc0'u8, 0xfe'u8, 0x78'u8, 0xcd'u8, 0x5a'u8, 0xf4'u8,
    0x1f'u8, 0xdd'u8, 0xa8'u8, 0x33'u8, 0x88'u8, 0x07'u8, 0xc7'u8, 0x31'u8, 0xb1'u8, 0x12'u8, 0x10'u8, 0x59'u8, 0x27'u8, 0x80'u8, 0xec'u8, 0x5f'u8,
    0x60'u8, 0x51'u8, 0x7f'u8, 0xa9'u8, 0x19'u8, 0xb5'u8, 0x4a'u8, 0x0d'u8, 0x2d'u8, 0xe5'u8, 0x7a'u8, 0x9f'u8, 0x93'u8, 0xc9'u8, 0x9c'u8, 0xef'u8,
    0xa0'u8, 0xe0'u8, 0x3b'u8, 0x4d'u8, 0xae'u8, 0x2a'u8, 0xf5'u8, 0xb0'u8, 0xc8'u8, 0xeb'u8, 0xbb'u8, 0x3c'u8, 0x83'u8, 0x53'u8, 0x99'u8, 0x61'u8,
    0x17'u8, 0x2b'u8, 0x04'u8, 0x7e'u8, 0xba'u8, 0x77'u8, 0xd6'u8, 0x26'u8, 0xe1'u8, 0x69'u8, 0x14'u8, 0x63'u8, 0x55'u8, 0x21'u8, 0x0c'u8, 0x7d'u8
  ]
  SBox4: array[256, uint8] = [
    0x30'u8, 0x68'u8, 0x99'u8, 0x1b'u8, 0x87'u8, 0xb9'u8, 0x21'u8, 0x78'u8, 0x50'u8, 0x39'u8, 0xdb'u8, 0xe1'u8, 0x72'u8, 0x09'u8, 0x62'u8, 0x3c'u8,
    0x3e'u8, 0x7e'u8, 0x5e'u8, 0x8e'u8, 0xf1'u8, 0xa0'u8, 0xcc'u8, 0xa3'u8, 0x2a'u8, 0x1d'u8, 0xfb'u8, 0xb6'u8, 0xd6'u8, 0x20'u8, 0xc4'u8, 0x8d'u8,
    0x81'u8, 0x65'u8, 0xf5'u8, 0x89'u8, 0xcb'u8, 0x9d'u8, 0x77'u8, 0xc6'u8, 0x57'u8, 0x43'u8, 0x56'u8, 0x17'u8, 0xd4'u8, 0x40'u8, 0x1a'u8, 0x4d'u8,
    0xc0'u8, 0x63'u8, 0x6c'u8, 0xe3'u8, 0xb7'u8, 0xc8'u8, 0x64'u8, 0x6a'u8, 0x53'u8, 0xaa'u8, 0x38'u8, 0x98'u8, 0x0c'u8, 0xf4'u8, 0x9b'u8, 0xed'u8,
    0x7f'u8, 0x22'u8, 0x76'u8, 0xaf'u8, 0xdd'u8, 0x3a'u8, 0x0b'u8, 0x58'u8, 0x67'u8, 0x88'u8, 0x06'u8, 0xc3'u8, 0x35'u8, 0x0d'u8, 0x01'u8, 0x8b'u8,
    0x8c'u8, 0xc2'u8, 0xe6'u8, 0x5f'u8, 0x02'u8, 0x24'u8, 0x75'u8, 0x93'u8, 0x66'u8, 0x1e'u8, 0xe5'u8, 0xe2'u8, 0x54'u8, 0xd8'u8, 0x10'u8, 0xce'u8,
    0x7a'u8, 0xe8'u8, 0x08'u8, 0x2c'u8, 0x12'u8, 0x97'u8, 0x32'u8, 0xab'u8, 0xb4'u8, 0x27'u8, 0x0a'u8, 0x23'u8, 0xdf'u8, 0xef'u8, 0xca'u8, 0xd9'u8,
    0xb8'u8, 0xfa'u8, 0xdc'u8, 0x31'u8, 0x6b'u8, 0xd1'u8, 0xad'u8, 0x19'u8, 0x49'u8, 0xbd'u8, 0x51'u8, 0x96'u8, 0xee'u8, 0xe4'u8, 0xa8'u8, 0x41'u8,
    0xda'u8, 0xff'u8, 0xcd'u8, 0x55'u8, 0x86'u8, 0x36'u8, 0xbe'u8, 0x61'u8, 0x52'u8, 0xf8'u8, 0xbb'u8, 0x0e'u8, 0x82'u8, 0x48'u8, 0x69'u8, 0x9a'u8,
    0xe0'u8, 0x47'u8, 0x9e'u8, 0x5c'u8, 0x04'u8, 0x4b'u8, 0x34'u8, 0x15'u8, 0x79'u8, 0x26'u8, 0xa7'u8, 0xde'u8, 0x29'u8, 0xae'u8, 0x92'u8, 0xd7'u8,
    0x84'u8, 0xe9'u8, 0xd2'u8, 0xba'u8, 0x5d'u8, 0xf3'u8, 0xc5'u8, 0xb0'u8, 0xbf'u8, 0xa4'u8, 0x3b'u8, 0x71'u8, 0x44'u8, 0x46'u8, 0x2b'u8, 0xfc'u8,
    0xeb'u8, 0x6f'u8, 0xd5'u8, 0xf6'u8, 0x14'u8, 0xfe'u8, 0x7c'u8, 0x70'u8, 0x5a'u8, 0x7d'u8, 0xfd'u8, 0x2f'u8, 0x18'u8, 0x83'u8, 0x16'u8, 0xa5'u8,
    0x91'u8, 0x1f'u8, 0x05'u8, 0x95'u8, 0x74'u8, 0xa9'u8, 0xc1'u8, 0x5b'u8, 0x4a'u8, 0x85'u8, 0x6d'u8, 0x13'u8, 0x07'u8, 0x4f'u8, 0x4e'u8, 0x45'u8,
    0xb2'u8, 0x0f'u8, 0xc9'u8, 0x1c'u8, 0xa6'u8, 0xbc'u8, 0xec'u8, 0x73'u8, 0x90'u8, 0x7b'u8, 0xcf'u8, 0x59'u8, 0x8f'u8, 0xa1'u8, 0xf9'u8, 0x2d'u8,
    0xf2'u8, 0xb1'u8, 0x00'u8, 0x94'u8, 0x37'u8, 0x9f'u8, 0xd0'u8, 0x2e'u8, 0x9c'u8, 0x6e'u8, 0x28'u8, 0x3f'u8, 0x80'u8, 0xf0'u8, 0x3d'u8, 0xd3'u8,
    0x25'u8, 0x8a'u8, 0xb5'u8, 0xe7'u8, 0x42'u8, 0xb3'u8, 0xc7'u8, 0xea'u8, 0xf7'u8, 0x4c'u8, 0x11'u8, 0x33'u8, 0x03'u8, 0xa2'u8, 0xac'u8, 0x60'u8
  ]
  # declare ARIA rounds constant
  ARIA128Rounds*: int = 12
  ARIA192Rounds*: int = 14
  ARIA256Rounds*: int = 16

  # declare ARIA key size constant
  ARIA128KeySize*: int = 16
  ARIA192KeySize*: int = 24
  ARIA256KeySize*: int = 32

  # declare ARIA block size constant
  ARIABlockSize*: int = 16

# calculate round numbers by keybits
template roundNumber*(keyBits: static int): static int =
  when keyBits == 128:
    ARIA128Rounds
  elif keyBits == 192:
    ARIA192Rounds
  else:
    ARIA256Rounds

# calculate round key size by keybits
template roundKeySize*(keyBits: static int): static int =
  when keyBits == 128:
    ARIA128Rounds + 1
  elif keyBits == 192:
    ARIA192Rounds + 1
  else:
    ARIA256Rounds + 1

type
  # declare ARIA generic context
  ARIACtx*[keyBits: static int] = object
    roundKeyE*: array[roundKeySize(keyBits), uint128]
    roundKeyD*: array[roundKeySize(keyBits), uint128]

  # declare ARIA-128/192/256 context
  ARIA128Ctx* = ARIACtx[128]
  ARIA192Ctx* = ARIACtx[192]
  ARIA256Ctx* = ARIACtx[256]

# extend key
template extendKey[N: static int](roundKey: var array[N, uint128], w0, w1, w2, w3: uint128): void =
  # when keybits is over 128
  roundKey[0] = w0 xor rotateRightBits(w1, 19)
  roundKey[1] = w1 xor rotateRightBits(w2, 19)
  roundKey[2] = w2 xor rotateRightBits(w3, 19)
  roundKey[3] = rotateRightBits(w0, 19) xor w3
  roundKey[4] = w0 xor rotateRightBits(w1, 31)
  roundKey[5] = w1 xor rotateRightBits(w2, 31)
  roundKey[6] = w2 xor rotateRightBits(w3, 31)
  roundKey[7] = rotateRightBits(w0, 31) xor w3
  roundKey[8] = w0 xor rotateLeftBits(w1, 61)
  roundKey[9] = w1 xor rotateLeftBits(w2, 61)
  roundKey[10] = w2 xor rotateLeftBits(w3, 61)
  roundKey[11] = rotateLeftBits(w0, 61) xor w3
  roundKey[12] = w0 xor rotateLeftBits(w1, 31)

  # when keybits is over 192
  when N > 13:
    roundKey[13] = w1 xor rotateLeftBits(w2, 31)
    roundKey[14] = w2 xor rotateLeftBits(w3, 31)
    # when keybits is over 256
    when N == 17:
      roundKey[15] = rotateLeftBits(w0, 31) xor w3
      roundKey[16] = w0 xor rotateLeftBits(w1, 19)

# aria sub1 template
template sub1[N: static int, T](state: ptr array[N, T]): void =
  # cast to ptr array[16, uint8]
  var chunk: ptr array[16, uint8] = cast[ptr array[16, uint8]](state)

  # replace each byte with SBox1, SBox2, SBox3, SBox4
  for i in static(0 ..< 4):
    chunk[i * 4 + 0] = SBox1[chunk[i * 4 + 0]]
    chunk[i * 4 + 1] = SBox2[chunk[i * 4 + 1]]
    chunk[i * 4 + 2] = SBox3[chunk[i * 4 + 2]]
    chunk[i * 4 + 3] = SBox4[chunk[i * 4 + 3]]

# aria sub2 template
template sub2[N: static int, T](state: ptr array[N, T]): void =
  # cast to ptr array[16, uint8
  var chunk: ptr array[16, uint8] = cast[ptr array[16, uint8]](state)

  # replace each byte with SBox3, SBox4, SBox1, SBox2
  for i in static(0 ..< 4):
    chunk[i * 4 + 0] = SBox3[chunk[i * 4 + 0]]
    chunk[i * 4 + 1] = SBox4[chunk[i * 4 + 1]]
    chunk[i * 4 + 2] = SBox1[chunk[i * 4 + 2]]
    chunk[i * 4 + 3] = SBox2[chunk[i * 4 + 3]]

# rotateLeftBits for uint128
template rotateLeftBits*(a: uint128, shift: int): uint128 =
  let s = shift mod 128
  var output: uint128
  if s == 0:
    output = a
  elif s == 64:
    output.value[0] = a.value[1]
    output.value[1] = a.value[0]
  elif s < 64:
    output.value[0] = (a.value[0] shl s) or (a.value[1] shr (64 - s))
    output.value[1] = (a.value[1] shl s) or (a.value[0] shr (64 - s))
  else: # s > 64
    let s2 = s - 64
    output.value[0] = (a.value[1] shl s2) or (a.value[0] shr (64 - s2))
    output.value[1] = (a.value[0] shl s2) or (a.value[1] shr (64 - s2))
  output

# rotateRightBits for uint128
template rotateRightBits*(a: uint128, shift: int): uint128 =
  rotateLeftBits(a, 128 - (shift mod 128))

# ariaA template
template ariaA(state: ptr array[16, uint8]): void =
  # set temporary state variables
  let x0 = state[0]; let x1 = state[1]; let x2 = state[2]; let x3 = state[3]
  let x4 = state[4]; let x5 = state[5]; let x6 = state[6]; let x7 = state[7]
  let x8 = state[8]; let x9 = state[9]; let x10 = state[10]; let x11 = state[11]
  let x12 = state[12]; let x13 = state[13]; let x14 = state[14]; let x15 = state[15]

  # calculate t0, t1, t2, t3
  let t0 = x0 xor x7 xor x10 xor x13
  let t1 = x1 xor x6 xor x11 xor x12
  let t2 = x2 xor x5 xor x8 xor x15
  let t3 = x3 xor x4 xor x9 xor x14

  # replace state with t0, t1, t2, t3
  state[0] = t3 xor x6 xor x8 xor x13
  state[1] = t2 xor x7 xor x9 xor x12
  state[2] = t1 xor x4 xor x10 xor x15
  state[3] = t0 xor x5 xor x11 xor x14
  state[4] = x0 xor t2 xor x11 xor x14
  state[5] = x1 xor t3 xor x10 xor x15
  state[6] = t0 xor x2 xor x9 xor x12
  state[7] = t1 xor x3 xor x8 xor x13
  state[8] = t0 xor x1 xor x4 xor x15
  state[9] = x0 xor t1 xor x5 xor x14
  state[10] = t2 xor x3 xor x6 xor x13
  state[11] = x2 xor t3 xor x7 xor x12
  state[12] = t1 xor x2 xor x7 xor x9
  state[13] = t0 xor x3 xor x6 xor x8
  state[14] = x0 xor t3 xor x5 xor x11
  state[15] = x1 xor t2 xor x4 xor x10

# ariaA template for uint128
template ariaA(u: var uint128): void =
  let v1 = u.value[1]
  let v0 = u.value[0]

  # set temporary state variables
  let x0 = uint8(v1 shr 56); let x1 = uint8(v1 shr 48); let x2 = uint8(v1 shr 40); let x3 = uint8(v1 shr 32)
  let x4 = uint8(v1 shr 24); let x5 = uint8(v1 shr 16); let x6 = uint8(v1 shr 8);  let x7 = uint8(v1)
  let x8 = uint8(v0 shr 56); let x9 = uint8(v0 shr 48); let x10 = uint8(v0 shr 40); let x11 = uint8(v0 shr 32)
  let x12 = uint8(v0 shr 24); let x13 = uint8(v0 shr 16); let x14 = uint8(v0 shr 8);  let x15 = uint8(v0)

  # calculate t0, t1, t2, t3
  let t0 = x0 xor x7 xor x10 xor x13
  let t1 = x1 xor x6 xor x11 xor x12
  let t2 = x2 xor x5 xor x8 xor x15
  let t3 = x3 xor x4 xor x9 xor x14

  # replace u.value[1] with t0, t1, t2, t3
  u.value[1] = (uint64(t3 xor x6 xor x8 xor x13) shl 56) or
               (uint64(t2 xor x7 xor x9 xor x12) shl 48) or
               (uint64(t1 xor x4 xor x10 xor x15) shl 40) or
               (uint64(t0 xor x5 xor x11 xor x14) shl 32) or
               (uint64(x0 xor t2 xor x11 xor x14) shl 24) or
               (uint64(x1 xor t3 xor x10 xor x15) shl 16) or
               (uint64(t0 xor x2 xor x9 xor x12) shl 8) or
               uint64(t1 xor x3 xor x8 xor x13)

  # replace u.value[0] with t0, t1, t2, t3
  u.value[0] = (uint64(t0 xor x1 xor x4 xor x15) shl 56) or
               (uint64(x0 xor t1 xor x5 xor x14) shl 48) or
               (uint64(t2 xor x3 xor x6 xor x13) shl 40) or
               (uint64(x2 xor t3 xor x7 xor x12) shl 32) or
               (uint64(t1 xor x2 xor x7 xor x9) shl 24) or
               (uint64(t0 xor x3 xor x6 xor x8) shl 16) or
               (uint64(x0 xor t3 xor x5 xor x11) shl 8) or
               uint64(x1 xor t2 xor x4 xor x10)

# aria sub1 template for uint128 
template sub1(u: var uint128): void =
  u.value[1] = (uint64(SBox1[uint8(u.value[1] shr 56)]) shl 56) or
               (uint64(SBox2[uint8(u.value[1] shr 48)]) shl 48) or
               (uint64(SBox3[uint8(u.value[1] shr 40)]) shl 40) or
               (uint64(SBox4[uint8(u.value[1] shr 32)]) shl 32) or
               (uint64(SBox1[uint8(u.value[1] shr 24)]) shl 24) or
               (uint64(SBox2[uint8(u.value[1] shr 16)]) shl 16) or
               (uint64(SBox3[uint8(u.value[1] shr 8)]) shl 8) or
               uint64(SBox4[uint8(u.value[1])])
  u.value[0] = (uint64(SBox1[uint8(u.value[0] shr 56)]) shl 56) or
               (uint64(SBox2[uint8(u.value[0] shr 48)]) shl 48) or
               (uint64(SBox3[uint8(u.value[0] shr 40)]) shl 40) or
               (uint64(SBox4[uint8(u.value[0] shr 32)]) shl 32) or
               (uint64(SBox1[uint8(u.value[0] shr 24)]) shl 24) or
               (uint64(SBox2[uint8(u.value[0] shr 16)]) shl 16) or
               (uint64(SBox3[uint8(u.value[0] shr 8)]) shl 8) or
               uint64(SBox4[uint8(u.value[0])])

# aria sub2 template for uint128
template sub2(u: var uint128): void =
  u.value[1] = (uint64(SBox3[uint8(u.value[1] shr 56)]) shl 56) or
               (uint64(SBox4[uint8(u.value[1] shr 48)]) shl 48) or
               (uint64(SBox1[uint8(u.value[1] shr 40)]) shl 40) or
               (uint64(SBox2[uint8(u.value[1] shr 32)]) shl 32) or
               (uint64(SBox3[uint8(u.value[1] shr 24)]) shl 24) or
               (uint64(SBox4[uint8(u.value[1] shr 16)]) shl 16) or
               (uint64(SBox1[uint8(u.value[1] shr 8)]) shl 8) or
               uint64(SBox2[uint8(u.value[1])])
  u.value[0] = (uint64(SBox3[uint8(u.value[0] shr 56)]) shl 56) or
               (uint64(SBox4[uint8(u.value[0] shr 48)]) shl 48) or
               (uint64(SBox1[uint8(u.value[0] shr 40)]) shl 40) or
               (uint64(SBox2[uint8(u.value[0] shr 32)]) shl 32) or
               (uint64(SBox3[uint8(u.value[0] shr 24)]) shl 24) or
               (uint64(SBox4[uint8(u.value[0] shr 16)]) shl 16) or
               (uint64(SBox1[uint8(u.value[0] shr 8)]) shl 8) or
               uint64(SBox2[uint8(u.value[0])])

# aria odd round template for uint128
template oddRoundV(roundKey: uint128, state: var uint128): void =
  state = state xor roundKey
  sub1(state)
  ariaA(state)

# aria even round template for uint128
template evenRoundV(roundKey: uint128, state: var uint128): void =
  state = state xor roundKey
  sub2(state)
  ariaA(state)

# aria odd round template for uint128 returning
template oddRound(roundKey: uint128, state: uint128): uint128 =
  var res = state xor roundKey
  sub1(res)
  ariaA(res)
  res

# aria even round template for uint128 returning
template evenRound(roundKey: uint128, state: uint128): uint128 =
  var res = state xor roundKey
  sub2(res)
  ariaA(res)
  res

# aria encrypt core
template ariaEncryptC(ctx: ARIACtx, input: ptr UncheckedArray[uint8]): void =
  var state: uint128
  # decode input to state by big endian
  state.value[1] = (uint64(input[0]) shl 56) or (uint64(input[1]) shl 48) or
                   (uint64(input[2]) shl 40) or (uint64(input[3]) shl 32) or
                   (uint64(input[4]) shl 24) or (uint64(input[5]) shl 16) or
                   (uint64(input[6]) shl 8) or uint64(input[7])
  state.value[0] = (uint64(input[8]) shl 56) or (uint64(input[9]) shl 48) or
                   (uint64(input[10]) shl 40) or (uint64(input[11]) shl 32) or
                   (uint64(input[12]) shl 24) or (uint64(input[13]) shl 16) or
                   (uint64(input[14]) shl 8) or uint64(input[15])

  # apply odd round
  oddRoundV(ctx.roundKeyE[0], state)

  # apply even round and odd round alternately
  for i in static(0 .. roundNumber(ctx.keyBits) div 2 - 2):
    evenRoundV(ctx.roundKeyE[i * 2 + 1], state)
    oddRoundV(ctx.roundKeyE[i * 2 + 2], state)

  # apply last even round
  let rounds: int = roundNumber(ctx.keyBits)
  state = state xor ctx.roundKeyE[rounds - 1]
  sub2(state)
  state = state xor ctx.roundKeyE[rounds]

  # encode state to input by big endian
  input[0] = uint8(state.value[1] shr 56)
  input[1] = uint8(state.value[1] shr 48)
  input[2] = uint8(state.value[1] shr 40)
  input[3] = uint8(state.value[1] shr 32)
  input[4] = uint8(state.value[1] shr 24)
  input[5] = uint8(state.value[1] shr 16)
  input[6] = uint8(state.value[1] shr 8)
  input[7] = uint8(state.value[1])
  input[8] = uint8(state.value[0] shr 56)
  input[9] = uint8(state.value[0] shr 48)
  input[10] = uint8(state.value[0] shr 40)
  input[11] = uint8(state.value[0] shr 32)
  input[12] = uint8(state.value[0] shr 24)
  input[13] = uint8(state.value[0] shr 16)
  input[14] = uint8(state.value[0] shr 8)
  input[15] = uint8(state.value[0])

# aria decrypt core
template ariaDecryptC(ctx: ARIACtx, input: ptr UncheckedArray[uint8]): void =
  var state: uint128
  # decode input to state by big endian
  state.value[1] = (uint64(input[0]) shl 56) or (uint64(input[1]) shl 48) or
                   (uint64(input[2]) shl 40) or (uint64(input[3]) shl 32) or
                   (uint64(input[4]) shl 24) or (uint64(input[5]) shl 16) or
                   (uint64(input[6]) shl 8) or uint64(input[7])
  state.value[0] = (uint64(input[8]) shl 56) or (uint64(input[9]) shl 48) or
                   (uint64(input[10]) shl 40) or (uint64(input[11]) shl 32) or
                   (uint64(input[12]) shl 24) or (uint64(input[13]) shl 16) or
                   (uint64(input[14]) shl 8) or uint64(input[15])

  # apply odd round
  oddRoundV(ctx.roundKeyD[0], state)

  # apply even round and odd round alternately
  for i in static(0 .. roundNumber(ctx.keyBits) div 2 - 2):
    evenRoundV(ctx.roundKeyD[i * 2 + 1], state)
    oddRoundV(ctx.roundKeyD[i * 2 + 2], state)

  # apply last even round
  let rounds: int = roundNumber(ctx.keyBits)
  state = state xor ctx.roundKeyD[rounds - 1]
  sub2(state)
  state = state xor ctx.roundKeyD[rounds]

  # encode state to input by big endian
  input[0] = uint8(state.value[1] shr 56)
  input[1] = uint8(state.value[1] shr 48)
  input[2] = uint8(state.value[1] shr 40)
  input[3] = uint8(state.value[1] shr 32)
  input[4] = uint8(state.value[1] shr 24)
  input[5] = uint8(state.value[1] shr 16)
  input[6] = uint8(state.value[1] shr 8)
  input[7] = uint8(state.value[1])
  input[8] = uint8(state.value[0] shr 56)
  input[9] = uint8(state.value[0] shr 48)
  input[10] = uint8(state.value[0] shr 40)
  input[11] = uint8(state.value[0] shr 32)
  input[12] = uint8(state.value[0] shr 24)
  input[13] = uint8(state.value[0] shr 16)
  input[14] = uint8(state.value[0] shr 8)
  input[15] = uint8(state.value[0])

# aria init core
template ariaInitC(ctx: var ARIACtx, input: ptr UncheckedArray[uint8]): void =
  # set constant
  var C1, C2, C3: uint128
  when Bits == 64:
    C1.value = [0xfe13abe8fa9a6ee0'u64, 0x517cc1b727220a94'u64]
    C2.value = [0xff28b1d5ef5de2b0'u64, 0x6db14acc9e21c820'u64]
    C3.value = [0x0324977504e8c90e'u64, 0xdb92371d2126e970'u64]
  elif Bits == 32:
    C1.value = [0xfa9a6ee0'u32, 0xfe13abe8'u32, 0x27220a94'u32, 0x517cc1b7'u32]
    C2.value = [0xef5de2b0'u32, 0xff28b1d5'u32, 0x9e21c820'u32, 0x6db14acc'u32]
    C3.value = [0x04e8c90e'u32, 0x03249775'u32, 0x2126e970'u32, 0xdb92371d'u32]

  var ck1, ck2, ck3: uint128
  var keyLeft, keyRight: uint128
  let rounds = ctx.roundKeyE.len - 1

  template toUint64(p: ptr UncheckedArray[uint8], offset: int): uint64 =
    (uint64(p[offset + 0]) shl 56) or (uint64(p[offset + 1]) shl 48) or
    (uint64(p[offset + 2]) shl 40) or (uint64(p[offset + 3]) shl 32) or
    (uint64(p[offset + 4]) shl 24) or (uint64(p[offset + 5]) shl 16) or
    (uint64(p[offset + 6]) shl 8) or uint64(p[offset + 7])

  # set key left and right
  when ctx.keyBits == 128:
    ck1 = C1; ck2 = C2; ck3 = C3
    keyLeft.value[1] = toUint64(input, 0)
    keyLeft.value[0] = toUint64(input, 8)
    keyRight.value = [0x00'u64, 0x00'u64]
  elif ctx.keyBits == 192:
    ck1 = C2; ck2 = C3; ck3 = C1
    keyLeft.value[1] = toUint64(input, 0)
    keyLeft.value[0] = toUint64(input, 8)
    keyRight.value[1] = toUint64(input, 16)
    keyRight.value[0] = 0x00'u64
  elif ctx.keyBits == 256:
    ck1 = C3; ck2 = C1; ck3 = C2
    keyLeft.value[1] = toUint64(input, 0)
    keyLeft.value[0] = toUint64(input, 8)
    keyRight.value[1] = toUint64(input, 16)
    keyRight.value[0] = toUint64(input, 24)

  # set round key
  let w0: uint128 = keyLeft
  let w1: uint128 = oddRound(ck1, w0) xor keyRight
  let w2: uint128 = evenRound(ck2, w1) xor w0
  let w3: uint128 = oddRound(ck3, w2) xor w1

  # extend key
  extendKey(ctx.roundKeyE, w0, w1, w2, w3)

  # set decrypt round key
  ctx.roundKeyD[0] = ctx.roundKeyE[rounds]
  for i in static(1 ..< (ctx.roundKeyE.len - 1)):
    ctx.roundKeyD[i] = ctx.roundKeyE[rounds - i]
    ariaA(ctx.roundKeyD[i])
  ctx.roundKeyD[rounds] = ctx.roundKeyE[0]

# export wrapper
when defined(templateOpt):
  template aria128Init*(ctx: var ARIA128Ctx, input: openArray[uint8]): void =
    ariaInitC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]))
  template aria128Init*(ctx: var ARIA128Ctx, input: array[16, uint8]): void =
    ariaInitC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  template aria128Init*(ctx: var ARIA128Ctx, input: ptr array[16, uint8]): void =
    ariaInitC(ctx, cast[ptr UncheckedArray[uint8]](input))
  template aria128Init*(ctx: var ARIA128Ctx, input: ptr UncheckedArray[uint8]): void =
    ariaInitC(ctx, input)

  template aria128Encrypt*(ctx: ARIA128Ctx, input: var openArray[uint8]): void =
    ariaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]))
  template aria128Encrypt*(ctx: ARIA128Ctx, input: var array[16, uint8]): void =
    ariaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  template aria128Encrypt*(ctx: ARIA128Ctx, input: ptr array[16, uint8]): void =
    ariaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](input))
  template aria128Encrypt*(ctx: ARIA128Ctx, input: ptr UncheckedArray[uint8]): void =
    ariaEncryptC(ctx, input)

  template aria128Decrypt*(ctx: ARIA128Ctx, input: var openArray[uint8]): void =
    ariaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]))
  template aria128Decrypt*(ctx: ARIA128Ctx, input: var array[16, uint8]): void =
    ariaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  template aria128Decrypt*(ctx: ARIA128Ctx, input: ptr array[16, uint8]): void =
    ariaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](input))
  template aria128Decrypt*(ctx: ARIA128Ctx, input: ptr UncheckedArray[uint8]): void =
    ariaDecryptC(ctx, input)

  template aria192Init*(ctx: var ARIA192Ctx, input: openArray[uint8]): void =
    ariaInitC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]))
  template aria192Init*(ctx: var ARIA192Ctx, input: array[16, uint8]): void =
    ariaInitC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  template aria192Init*(ctx: var ARIA192Ctx, input: ptr array[16, uint8]): void =
    ariaInitC(ctx, cast[ptr UncheckedArray[uint8]](input))
  template aria192Init*(ctx: var ARIA192Ctx, input: ptr UncheckedArray[uint8]): void =
    ariaInitC(ctx, input)

  template aria192Encrypt*(ctx: ARIA192Ctx, input: var openArray[uint8]): void =
    ariaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]))
  template aria192Encrypt*(ctx: ARIA192Ctx, input: var array[16, uint8]): void =
    ariaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  template aria192Encrypt*(ctx: ARIA192Ctx, input: ptr array[16, uint8]): void =
    ariaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](input))
  template aria192Encrypt*(ctx: ARIA192Ctx, input: ptr UncheckedArray[uint8]): void =
    ariaEncryptC(ctx, input)

  template aria192Decrypt*(ctx: ARIA192Ctx, input: var openArray[uint8]): void =
    ariaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]))
  template aria192Decrypt*(ctx: ARIA192Ctx, input: var array[16, uint8]): void =
    ariaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  template aria192Decrypt*(ctx: ARIA192Ctx, input: ptr array[16, uint8]): void =
    ariaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](input))
  template aria192Decrypt*(ctx: ARIA192Ctx, input: ptr UncheckedArray[uint8]): void =
    ariaDecryptC(ctx, input)

  template aria256Init*(ctx: var ARIA256Ctx, input: openArray[uint8]): void =
    ariaInitC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]))
  template aria256Init*(ctx: var ARIA256Ctx, input: array[16, uint8]): void =
    ariaInitC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  template aria256Init*(ctx: var ARIA256Ctx, input: ptr array[16, uint8]): void =
    ariaInitC(ctx, cast[ptr UncheckedArray[uint8]](input))
  template aria256Init*(ctx: var ARIA256Ctx, input: ptr UncheckedArray[uint8]): void =
    ariaInitC(ctx, input)

  template aria256Encrypt*(ctx: ARIA256Ctx, input: var openArray[uint8]): void =
    ariaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]))
  template aria256Encrypt*(ctx: ARIA256Ctx, input: var array[16, uint8]): void =
    ariaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  template aria256Encrypt*(ctx: ARIA256Ctx, input: ptr array[16, uint8]): void =
    ariaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](input))
  template aria256Encrypt*(ctx: ARIA256Ctx, input: ptr UncheckedArray[uint8]): void =
    ariaEncryptC(ctx, input)

  template aria256Decrypt*(ctx: ARIA256Ctx, input: var openArray[uint8]): void =
    ariaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]))
  template aria256Decrypt*(ctx: ARIA256Ctx, input: var array[16, uint8]): void =
    ariaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  template aria256Decrypt*(ctx: ARIA256Ctx, input: ptr array[16, uint8]): void =
    ariaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](input))
  template aria256Decrypt*(ctx: ARIA256Ctx, input: ptr UncheckedArray[uint8]): void =
    ariaDecryptC(ctx, input)
else:
  proc aria128Init*(ctx: var ARIA128Ctx, input: openArray[uint8]): void =
    ariaInitC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]))
  proc aria128Init*(ctx: var ARIA128Ctx, input: array[16, uint8]): void =
    ariaInitC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  proc aria128Init*(ctx: var ARIA128Ctx, input: ptr array[16, uint8]): void {.exportc: "aria128Init", cdecl.} =
    ariaInitC(ctx, cast[ptr UncheckedArray[uint8]](input))
  proc aria128Init*(ctx: var ARIA128Ctx, input: ptr UncheckedArray[uint8]): void {.exportc: "aria128Init_unchecked", cdecl.} =
    ariaInitC(ctx, input)

  proc aria128Encrypt*(ctx: ARIA128Ctx, input: var openArray[uint8]): void =
    ariaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]))
  proc aria128Encrypt*(ctx: ARIA128Ctx, input: var array[16, uint8]): void =
    ariaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  proc aria128Encrypt*(ctx: ARIA128Ctx, input: ptr array[16, uint8]): void {.exportc: "aria128Encrypt", cdecl.} =
    ariaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](input))
  proc aria128Encrypt*(ctx: ARIA128Ctx, input: ptr UncheckedArray[uint8]): void {.exportc: "aria128Encrypt_unchecked", cdecl.} =
    ariaEncryptC(ctx, input)

  proc aria128Decrypt*(ctx: ARIA128Ctx, input: var openArray[uint8]): void =
    ariaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]))
  proc aria128Decrypt*(ctx: ARIA128Ctx, input: var array[16, uint8]): void =
    ariaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  proc aria128Decrypt*(ctx: ARIA128Ctx, input: ptr array[16, uint8]): void {.exportc: "aria128Decrypt", cdecl.} =
    ariaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](input))
  proc aria128Decrypt*(ctx: ARIA128Ctx, input: ptr UncheckedArray[uint8]): void {.exportc: "aria128Decrypt_unchecked", cdecl.} =
    ariaDecryptC(ctx, input)

  proc aria192Init*(ctx: var ARIA192Ctx, input: openArray[uint8]): void =
    ariaInitC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]))
  proc aria192Init*(ctx: var ARIA192Ctx, input: array[16, uint8]): void =
    ariaInitC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  proc aria192Init*(ctx: var ARIA192Ctx, input: ptr array[16, uint8]): void {.exportc: "aria192Init", cdecl.} =
    ariaInitC(ctx, cast[ptr UncheckedArray[uint8]](input))
  proc aria192Init*(ctx: var ARIA192Ctx, input: ptr UncheckedArray[uint8]): void {.exportc: "aria192Init_unchecked", cdecl.} =
    ariaInitC(ctx, input)

  proc aria192Encrypt*(ctx: ARIA192Ctx, input: var openArray[uint8]): void =
    ariaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]))
  proc aria192Encrypt*(ctx: ARIA192Ctx, input: var array[16, uint8]): void =
    ariaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  proc aria192Encrypt*(ctx: ARIA192Ctx, input: ptr array[16, uint8]): void {.exportc: "aria192Encrypt", cdecl.} =
    ariaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](input))
  proc aria192Encrypt*(ctx: ARIA192Ctx, input: ptr UncheckedArray[uint8]): void {.exportc: "aria192Encrypt_unchecked", cdecl.} =
    ariaEncryptC(ctx, input)

  proc aria192Decrypt*(ctx: ARIA192Ctx, input: var openArray[uint8]): void =
    ariaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]))
  proc aria192Decrypt*(ctx: ARIA192Ctx, input: var array[16, uint8]): void =
    ariaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  proc aria192Decrypt*(ctx: ARIA192Ctx, input: ptr array[16, uint8]): void {.exportc: "aria192Decrypt", cdecl.} =
    ariaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](input))
  proc aria192Decrypt*(ctx: ARIA192Ctx, input: ptr UncheckedArray[uint8]): void {.exportc: "aria192Decrypt_unchecked", cdecl.} =
    ariaDecryptC(ctx, input)

  proc aria256Init*(ctx: var ARIA256Ctx, input: openArray[uint8]): void =
    ariaInitC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]))
  proc aria256Init*(ctx: var ARIA256Ctx, input: array[16, uint8]): void =
    ariaInitC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  proc aria256Init*(ctx: var ARIA256Ctx, input: ptr array[16, uint8]): void {.exportc: "aria256Init", cdecl.} =
    ariaInitC(ctx, cast[ptr UncheckedArray[uint8]](input))
  proc aria256Init*(ctx: var ARIA256Ctx, input: ptr UncheckedArray[uint8]): void {.exportc: "aria256Init_unchecked", cdecl.} =
    ariaInitC(ctx, input)

  proc aria256Encrypt*(ctx: ARIA256Ctx, input: var openArray[uint8]): void =
    ariaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]))
  proc aria256Encrypt*(ctx: ARIA256Ctx, input: var array[16, uint8]): void =
    ariaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  proc aria256Encrypt*(ctx: ARIA256Ctx, input: ptr array[16, uint8]): void {.exportc: "aria256Encrypt", cdecl.} =
    ariaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](input))
  proc aria256Encrypt*(ctx: ARIA256Ctx, input: ptr UncheckedArray[uint8]): void {.exportc: "aria256Encrypt_unchecked", cdecl.} =
    ariaEncryptC(ctx, input)

  proc aria256Decrypt*(ctx: ARIA256Ctx, input: var openArray[uint8]): void =
    ariaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]))
  proc aria256Decrypt*(ctx: ARIA256Ctx, input: var array[16, uint8]): void =
    ariaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](addr input[0]))
  proc aria256Decrypt*(ctx: ARIA256Ctx, input: ptr array[16, uint8]): void {.exportc: "aria256Decrypt", cdecl.} =
    ariaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](input))
  proc aria256Decrypt*(ctx: ARIA256Ctx, input: ptr UncheckedArray[uint8]): void {.exportc: "aria256Decrypt_unchecked", cdecl.} =
    ariaDecryptC(ctx, input)

# test code
when defined(test):
  var ctx128: ARIA128Ctx
  var key128: array[16, uint8] = [
    0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8, 0x08'u8, 0x09'u8, 0x0a'u8, 0x0b'u8, 0x0c'u8, 0x0d'u8, 0x0e'u8, 0x0f'u8
  ]
  var text128: array[16, uint8] = [
    0x00'u8, 0x11'u8, 0x22'u8, 0x33'u8, 0x44'u8, 0x55'u8, 0x66'u8, 0x77'u8, 0x88'u8, 0x99'u8, 0xaa'u8, 0xbb'u8, 0xcc'u8, 0xdd'u8, 0xee'u8, 0xff'u8
  ]

  aria128Init(ctx128, key128)
  echo "--- Test : ARIA-128 ---"
  echo "ARIA-128 Key : 000102030405060708090A0B0C0D0E0F"
  aria128Encrypt(ctx128, text128)
  echo "ARIA-128 Encrypt Cipher Text : ", binToHex(text128)
  echo "ARIA-128 Standard Cipher Text : D718FBD6AB644C739DA95F3BE6451778"
  aria128Decrypt(ctx128, text128)
  echo "ARIA-128 Decrypt Plain Text : ", binToHex(text128)
  echo "Standard Plain Text : 00112233445566778899AABBCCDDEEFF"

  var ctx192: ARIA192Ctx
  var key192: array[24, uint8] = [
    0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8, 0x08'u8, 0x09'u8, 0x0A'u8, 0x0B'u8, 0x0C'u8, 0x0D'u8, 0x0E'u8, 0x0F'u8, 0x10'u8, 0x11'u8, 0x12'u8, 0x13'u8, 0x14'u8, 0x15'u8, 0x16'u8, 0x17'u8
  ]
  var text192: array[16, uint8] = [
    0x00'u8, 0x11'u8, 0x22'u8, 0x33'u8, 0x44'u8, 0x55'u8, 0x66'u8, 0x77'u8, 0x88'u8, 0x99'u8, 0xaa'u8, 0xbb'u8, 0xcc'u8, 0xdd'u8, 0xee'u8, 0xff'u8
  ]

  aria192Init(ctx192, key192)
  echo "--- Test : ARIA-192 ---"
  echo "ARIA-192 Key : 000102030405060708090A0B0C0D0E0F1011121314151617"
  aria192Encrypt(ctx192, text192)
  echo "ARIA-192 Encrypt Cipher Text : ", binToHex(text192)
  echo "ARIA-192 Standard Cipher Text : 26449C1805DBE7AA25A468CE263A9E79"
  aria192Decrypt(ctx192, text192)
  echo "ARIA-192 Decrypt Plain Text : ", binToHex(text192)
  echo "Standard Plain Text : 00112233445566778899AABBCCDDEEFF"

  var ctx256: ARIA256Ctx
  var key256: array[32, uint8] = [
    0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8, 0x08'u8, 0x09'u8, 0x0A'u8, 0x0B'u8, 0x0C'u8, 0x0D'u8, 0x0E'u8, 0x0F'u8, 0x10'u8, 0x11'u8, 0x12'u8, 0x13'u8, 0x14'u8, 0x15'u8, 0x16'u8, 0x17'u8, 0x18'u8, 0x19'u8, 0x1A'u8, 0x1B'u8, 0x1C'u8, 0x1D'u8, 0x1E'u8, 0x1F'u8
  ]
  var text256: array[16, uint8] = [
    0x00'u8, 0x11'u8, 0x22'u8, 0x33'u8, 0x44'u8, 0x55'u8, 0x66'u8, 0x77'u8, 0x88'u8, 0x99'u8, 0xaa'u8, 0xbb'u8, 0xcc'u8, 0xdd'u8, 0xee'u8, 0xff'u8
  ]

  aria256Init(ctx256, key256)
  echo "--- Test : ARIA-256 ---"
  echo "ARIA-256 Key : "
  aria256Encrypt(ctx256, text256)
  echo "ARIA-256 Encrypt Cipher Text : ", binToHex(text256)
  echo "ARIA-256 Standard Cipher Text : F92BD7C79FB72E2F2B8F80C1972D24FC"
  aria256Decrypt(ctx256, text256)
  echo "ARIA-256 Decrypt Plain Text : ", binToHex(text256)
  echo "Standard Plain Text : 00112233445566778899AABBCCDDEEFF"

  template benchmark(name: string, code: untyped) =
    let start = getMonoTime()
    code
    let elapsed = getMonoTime() - start
    echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

  benchmark("ARIA-128 Init"):
    for i in 1 .. 1_000_000:
      aria128Init(ctx128, key128)

  benchmark("ARIA-128 Encrypt"):
    for i in 1 .. 1_000_000:
      aria128Encrypt(ctx128, text128)

  benchmark("ARIA-128 Decrypt"):
    for i in 1 .. 1_000_000:
      aria128Decrypt(ctx128, text128)

  benchmark("ARIA-192 Init"):
    for i in 1 .. 1_000_000:
      aria192Init(ctx192, key192)

  benchmark("ARIA-192 Encrypt"):
    for i in 1 .. 1_000_000:
      aria192Encrypt(ctx192, text192)

  benchmark("ARIA-192 Decrypt"):
    for i in 1 .. 1_000_000:
      aria192Decrypt(ctx192, text192)

  benchmark("ARIA-256 Init"):
    for i in 1 .. 1_000_000:
      aria256Init(ctx256, key256)

  benchmark("ARIA-256 Encrypt"):
    for i in 1 .. 1_000_000:
      aria256Encrypt(ctx256, text256)

  benchmark("ARIA-256 Decrypt"):
    for i in 1 .. 1_000_000:
      aria256Decrypt(ctx256, text256)
