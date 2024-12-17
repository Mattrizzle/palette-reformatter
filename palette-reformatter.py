import sys
import os
import argparse
import functools
import re
import zlib
from datetime import datetime

format_shortnames = [
	"32x",
	"act",
	"amp",
	"bmp24",
	"col",
	"gen",
	"gpl",
	"gs0",
	"jasc",
	"png8",
	"rgb15",
	"riff",
	"snes",
	"tpl15",
	"tpl24",
	"zst"
]

format_names = [
	"Raw 15-bit BGR, Big Endian (32X)",
	"Adobe Color Table (Raw 24-bit RGB)",
	"Adobe Arbitrary Map File (AMP)",
	"16x16 24Bpp Bitmap (BMP)",
	"S-CG-CAD COL File (15-bit BGR)",
	"Raw 9-bit BGR, Big Endian (Mega Drive/Genesis)",
	"GIMP Palette (GPL) (24-bit RGB)",
	"Genecyst/Kega/Gens Savestate (GS*)",
	"JASC Palette (24-bit RGB)",
	"16x16 256-color PNG",
	"Raw 15-bit RGB, Little Endian (Midway IMG files)",
	"RIFF Palette (24-bit RGB)",
	"Raw 15-bit BGR, Little Endian (SNES, PSX, GBC, GBA)",
	"Tile Layer Pro 15-bit BGR (TPL)",
	"Tile Layer Pro 24-bit RGB (TPL)",
	"ZSNES Savestate (ZS*)"
]

format_outfile_folders = [
	"raw-32X",
	"act",
	"amp",
	"bmp",
	"COL",
	"raw-gen-MD",
	"gpl",
	"",
	"jasc-pal",
	"indexed-png",
	"raw-RGB15",
	"riff-pal",
	"raw-SNES",
	"tpl-BGR15",
	"tpl-RGB24",
	""
]

format_outfile_ends = [
	"-32X.bin",
	".act",
	".amp",
	"-RGB24.bmp",
	".COL",
	"-GEN.bin",
	".gpl",
	"",
	"-JASC.pal",
	"-RGB8.png",
	"-RGB15.bin",
	"-RIFF.pal",
	"-SNES.pal",
	"-BGR15.tpl",
	"-RGB24.tpl",
	""
]

format_index_lengths = [
	2,
	3,
	1,
	3,
	2,
	2,
	1,	# This is in lines rather than bytes, as GIMP palettes are text-based
	2,
	1,	# This is in lines rather than bytes, as JASC palettes are text-based
	3,
	2,
	4,
	2,
	2,
	3,
	2
]

format_endianness = [
	"big",
	"big",
	"big",
	"big",
	"little",
	"big",
	"big",
	"little",
	"big",
	"big",
	"little",
	"big",
	"little",
	"little",
	"big",
	"little"
]

def read_byte(data, address):
	try:
		data_range = data[address:address+1]
	except IndexError:
		print('ERROR: Byte read out of range for data.')
		exit()

	try:
		byte = int.from_bytes(data_range, byteorder='big')
		return byte
	except TypeError:
		print('ERROR: Input file is empty or cannot be read.')
		exit()

def read_word(data, address, endianness):
	try:
		data_range = data[address:address+2]
	except IndexError:
		print('ERROR: Word read out of range for file.')
		exit()

	try:
		word = int.from_bytes(data_range, byteorder=endianness)
		return word
	except TypeError:
		print('ERROR: Input file is empty or cannot be read.')
		exit()

def read_lword(data, address, endianness):
	try:
		data_range = data[address:address+3]
	except IndexError:
		print('ERROR: Long word read out of range for data.')
		exit()

	try:
		lword = int.from_bytes(data_range, byteorder=endianness)
		return lword
	except TypeError:
		print('ERROR: Input file is empty or cannot be read.')
		exit()

def read_dword(data, address, endianness):
	try:
		data_range = data[address:address+4]
	except IndexError:
		print('ERROR: Double word read out of range for data.')
		exit()

	try:
		dword = int.from_bytes(data_range, byteorder=endianness)
		return dword
	except TypeError:
		print('ERROR: Input file is empty or cannot be read.')
		exit()

def load_file(path):
	try:
		file = open(path, 'rb')
		while True:
			data = file.read(-1)  
			if not data:
				break
			return bytes(data)
	except IOError:
		print('ERROR: Failed to open file.')
		exit()

def save_file(path, address, data):
	try:
		file = open(path, 'wb')
		if True:
			file.seek(address)
			file.write(data)
			return
	except IOError:
		print('ERROR: Failed to open file.')
		exit()
		
def get_data_chunk(data, address_a, address_b):
	chunk = data[address_a:address_b]
	return chunk

def is_raw_type(type):
	if type in {"snes", "rgb15", "gen", "32x"}:
		return True
	else:
		return False

def is_text_type(type):
	if type in {"jasc", "gpl"}:
		return True
	else:
		return False

def generate_header(type, length, index_length):
	if type == "riff": # RIFF
		riff_header = "RIFF".encode('ascii')+0xDEADBEEF.to_bytes(4, "little")
		riff_header_len = len(riff_header)
		pal_data_header = "PAL data".encode('ascii')+0xDEADBEEF.to_bytes(4, "little")+0x300.to_bytes(2, "little")+(16 if length <= 16 else 256).to_bytes(2, "little")
		pal_data_header_len = len(pal_data_header)
		headers_len = riff_header_len+pal_data_header_len
		file_len = headers_len+(length*index_length)+index_length
		riff_header = riff_header.replace(0xDEADBEEF.to_bytes(4, "little"), (file_len-riff_header_len).to_bytes(4, "little"))
		pal_data_header = pal_data_header.replace(0xDEADBEEF.to_bytes(4, "little"), ((length*index_length)+8).to_bytes(4, "little"))

		file_header = riff_header+pal_data_header
	elif type == "jasc": # JASC
		file_header = ("JASC-PAL" + os.linesep + "0100" + os.linesep + str(16 if length <= 16 else 256) + os.linesep).encode('ascii')
	elif type in {"tpl24", "tpl15"}: # TPL
		file_header = "TPL".encode('ascii')+(2 if type == "tpl15" else 0).to_bytes(1, "big")
	elif type == "png8": # PNG
		file_header = 0x89.to_bytes(1, "big")+"PNG\r\n".encode('ascii')+0x1A.to_bytes(1, "big")+"\n".encode('ascii')
		ihdr = 0x10.to_bytes(4, "big")+0x10.to_bytes(4, "big")+0x8.to_bytes(1, "big")+0x3.to_bytes(1, "big")+0x0.to_bytes(3, "big")

		file_header += len(ihdr).to_bytes(4, "big")+"IHDR".encode('ascii')+ihdr+0x282D0F53.to_bytes(4, "big")+(length*index_length).to_bytes(4, "big")+"PLTE".encode('ascii')
	elif type == "bmp24": # BMP
		bmp_file_header = "BM".encode('ascii')+0xDEADBEEF.to_bytes(4, "little")+0x0.to_bytes(4, "little")+0xDEADC0DE.to_bytes(4, "little")
		bmp_file_header_len = len(bmp_file_header)
		bmp_info_header = 0x1337C0DE.to_bytes(4, "little")+0x10.to_bytes(4, "little")+0x10.to_bytes(4, "little")+0x1.to_bytes(2, "little")+0x18.to_bytes(2, "little")+0x0.to_bytes(4, "little")+(length*index_length).to_bytes(2, "little")+0x0.to_bytes(18, "little")
		bmp_info_header_len = len(bmp_info_header)
		headers_len = bmp_file_header_len+bmp_info_header_len
		file_len = bmp_file_header_len+bmp_info_header_len+(length*index_length)
		bmp_file_header = bmp_file_header.replace(0xDEADBEEF.to_bytes(4, "little"), file_len.to_bytes(4, "little"))
		bmp_file_header = bmp_file_header.replace(0xDEADC0DE.to_bytes(4, "little"), headers_len.to_bytes(4, "little"))
		bmp_info_header = bmp_info_header.replace(0x1337C0DE.to_bytes(4, "little"), bmp_info_header_len.to_bytes(4, "little"))

		file_header = bmp_file_header+bmp_info_header
	elif type == "gpl": # GPL
		file_header = ("GIMP Palette" + os.linesep + "Name: " + label + os.linesep + "Columns: 16" + os.linesep + "#Converted using Palette Reformatter <a href=\"https://github.com/Mattrizzle/palette-reformatter\">https://github.com/Mattrizzle/palette-reformatter</a>" + os.linesep).encode('ascii')
	else:
		file_header = "".encode('ascii')

	return file_header

def get_default_input_offset(data, type, line_num=None):
	if type == "riff":
		input_offset = 0x18
	elif is_text_type(type):
		input_offset = line_num	# This is a line number instead of an offset, as JASC palettes are text-based
	elif type in {"tpl24", "tpl15"}:
		input_offset = 0x4
	elif type == "zst":
		input_offset = 0x618
	elif type == "bmp24":
		input_offset = read_dword(data, 0xA, 'little')+(0x10*0xF*format_index_lengths[format_shortnames.index(type)])
	elif type == "gs0":
		input_offset = 0x112
	else:
		input_offset = 0x0

	return input_offset

def get_default_input_length(data, type, input_offset=None, line_count=None):
	if type == "riff":
		input_length = (read_dword(data, 0x4, "little")-8)//format_index_lengths[format_shortnames.index(type)],
	elif type == "jasc":
		input_length = int(data.decode('ascii', 'ignore').splitlines()[2]) if data.decode('ascii', 'ignore').splitlines()[2].isdigit() else 256
	elif type == "act":
		input_length = read_word(data, 0x400, 2, 'big') if len(data) == 0x404 else 256
	elif is_raw_type(type):
		input_length = 256 if len(data)//format_index_lengths[format_shortnames.index(type)] > 256 else len(data)//format_index_lengths[format_shortnames.index(type)]
	elif type == "gpl":
		input_length = line_count-input_offset
	elif type == "gs0":
		input_length = 64
	else:
		input_length = 256

	return input_length

def get_output_length(type, input_length):
	if type in {"riff", "gpl"} or is_raw_type(type):
		output_length = input_length
	elif type == "jasc":
		output_length = 16 if input_length <= 16 else 256
	else:
		output_length = 256

	return output_length

def decode_color(data, address, type, endianness, line_num=None):
	if type in {"riff", "act", "tpl24", "png8"}:	# 24-bit RGB
		r = read_byte(data, address)
		g = read_byte(data, address+1)
		b = read_byte(data, address+2)
	elif is_text_type(type):				# JASC / GIMP
		colors = re.split(r'\s', data[line_num])
		try:
			r = int(colors[0])
			if r > 255 or r < 0:
				raise ValueError()
		except ValueError:
			r = 255
			print("ERROR on line " + str(line_num+1) + " of input file:\n\tInvalid red value. Replaced with " + str(r) + ".")
		except IndexError:
			r = 0
			print("ERROR on line " + str(line_num+1) + " of input file:\n\tMissing red value. Replaced with " + str(r) + ".")

		try:
			g = int(colors[1])
			if g > 255 or g < 0:
				raise ValueError()
		except ValueError:
			g = 255
			print("ERROR on line " + str(line_num+1) + " of input file:\n\tInvalid green value. Replaced with " + str(g) + ".")
		except IndexError:
			g = 0
			print("ERROR on line " + str(line_num+1) + " of input file:\n\tMissing green value. Replaced with " + str(g) + ".")

		try:
			b = int(colors[2])
			if b > 255 or b < 0:
				raise ValueError()
		except ValueError:
			b = 255
			print("ERROR on line " + str(line_num+1) + " of input file:\n\tInvalid blue value. Replaced with " + str(b) + ".")
		except IndexError:
			b = 0
			print("ERROR on line " + str(line_num+1) + " of input file:\n\tMissing blue value. Replaced with " + str(b) + ".")

	elif type == "rgb15":					# 15-bit RGB
		r = (read_word(data, address, endianness)&0x7C00)>>7
		g = (read_word(data, address, endianness)&0x03E0)>>2
		b = (read_word(data, address, endianness)&0x001F)<<3
	elif type in {"gen", "gs0"}:				# 9-bit BGR
		r = (read_word(data, address, endianness)&0x000E)<<4
		g = (read_word(data, address, endianness)&0x00E0)
		b = (read_word(data, address, endianness)&0x0E00)>>4
	elif type == "bmp24":					# 24-bit BGR
		r = read_byte(data, address+2)
		g = read_byte(data, address+1)
		b = read_byte(data, address)
	elif type == "amp":					# Adobe Curves File (AMP)
		r = read_byte(data, address)
		g = read_byte(data, address+0x100)
		b = read_byte(data, address+0x200)
	else:							# 15-bit BGR
		r = (read_word(data, address, endianness)&0x001F)<<3
		g = (read_word(data, address, endianness)&0x03E0)>>2
		b = (read_word(data, address, endianness)&0x7C00)>>7

	return r, g, b

def encode_color(data, type, r, g, b, endianness, index):
	if type == "riff": 					# 32-bit RGBX
		color = red<<24|green<<16|blue<<8
		color_bytes = color.to_bytes(4, endianness)
	elif type == "jasc":					# JASC
		line = str(format(red, '03d')) + ' ' + str(format(green, '03d')) + ' ' + str(format(blue, '03d')) + os.linesep
		color_bytes = line.encode('ascii')
	elif type in {"act", "tpl24", "png8"}:			# 24-bit RGB
		color = red<<16|green<<8|blue
		color_bytes = color.to_bytes(3, endianness)
	elif type == "rgb15":					# 15-bit RGB
		color = ((red<<7)&0x7C00)|((green<<2)&0x03E0)|((blue>>3)&0x001F)
		color_bytes = color.to_bytes(2, endianness)
	elif type == "gen":					# 9-bit BGR
		color = ((red>>4)&0x000E)|(green&0x00E0)|((blue<<4)&0x0E00)
		color_bytes = color.to_bytes(2, endianness)
	elif type == "bmp24":					# 24-bit BGR
		color = red|green<<8|blue<<16
		color_bytes = color.to_bytes(3, endianness)
	elif type == "gpl":					# GIMP
		line = str(red) + '\t' + str(green) + '\t' + str(blue) + '\tIndex ' + str(index) + os.linesep
		color_bytes = line.encode('ascii')
	else:							# 15-bit BGR
		color = ((red>>3)&0x001F)|((green<<2)&0x03E0)|((blue<<7)&0x7C00)
		color_bytes = color.to_bytes(2, endianness)

	return color_bytes

def generate_footer(data, type, palstart, length, index_length):
	if type == "riff":	# RIFF
		file_footer = 0x0.to_bytes(4, "little")
	elif type == "act" and args.inlength < 256:	# ACT
		file_footer = args.inlength.to_bytes(2, "big")+0xFFFF.to_bytes(2, "big")	# This is so Photoshop only shows the actual used colors in its Color Table window
	elif type == "col":	# COL
		now = datetime.now()
		date = now.strftime("%y%m%d")
		file_footer = ("NAK1989 S-CG-CADVer1.XX " + date + "  ").encode('ascii')+0x0.to_bytes(0x1E0, "big")
	elif type == "png8":	# PNG
		stored_seek_offset = data.tell()
		data.seek(palstart)
		read_palette = data.read(length*index_length)
		plte_crc32 = zlib.crc32("PLTE".encode('ascii'))
		plte_crc32 = zlib.crc32(read_palette, plte_crc32)
		data.seek(stored_seek_offset)
		idat = "IDAT".encode('ascii')+0x18576361.to_bytes(4, "big")+0x6044052C.to_bytes(4, "big")+0x02235A00.to_bytes(4, "big")+0x0022D702.to_bytes(4, "big")+0x21.to_bytes(1, "big")
		idat_crc32 = zlib.crc32(idat)
		iend = "IEND".encode('ascii')
		iend_crc32 = zlib.crc32(iend)
		file_footer = plte_crc32.to_bytes(4, "big")+(len(idat)-4).to_bytes(4, "big")+idat+idat_crc32.to_bytes(4, "big")+0x0.to_bytes(4, "big")+iend+iend_crc32.to_bytes(4, "big")
	else:
		file_footer = "".encode('ascii')
	return file_footer

parser = argparse.ArgumentParser(prog="palette-reformatter", formatter_class=argparse.RawDescriptionHelpFormatter, description="Palette Reformatter\nBy Mattrizzle - https://github.com/Mattrizzle/palette-reformatter\nThis script converts a single palette file from a specified input type to one \nor more specified output types.", epilog="Multiple-File Palette Reformatter\nBy Mattrizzle - https://github.com/Mattrizzle/palette-reformatter\nThis script searches a directory for files of the specified input type and \nconverts them to one or more specified output types.", epilog="NOTE: The following input/output file types are available:\n  32x:   Raw 15-bit BGR, Big Endian (32X)\n  act:   Adobe Color Table (Raw 24-bit RGB)\n  amp:   Adobe Arbitrary Map File (AMP)\n  bmp24: 16x16 24Bpp Bitmap (BMP)\n  col:   S-CG-CAD COL File (15-bit BGR)\n  gen:   Raw 9-bit BGR, Big Endian (Mega Drive/Genesis)\n  gpl:   GIMP Palette (GPL) (24-bit RGB)\n  gs0:   Genecyst/Kega/Gens Savestate (GS*) **INPUT ONLY**\n  jasc:  JASC Palette (24-bit RGB)\n  png8:  16x16 256-color PNG **OUTPUT ONLY**\n  rgb15: Raw 15-bit RGB, Little Endian (Midway IMG files)\n  riff:  RIFF Palette (24-bit RGB)\n  snes:  Raw 15-bit BGR, Little Endian (SNES, PSX, GBC, GBA)\n  tpl15: Tile Layer Pro 15-bit BGR (TPL)\n  tpl24: Tile Layer Pro 24-bit RGB (TPL)\n  zst:   ZSNES Savestate (ZS*) **INPUT ONLY**")
parser.add_argument("-n", "--noprint", action="store_true", help="If present, information will not be displayed in the terminal.")
parser.add_argument("infile", metavar="<input file>", help="Source file path.")
parser.add_argument("intype", metavar="<input type>", choices=["32x", "act", "amp", "bmp24", "col", "gen", "gs0", "gpl", "jasc", "rgb15", "riff", "snes", "tpl15", "tpl24", "zst"], help="Input file type. (See NOTE below)")
parser.add_argument("-a", "--inoffset", metavar="<input offset>", type=functools.wraps(int)(functools.partial(int, base=0)), help="Offset of palette to convert in source file. Input offset must not exceed the end of the source file. For GIMP and JASC palettes (intypes gpl and jasc), a line number should be specified instead of an offset.")
parser.add_argument("-l", "--inlength", metavar="<input length>", type=functools.wraps(int)(functools.partial(int, base=0)), choices=range(1, 257), help="Number of palette indices to convert in source file (minimum: 1; maximum 256; default: 256). Input length must not exceed the end of the source file.")
parser.add_argument("outtype", metavar="<output types>", nargs="+", choices=["32x", "act", "amp", "bmp24", "col", "gen", "gpl", "jasc", "png8", "rgb15", "riff", "snes", "tpl15", "tpl24"], help="Output file type(s). Can specify multiple types to write more than one file. (See NOTE below)")

args = parser.parse_args()

src_data = load_file(args.infile)
src_file_size = os.path.getsize(args.infile)

intype_id = format_shortnames.index(args.intype)

# outtypes_unique = [i for n, i in enumerate(args.outtype) if i not in args.outtype[:n]]
outtypes_unique = set(args.outtype)
outtypes_unique_list = list(outtypes_unique)
outtypes_unique_list.sort()

if args.inoffset != None and (is_text_type(args.intype)):
	args.inoffset -= 1

if args.noprint == False:
	print("\nInput file...")
	print("\tPath: " + args.infile)
	print("\tType: " + str(format_names[intype_id]))

if args.intype == "riff":	# RIFF
	riff_sig_read = get_data_chunk(src_data, 0x0, 0x4).decode('ascii', 'ignore')
	riff_size_read = read_dword(src_data, 0x4, "little")
	riff_paldata_sig_read = get_data_chunk(src_data, 0x8, 0x10).decode('ascii', 'ignore')
	riff_paldata_size_read = read_dword(src_data, 0x4, "little")+8

	if riff_sig_read != "RIFF":
		print("ERROR: Incorrect RIFF file signature.")
		exit()
	if riff_size_read+8 != src_file_size:
		print("ERROR: Invalid file size in RIFF header.")
		exit()
	if riff_paldata_sig_read != "PAL data":
		print("ERROR: PAL data header not present.")
		exit()
	if riff_paldata_size_read+16 != src_file_size:
		print("ERROR: Invalid palette size in PAL data header.")
		exit()

elif args.intype == "jasc":	# JASC
	try:
		src_data_text = src_data.decode('ascii', 'ignore')
	except AttributeError:
		print("ERROR: Input file is empty or cannot be read.")
		exit()

	src_data_text_split = src_data_text.splitlines()

	if src_data_text_split[0] != "JASC-PAL" or src_data_text_split[1] != "0100":
		print("ERROR: Incorrect JASC file signature.")
		exit()

	if src_data_text_split[2] not in {"256", "16"}:
		print("ERROR: Invalid JASC palette length.")
		exit()

	src_data_start_line = 3
	src_data_pal_length = len(src_data_text_split)-src_data_start_line

elif args.intype == "act":	# ACT
	if src_file_size not in {768, 772}:
		print("ERROR: Invalid Adobe Color Table file size. Should be 768 or 772 bytes long.")
		exit()

elif args.intype in {"tpl24", "tpl15"}:	# TPL
	tpl_sig_read =  get_data_chunk(src_data, 0x0, 0x3).decode('ascii', 'ignore')
	tpl_type = read_byte(src_data, 0x3)
	expected_tpl_type = (intype_id-6)*2

	if tpl_sig_read != "TPL":
		print("ERROR: Incorrect or missing TPL file signature.")
		exit()
	if tpl_type != expected_tpl_type:
		print("ERROR: Invalid TPL type. Expected " + str(expected_tpl_type) + ", but read " + str(tpl_type) + ".")
		exit()
	if src_file_size != (256*format_index_lengths[intype_id])+4:
		print("ERROR: Incorrect TPL file size. Should be " + str((256*format_index_lengths[intype_id])+4) + " bytes long.")
		exit()

elif args.intype == "zst":	# zs*
	zst_sig_read = get_data_chunk(src_data, 0x0, 0x17).decode('ascii', 'ignore')
	zst_sig_actual = "ZSNES Save State File V"

	if zst_sig_read != zst_sig_actual:
		print("ERROR: Incorrect ZSNES Savestate file signature.")
		exit()

elif args.intype == "col":	# COL
	col_sig_read = get_data_chunk(src_data, 0x200, 0x213).decode('ascii', 'ignore')
	col_sig_actual = "NAK1989 S-CG-CADVer"

	if col_sig_read != col_sig_actual:
		print("ERROR: Incorrect S-CG-CAD COL file signature.")
		exit()
	if src_file_size != 0x400:
		print("ERROR: Incorrect S-CG-CAD COL file size. Should be 1024 bytes long.")
		exit()

elif args.intype == "bmp24":	# BMP
	bmp_sig_read = get_data_chunk(src_data, 0x0, 0x2).decode('ascii', 'ignore')
	bmp_size_read = read_dword(src_data, 0x2, "little")
	bmp_size_actual = os.path.getsize(args.infile)
	bmp_width_read = read_dword(src_data, 0x12, "little")
	bmp_height_read = read_dword(src_data, 0x16, "little")
	bmp_color_depth_read = read_word(src_data, 0x1C, "little")
	bmp_data_size_read = read_dword(src_data, 0x22, "little")

	if bmp_sig_read != "BM":
		print("ERROR: Invalid BMP file signature. Expected 'BM' but read '" + bmp_sig_read + "'.")
		exit()
	if bmp_size_read != src_file_size:
		print("ERROR: Invalid file size in BMP header. Expected '" + str(src_file_size) + "' but read '" + str(bmp_size_read) + "'.")
		exit()
	if bmp_width_read != 16 and bmp_height_read != 16:
		print("ERROR: Invalid dimensions for input BMP. Width and height should both be 16 pixels.")
		exit()
	if bmp_color_depth_read != 24:
		print("ERROR: Invalid color depth for input BMP. Color depth should be 24 bits per pixel.")
		exit()
	if bmp_data_size_read != 768:
		print("ERROR: Invalid image data size for input BMP. Data should be 768 bytes long, but read " + str(bmp_data_size_read) + " bytes.")
		exit()

elif args.intype == "gpl": # GPL
	try:
		src_data_text = src_data.decode('ascii', 'ignore')
	except AttributeError:
		print("ERROR: Input file is not a text file.")
		exit()

	src_data_text_split = src_data_text.splitlines()

	if not src_data_text.startswith("GIMP Palette"):
		print("ERROR: Incorrect GIMP Palette signature.")
		exit()

	src_data_start_line = 1
	found_index_0 = False
	while src_data_start_line < len(src_data_text_split) and found_index_0 == False:
		index_0_search = re.search(r'^(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\s(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\s(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])', src_data_text_split[src_data_start_line])
		if index_0_search != None:
			found_index_0 = True
		else:
			src_data_start_line += 1
	else: 
		if src_data_start_line == len(src_data_text_split) and found_index_0 == False:
			print("ERROR: GIMP Palette file has no colors.")
			exit()

	src_data_pal_length = len(src_data_text_split)-src_data_start_line

elif args.intype == "gs0": # gs#
	pass

elif args.intype == "amp":
	if src_file_size != 768:
		print("ERROR: Invalid file size for Adobe AMP file.")
		exit()

if not args.inoffset:
	if is_text_type(args.intype):
		args.inoffset = get_default_input_offset(src_data, args.intype, src_data_start_line)
	else:
		args.inoffset = get_default_input_offset(src_data, args.intype)

if not args.inlength:													# If optional input length parameter isn't specified,
	if args.intype == "gpl":
		args.inlength = get_default_input_length(src_data, args.intype, args.inoffset, len(src_data_text_split))	# use function to determine default input length based on input type
	else:
		args.inlength = get_default_input_length(src_data, args.intype)							# use function to determine default input length based on input type

if is_text_type(args.intype):
	if args.noprint == False:
		print("\tStarting line number: " + str(args.inoffset+1))

	if args.inoffset < src_data_start_line or args.inoffset >= len(src_data_text_split):
		print("ERROR: Starting line number " + str(args.inoffset+1) + " outside of range for input file " + args.infile + ".")
		exit()

elif args.intype == "amp":
	if args.noprint == False:
		print("\tStarting index: " + str(args.inoffset))

	if args.inoffset not in range(256):
		print("ERROR: Starting index " + str(args.inoffset) + " invalid for input file " + args.infile + ".")
		exit()

else:
	if args.noprint == False:
		print("\tStarting offset: 0x" + str(format(args.inoffset, '0x').upper()[0:]))

	if args.inoffset not in range(src_file_size+1):
		print("ERROR: Starting offset 0x" + str(format(args.inoffset, '0x').upper()[0:]) + " outside of range for input file " + args.infile + ".")
		exit()

if args.noprint == False:
	print("\tPalette indices: " + str(args.inlength))

if is_text_type(args.intype):
	palette_end_offset = args.inoffset+args.inlength
elif args.intype == "bmp24":
	palette_end_offset = args.inoffset-(format_index_lengths[intype_id]*(args.inlength-16))	# End offset is before start offset because the bitmap data in BMP files is inverted
else:
	palette_end_offset = args.inoffset+(format_index_lengths[intype_id]*args.inlength)

if is_text_type(args.intype):
	if palette_end_offset > len(src_data_text_split):
		print("ERROR: Ending line number " + str(palette_end_offset+1) + " outside of range for file " + args.infile + ".")
		exit()
else:
	if palette_end_offset not in range(src_file_size+1):
		print("ERROR: Ending offset 0x" + str(format(palette_end_offset, '0x').upper()[0:]) + " outside of range for file " + args.infile + ".")
		exit()

for x, value in enumerate(outtypes_unique_list):
	outtype_id = format_shortnames.index(value)

	os.makedirs(format_outfile_folders[outtype_id], exist_ok=True)

	if args.intype == "zst":
		zst_extension_find = r'(?i)\.(z[1-9s][0-9t])$'
		zst_extension_replace =  r'_\1'

		outfile = format_outfile_folders[outtype_id] + '/' + re.sub(zst_extension_find, zst_extension_replace, args.infile) + format_outfile_ends[outtype_id]
	elif args.intype == "gs0":
		gsx_extension_find = r'(?i)\.(gs[0-9x])$'
		gsx_extension_replace =  r'_\1'

		outfile = format_outfile_folders[outtype_id] + '/' + re.sub(gsx_extension_find, gsx_extension_replace, args.infile) + format_outfile_ends[outtype_id]
	elif len(args.infile.split(format_outfile_ends[intype_id])) > 1:
		outfile = format_outfile_folders[outtype_id] + '/' + args.infile.rsplit(format_outfile_ends[intype_id], 1)[0] + format_outfile_ends[outtype_id]
	else:
		outfile = format_outfile_folders[outtype_id] + '/' + args.infile.rsplit(".", 1)[0] + format_outfile_ends[outtype_id]

	if value == "gpl":
		label = args.infile.rsplit(".", 1)[0]
	
	try:
		with open(outfile, 'w'):
			pass					# This creates an empty file, since a file must already exist for r+ mode to work later.
	except IOError:
		print("ERROR: Failed to open file " + outfile + ".")

	outlength = get_output_length(value, args.inlength)

	if args.noprint == False:
		print("\nOutput file " + str(x+1) + " of " + str(len(outtypes_unique_list)) + "...")
		print("\tPath: " + outfile)
		print("\tType: " + str(format_names[outtype_id]))
		print("\tPalette indices: " + str(outlength))

	with open(outfile, 'r+b') as output_file:	# The r+b argument allows us to open with the ability to read AND write
		src_offset = args.inoffset		# Set offset for reading from input file

		header = generate_header(value, outlength, format_index_lengths[outtype_id])	# Generate output file header based on the output file type argument
		output_file.write(header)
		palette_start = output_file.tell()	# Store current offset. After writing the header to the output file, this will be where the actual palette data starts.

		i = 0

		if value == "bmp24":	# Check if output file type is BMP
			write_seek_address = palette_start+(0xF0*format_index_lengths[outtype_id])	# -If so, we have to do this because bitmaps are stored inverted. The topmost row is the last one stored in the file.
			output_file.seek(write_seek_address)					# /

		while i < args.inlength:
			if is_text_type(args.intype):
				red, green, blue = decode_color(src_data_text_split, src_offset, args.intype, format_endianness[intype_id], i+args.inoffset)
			else: 
				red, green, blue = decode_color(src_data, src_offset, args.intype, format_endianness[intype_id])
				
			if value == "amp":
				color_start = i
				green_start = color_start+0x100
				blue_start = color_start+0x200
				
				output_file.seek(color_start)
				write_value = red.to_bytes(1, format_endianness[outtype_id])
				output_file.write(write_value)

				output_file.seek(green_start)
				write_value = green.to_bytes(1, format_endianness[outtype_id])
				output_file.write(write_value)

				output_file.seek(blue_start)
				write_value = blue.to_bytes(1, format_endianness[outtype_id])
				output_file.write(write_value)
			else:
				write_value = encode_color(output_file, value, red, green, blue, format_endianness[outtype_id], i)
				output_file.write(write_value)

			src_offset += format_index_lengths[intype_id]
			i += 1

			if args.intype == "bmp24": # Check if input file type is BMP
				index_modulo = i%0x10
				if index_modulo == 0:
					src_offset = src_offset-(format_index_lengths[intype_id]*0x20)

			if value == "bmp24":	# Check if output file type is BMP
				index_modulo = i%0x10
				if index_modulo == 0:
					if write_seek_address == palette_start:
						i = get_output_length(args.intype, args.inlength)
					else:
						write_seek_address = write_seek_address-(0x10*format_index_lengths[outtype_id])
						output_file.seek(write_seek_address)

		while i < outlength:
			if value == "jasc":
				filler_line = "000 000 000" + os.linesep
				output_file.write(filler_line.encode('ascii'))
			elif value == "gpl":
				filler_line = "0\t0\t0\tIndex " + str(i) + os.linesep
				output_file.write(filler_line.encode('ascii'))
			elif value == "amp":
				color_start = i
				green_start = color_start+0x100
				blue_start = color_start+0x200

				output_file.seek(color_start)
				write_value = 0x0.to_bytes(1, format_endianness[outtype_id])
				output_file.write(write_value)

				output_file.seek(green_start)
				write_value = 0x0.to_bytes(1, format_endianness[outtype_id])
				output_file.write(write_value)

				output_file.seek(blue_start)
				write_value = 0x0.to_bytes(1, format_endianness[outtype_id])
				output_file.write(write_value)	
			else:
				output_file.write(0x0.to_bytes(format_index_lengths[outtype_id], "big"))
			i += 1

			if value == "bmp24":
				index_modulo = i%0x10
				if index_modulo == 0:
					if write_seek_address == palette_start:
						i = outlength
					else:
						write_seek_address = write_seek_address-(0x10*format_index_lengths[outtype_id])
						output_file.seek(write_seek_address)
		
		footer = generate_footer(output_file, value, palette_start, outlength, format_index_lengths[outtype_id])
		output_file.write(footer)