import palette_reformatter_shared as palrfs
import os
from pathlib import Path
import argparse
import functools
import math
import re
import zlib
from datetime import datetime
import bisect

format_outfile_folders = [
	"raw-32X",
	"act",
	"amp",
	"bmp",
	"COL",
	"raw-gen-MD",
	"raw-game-gear",
	"gpl",
	"",
	"jasc-pal",
	"paint.net-txt",
	"indexed-png",
	"png",
	"raw-RGB15",
	"raw-RGB18",
	"riff-pal",
	"raw-SMS",
	"raw-SNES",
	"tpl-BGR15",
	"tpl-RGB24",
	"raw-WSC",
	""
]

format_outfile_ends = [
	"-32X.bin",
	".act",
	".amp",
	"-RGB24.bmp",
	".COL",
	"-GEN.bin",
	"-GG.bin",
	".gpl",
	"",
	"-JASC.pal",
	"-PDN.txt",
	"-RGB8.png",
	"-RGB24.png",
	"-RGB15.bin",
	"-RGB18.bin",
	"-RIFF.pal",
	"-SMS.bin",
	"-SNES.pal",
	"-BGR15.tpl",
	"-RGB24.tpl",
	"-WSC.bin"
	""
]

md_color_ramp = [  0,  52,  87, 116, 144, 172, 206, 255]	# Values for all levels of color channels for Mega Drive/Genesis

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

def find_less_or_equal(value_to_search, list_to_search):
	# Find rightmost value less than or equal to x
	i = bisect.bisect_right(list_to_search, value_to_search)
	if i:
		return i - 1
	raise ValueError

def get_png_chunk_list(data, filesize):
	addresses = []
	lengths = []
	names = []

	cursor_address = 0x8 # 0x8 is always the address of first chunk, which should be the IHDR chunk
	
	while cursor_address < filesize:
		addresses.append(cursor_address)
		lengths.append(read_dword(data, cursor_address, "big"))
		names.append(data[cursor_address+4:cursor_address+8].decode('ascii'))
		cursor_address = cursor_address+lengths[-1]+0xC

	return addresses, lengths, names

def validate_png(data, filesize):
	png_sig = get_data_chunk(data, 0, 8)
	if png_sig != b'\x89PNG\r\n\x1a\n':
		print('ERROR: Invalid PNG file signature.')
		exit()

	chunk_addresses, chunk_lengths, chunk_names = get_png_chunk_list(data, filesize)

	try:
		ihdr_index = chunk_names.index('IHDR')
	except ValueError:
		print('ERROR - PNG: Missing IHDR chunk.')
		exit()

	ihdr_len = chunk_lengths[ihdr_index]
	ihdr_data = get_data_chunk(data, chunk_addresses[ihdr_index]+8, chunk_addresses[ihdr_index+1]-4)
	if len(ihdr_data) != ihdr_len:
		print('ERROR - PNG: Length specified in IHDR chunk does not match length of actual header. Should be 13 bytes long per PNG Specification, Version 1.2.')
		exit()

	bit_depth = read_byte(data, 0x18)
	if bit_depth != 8:
		print('ERROR - PNG: Incorrect bit depth. Should be 8.')
		exit()

	color_type = read_byte(data, 0x19)
	if color_type != 2:
		print('ERROR - PNG: Incorrect color type. Should be 2 (R,G,B triple).')
		exit()

	interlace_type = read_byte(data, 0x1C)
	if interlace_type == 1:
		print('ERROR - PNG: Adam7 interlace method detected. This is currently unsupported by the script.')
		exit()

	width = read_dword(data, 0x10, "big")
	height = read_dword(data, 0x14, "big")

	try:
		idat_index = chunk_names.index('IDAT')
	except ValueError:
		print('ERROR - PNG: No IDAT chunks found.')
		exit()

	png_comp_len = chunk_lengths[idat_index]
	png_comp_data = get_data_chunk(data, chunk_addresses[idat_index]+8, chunk_addresses[idat_index+1]-4)
	if len(png_comp_data) != png_comp_len:
		print('ERROR: Length specified in IDAT chunk does not match length of image data.')
		exit()

	if chunk_names[-1] != 'IEND':
		print('ERROR - PNG: Missing IEND chunk.')
		exit()

	return width, height, png_comp_data

def paeth_predictor(left, above, upper_left):
        p = left + above - upper_left	# initial estimate
        pa = abs(p - left)		# distances to left, above, upper_left
        pb = abs(p - above)
        pc = abs(p - upper_left)
        # return nearest of left, above, upper_left,
        # breaking ties in order left, above, upper_left.
        if (pa <= pb) and (pa <= pc):
        	return left
        elif pb <= pc:
        	return above
        else:
        	return upper_left

def unfilter_decomped_idat(data, index_size, width, height):
	src_row_width = (width*index_size)+1
	dest_row_width = width*index_size
	unfiltered_data = bytearray()
	unfiltered_length = (width*index_size)*height
	src_address = 0
	dest_address = 0
	dest_row = 0

	while dest_address < unfiltered_length:
		dest_row = dest_address//(width*index_size)

		if src_address % src_row_width == 0:
			filter_byte = data[src_address]
			dest_column = 0
			src_address += 1

		if filter_byte == 0:	# None
			while dest_column < dest_row_width:
				write_value = (data[src_address])
				unfiltered_data.append(write_value)
				dest_column += 1
				src_address += 1
				dest_address += 1
		elif filter_byte == 1:	# Sub
			while dest_column < dest_row_width:
				if dest_column < index_size:
					left_sample = 0
				else:
					left_sample = unfiltered_data[-index_size]		# retrieve channel byte of processed color to the left of current pixel
				write_value = (data[src_address]+left_sample) % 256
				unfiltered_data.append(write_value)
				dest_column += 1
				src_address += 1
				dest_address += 1
		elif filter_byte == 2:	# Up
			while dest_column < dest_row_width:
				if dest_row == 0:
					above_sample = 0
				else:
					above_sample = unfiltered_data[-dest_row_width]		# retrieve channel byte of processed color in row above current pixel
				write_value = (data[src_address]+above_sample) % 256
				unfiltered_data.append(write_value)
				dest_column += 1
				src_address += 1
				dest_address += 1
		elif filter_byte == 3:	# Average
			while dest_column < dest_row_width:
				if dest_column < index_size:
					left_sample = 0
				else:
					left_sample = unfiltered_data[-index_size]		# retrieve channel byte of processed color to the left of current pixel
				if dest_row == 0:
					above_sample = 0
				else:
					above_sample = unfiltered_data[-dest_row_width]		# retrieve channel byte of processed color in row above current pixel
				write_value = (data[src_address]+((left_sample+above_sample)//2) % 256)
				unfiltered_data.append(write_value)
				dest_column += 1
				src_address += 1
				dest_address += 1
		elif filter_byte == 4:	# Paeth
			while dest_column < dest_row_width:
				if dest_column < index_size:
					left_sample = 0
				else:
					left_sample = unfiltered_data[-index_size]		# retrieve channel byte of processed color to the left of current pixel
				if dest_row == 0:
					above_sample = 0
				else:
					above_sample = unfiltered_data[-dest_row_width]		# retrieve channel byte of processed color in row above current pixel
				if (dest_row == 0) or (dest_column < index_size):
					upper_left_sample = 0
				else:
					upper_left_sample = unfiltered_data[-(dest_row_width+index_size)]		# retrieve channel byte of processed color to the upper left of current pixel
				paeth_result = paeth_predictor(left_sample, above_sample, upper_left_sample)
				write_value = (data[src_address]+paeth_result) % 256
				unfiltered_data.append(write_value)
				dest_column += 1
				src_address += 1
				dest_address += 1
		else:
			print('ERROR: invalid filter byte ' + filter_byte + '. Valid values are between 0 and 4.')
			exit()

	return unfiltered_data

def generate_header(file_type, length, index_size, width = None, height = None):
	if file_type == "bmp24": # BMP
		bmp_file_header = "BM".encode('ascii') + 0xDEADBEEF.to_bytes(4, "little") + 0x0.to_bytes(4, "little") + 0xDEADC0DE.to_bytes(4, "little")
		bmp_file_header_len = len(bmp_file_header)
		bmp_info_header = 0x1337C0DE.to_bytes(4, "little") + 0x10.to_bytes(4, "little") + 0x10.to_bytes(4, "little") + 0x1.to_bytes(2, "little") + 0x18.to_bytes(2, "little") + 0x0.to_bytes(4, "little") + (length * index_size).to_bytes(2, "little") + 0x0.to_bytes(18, "little")
		bmp_info_header_len = len(bmp_info_header)
		headers_len = bmp_file_header_len + bmp_info_header_len
		file_len = bmp_file_header_len + bmp_info_header_len + (length * index_size)
		bmp_file_header = bmp_file_header.replace(0xDEADBEEF.to_bytes(4, "little"), file_len.to_bytes(4, "little"))
		bmp_file_header = bmp_file_header.replace(0xDEADC0DE.to_bytes(4, "little"), headers_len.to_bytes(4, "little"))
		bmp_info_header = bmp_info_header.replace(0x1337C0DE.to_bytes(4, "little"), bmp_info_header_len.to_bytes(4, "little"))

		file_header = bmp_file_header+bmp_info_header
	elif file_type == "gpl": # GPL
		file_header = ("GIMP Palette" + os.linesep + "Name: " + label + os.linesep + "Columns: 16" + os.linesep + "#Converted using Palette Reformatter <a href=\"https://github.com/Mattrizzle/palette-reformatter\">https://github.com/Mattrizzle/palette-reformatter</a>" + os.linesep).encode('ascii')
	elif file_type == "jasc": # JASC
		file_header = ("JASC-PAL" + os.linesep + "0100" + os.linesep + str(16 if length <= 16 else 256) + os.linesep).encode('ascii')
	elif file_type == "pdn": # Paint.NET
		file_header = ("; Paint.NET Palette File" + os.linesep + "; " + label + os.linesep + "; Converted using Palette Reformatter https://github.com/Mattrizzle/palette-reformatter" + os.linesep).encode('ascii')
	elif file_type == "png8": # 8-bit PNG
		file_header = 0x89.to_bytes(1, "big") + "PNG\r\n".encode('ascii') + 0x1A.to_bytes(1, "big") + "\n".encode('ascii')
		ihdr = 0x10.to_bytes(4, "big") + 0x10.to_bytes(4, "big") + 0x8.to_bytes(1, "big") + 0x3.to_bytes(1, "big")+0x0.to_bytes(3, "big")

		file_header += len(ihdr).to_bytes(4, "big") + "IHDR".encode('ascii') + ihdr + 0x282D0F53.to_bytes(4, "big")
	elif file_type == "png24": # 24-bit PNG
		file_header = 0x89.to_bytes(1, "big") + "PNG\r\n".encode('ascii') + 0x1A.to_bytes(1, "big") + "\n".encode('ascii')
		ihdr_sig = "IHDR".encode('ascii')
		ihdr = width.to_bytes(4, "big") + height.to_bytes(4, "big") + 0x8.to_bytes(1, "big") + 0x2.to_bytes(1, "big") + 0x0.to_bytes(3, "big")
		ihdr_crc32 = zlib.crc32(ihdr_sig+ihdr)

		file_header += len(ihdr).to_bytes(4, "big")+ihdr_sig+ihdr+ihdr_crc32.to_bytes(4, "big")
	elif file_type == "riff": # RIFF
		riff_header = "RIFF".encode('ascii')+0xDEADBEEF.to_bytes(4, "little")
		riff_header_len = len(riff_header)
		pal_data_len = 16 if length <= 16 else 256
		pal_data_header = "PAL data".encode('ascii') + 0xDEADBEEF.to_bytes(4, "little") + 0x300.to_bytes(2, "little") + pal_data_len.to_bytes(2, "little")
		pal_data_header_len = len(pal_data_header)
		headers_len = riff_header_len + pal_data_header_len
		file_len = headers_len+(pal_data_len * index_size) + index_size
		riff_header = riff_header.replace(0xDEADBEEF.to_bytes(4, "little"), (file_len-riff_header_len).to_bytes(4, "little"))
		pal_data_header = pal_data_header.replace(0xDEADBEEF.to_bytes(4, "little"), ((pal_data_len * index_size) + 8).to_bytes(4, "little"))

		file_header = riff_header + pal_data_header
	elif file_type in {"tpl24", "tpl15"}: # TPL
		file_header = "TPL".encode('ascii')+(2 if file_type == "tpl15" else 0).to_bytes(1, "big")
	else:
		file_header = "".encode('ascii')

	return file_header

def get_base_address(data, file_type, index_size, content_type, line_num = None):
	if file_type == "bmp24":
		base_address = read_dword(data, 0xA, 'little')
	elif file_type == "gs0":
		base_address = 0x112
	elif file_type == "png8":
		chunk_addresses, chunk_lengths, chunk_names = get_png_chunk_list(data, len(data))
		base_address = chunk_addresses[chunk_names.index('PLTE')]+8	# Get location of first byte of data in PNG PLTE chunk
	elif file_type == "riff":
		base_address = 0x18
	elif file_type in {"tpl24", "tpl15"}:
		base_address = 0x4
	elif file_type == "zst":
		base_address = 0x618
	elif content_type == "text":
		base_address = line_num	# This is a line number instead of an offset, as JASC, GPL and Paint.NET palettes are text-based
	else:
		base_address = 0x0

	return base_address

def resolve_input_offset(data, file_type, base_address, input_position, index_size, content_type, length_type, input_width = None, input_height = None):
	if file_type == "bmp24":
		inverse_input_position = input_width * (input_height-1)-input_position+(2 * (input_position % input_width))
		input_offset = base_address + (inverse_input_position * index_size)
	elif content_type == "raw" and length_type == "variable":
		input_offset = base_address + input_position
	else:
		input_offset = base_address + (input_position * index_size)

	return input_offset

def get_default_input_length(data, file_type, index_size, content_type, length_type, input_offset = None, line_count = None, input_width = None, input_height = None):
	if file_type == "act":
		input_length = read_word(data, 0x400, 2, 'big') if len(data) == 0x404 else 256
	elif file_type in {"gpl", "pdn"}:
		input_length = line_count-input_offset
	elif file_type == "gs0":
		input_length = 64
	elif file_type == "riff":
		input_length = (read_dword(data, 0x4, "little")-8) // index_size,
	elif file_type == "jasc":
		input_length = int(data.decode('ascii', 'ignore').splitlines()[2]) if data.decode('ascii', 'ignore').splitlines()[2].isdigit() else 256
	elif content_type == "image" and length_type == "variable":
		input_length = input_width * input_height
	elif content_type == "raw":
		input_length = 256 if len(data) // index_size > 256 else len(data) // index_size
	else:
		input_length = 256

	if length_type == "fixed":
		input_length -= input_offset

	return input_length

def get_max_length(file_type, content_type, length_type, input_length, width = None, height = None):
	if file_type == "gs0":
		max_length = 64
	elif file_type == "jasc":
		max_length = 16 if input_length <= 16 else 256
	elif file_type == "pdn":
		max_length = 96
	elif length_type == "fixed":
		max_length = 256
	elif content_type == "image" and length_type == "variable":
		max_length = width * height if width != None and height != None else False
	elif length_type == "variable":
		max_length = False
	return max_length

def get_output_length(content_type, input_length, maximum_output_size, output_width, output_height):
	if content_type == "image" and maximum_output_size == False:
		output_length = output_width * output_height
	elif maximum_output_size != False and input_length != maximum_output_size:
		output_length = maximum_output_size
	else:
		output_length = input_length

	return output_length

def decode_color(data, address, file_type, content_type, endianness, use_old_conv_method = None):
	if file_type in {"act", "png8", "png24", "riff",  "tpl24"}:	# 24-bit RGB
		r = read_byte(data, address)
		g = read_byte(data, address+1)
		b = read_byte(data, address+2)
	elif file_type == "amp":					# Adobe Curves File (AMP)
		r = read_byte(data, address)
		g = read_byte(data, address + 0x100)
		b = read_byte(data, address + 0x200)
	elif file_type == "bmp24":					# 24-bit BGR
		r = read_byte(data, address + 2)
		g = read_byte(data, address + 1)
		b = read_byte(data, address)
	elif file_type in {"gen", "gs0"}:				# 9-bit BGR
		raw_color = read_word(data, address, endianness)
		raw_red = (raw_color >> 1) & 0x0007
		raw_green = (raw_color >> 5) & 0x0007
		raw_blue = (raw_color >> 9) & 0x0007

		if use_old_conv_method == True:
			r = raw_red << 5
			g = raw_green << 5
			b = raw_blue << 5
		else:
			r = md_color_ramp[raw_red]
			g = md_color_ramp[raw_green]
			b = md_color_ramp[raw_blue]
	elif file_type in {"gg", "wsc"}:				# 12-bit BGR
		raw_color = read_word(data, address, endianness)
		raw_red = raw_color & 0x000F
		raw_green = (raw_color >> 4) & 0x000F
		raw_blue = (raw_color >> 8) & 0x000F

		r = raw_red << 4
		g = raw_green << 4
		b = raw_blue << 4

		if use_old_conv_method == False:
			if file_type == "gg":
				r = r | (raw_red >> 1) + (raw_red & 8)
				g = g | (raw_green >> 1) + (raw_green & 8)
				b = b | (raw_blue >> 1) + (raw_blue & 8)
			elif file_type == "wsc":
				r = r | raw_red
				g = g | raw_green
				b = b | raw_blue
	elif file_type == "pdn":
		r = int(data[address][2:4], 16)
		g = int(data[address][4:6], 16)
		b = int(data[address][6:8], 16)
	elif file_type == "rgb15":					# 15-bit RGB
		raw_color = read_word(data, address, endianness)
		r = ((raw_color >> 10) & 0x001F) << 3
		g = ((raw_color >> 5) & 0x001F) << 3
		b = (raw_color & 0x001F) << 3
		
		if use_old_conv_method == False:
			r += (((raw_color >> 10) & 0x001F) >> 2)
			g += (((raw_color >> 5) & 0x001F) >> 2)
			b += ((raw_color & 0x001F) >> 2)
	elif file_type == "rgb18":					# 18-bit RGB
		raw_red = read_byte(data, address)
		raw_green = read_byte(data, address+1)
		raw_blue = read_byte(data, address+2)

		r = raw_red << 2
		g = raw_green << 2
		b = raw_blue << 2

		if use_old_conv_method == False:
			r = r | (raw_red >> 4)
			g = g | (raw_green >> 4)
			b = b | (raw_blue >> 4)
	elif file_type == "sms":					# 6-bit BGR
		raw_color = read_byte(data, address)
		raw_red = raw_color & 0x03
		raw_green = (raw_color >> 2) & 0x03
		raw_blue = (raw_color >> 4) & 0x03

		r = raw_red << 6
		g = raw_green << 6
		b = raw_blue << 6

		if use_old_conv_method == False:
			r = r | (raw_red << 4) | (((raw_red << 2) | raw_red) >> 1) + (((raw_red << 2) | raw_red) & 8)
			g = g | (raw_green << 4) | (((raw_green << 2) | raw_green) >> 1) + (((raw_green << 2) | raw_green) & 8)
			b = b | (raw_blue << 4) | (((raw_blue << 2) | raw_blue) >> 1) + (((raw_blue << 2) | raw_blue) & 8)
	elif content_type == "text":				# JASC / GIMP
		colors = re.split(r'\s+', data[address])
		try:
			r = int(colors[0])
			if r > 255 or r < 0:
				raise ValueError()
		except ValueError:
			r = 255
			print("ERROR on line " + str(address+1) + " of input file:\n\tInvalid red value. Replaced with " + str(r) + ".")
		except IndexError:
			r = 0
			print("ERROR on line " + str(address+1) + " of input file:\n\tMissing red value. Replaced with " + str(r) + ".")

		try:
			g = int(colors[1])
			if g > 255 or g < 0:
				raise ValueError()
		except ValueError:
			g = 255
			print("ERROR on line " + str(address+1) + " of input file:\n\tInvalid green value. Replaced with " + str(g) + ".")
		except IndexError:
			g = 0
			print("ERROR on line " + str(address+1) + " of input file:\n\tMissing green value. Replaced with " + str(g) + ".")

		try:
			b = int(colors[2])
			if b > 255 or b < 0:
				raise ValueError()
		except ValueError:
			b = 255
			print("ERROR on line " + str(address+1) + " of input file:\n\tInvalid blue value. Replaced with " + str(b) + ".")
		except IndexError:
			b = 0
			print("ERROR on line " + str(address+1) + " of input file:\n\tMissing blue value. Replaced with " + str(b) + ".")
	else:							# 15-bit BGR
		raw_color = read_word(data, address, endianness)
		r = (raw_color & 0x001F) << 3
		g = ((raw_color >> 5) & 0x001F) << 3
		b = ((raw_color >> 10) & 0x001F) << 3
		
		if use_old_conv_method == False:
			r += ((raw_color & 0x001F) >> 2)
			g += (((raw_color >> 5) & 0x001F) >> 2)
			b += (((raw_color >> 10) & 0x001F) >> 2)
		
	return r, g, b

def encode_color(data, file_type, r, g, b, endianness, index, use_old_conv_method = None):
	if file_type in {"act", "tpl24", "png8"}:			# 24-bit RGB
		color = r << 16 | g << 8 | b
		color_bytes = color.to_bytes(3, endianness)
	elif file_type == "bmp24":					# 24-bit BGR
		color = r | g << 8 | b << 16
		color_bytes = color.to_bytes(3, endianness)
	elif file_type == "gen":					# 9-bit BGR
		if use_old_conv_method == False:
			red = find_less_or_equal(r, md_color_ramp) << 1
			green = find_less_or_equal(g, md_color_ramp) << 1
			blue = find_less_or_equal(b, md_color_ramp) << 1

			color = (red & 0x000E) | ((green << 4) & 0x00E0) | ((blue << 8) & 0x0E00)
		else:	
			color = ((r >> 4) & 0x000E) | (g & 0x00E0) | ((b << 4) & 0x0E00)
		color_bytes = color.to_bytes(2, endianness)
	elif file_type in {"gg", "wsc"}:				# 12-bit BGR
		color = ((r >> 4) & 0x00F) | (g & 0x0F0) | ((b << 4) & 0xF00)
		color_bytes = color.to_bytes(2, endianness)
	elif file_type == "gpl":					# GIMP
		line = str(r) + '\t' + str(g) + '\t' + str(b) + '\tIndex ' + str(index) + os.linesep
		color_bytes = line.encode('ascii')
	elif file_type == "jasc":					# JASC
		line = str(format(r, '03d')) + ' ' + str(format(g, '03d')) + ' ' + str(format(b, '03d')) + os.linesep
		color_bytes = line.encode('ascii')
	elif file_type == "pdn":
		line = str(format(255, '02X')) + str(format(r, '02X')) + str(format(g, '02X')) + str(format(b, '02X')) + os.linesep
		color_bytes = line.encode('ascii')	
	elif file_type == "rgb15":					# 15-bit RGB
		color = ((r << 7) & 0x7C00) | ((g << 2) & 0x03E0) | ((b >> 3) & 0x001F)
		color_bytes = color.to_bytes(2, endianness)
	elif file_type == "rgb18":
		color = ((r << 14) & 0x3F0000) | ((g << 6) & 0x3F00) | ((b >> 2) & 0x3F)
		color_bytes = color.to_bytes(3, endianness)
	elif file_type == "riff": 					# 32-bit RGBX
		color = r << 24 | g << 16 | b << 8
		color_bytes = color.to_bytes(4, endianness)
	elif file_type == "sms":					# 6-bit BGR
		color = ((r >> 6) & 0x03) | ((g >> 4) & 0x0C) | ((b >> 2) & 0x30)
		color_bytes = color.to_bytes(1, endianness)
	else:								# 15-bit BGR
		color = ((r >> 3) & 0x001F) | ((g << 2) & 0x03E0) | ((b << 7) & 0x7C00)
		color_bytes = color.to_bytes(2, endianness)

	return color_bytes

def generate_footer(data, file_type, length, index_size):
	if file_type == "act" and args.inlength < 256:	# ACT
		file_footer = args.inlength.to_bytes(2, "big")+0xFFFF.to_bytes(2, "big")	# This is so Photoshop only shows the actual used colors in its Color Table window
	elif file_type == "col":	# COL
		now = datetime.now()
		date = now.strftime("%y%m%d")
		file_footer = ("NAK1989 S-CG-CADVer1.XX " + date + "  ").encode('ascii')+0x0.to_bytes(0x1E0, "big")
	elif file_type == "png8":	# 8-bit PNG
		idat = "IDAT".encode('ascii') + 0x18576361.to_bytes(4, "big") + 0x6044052C.to_bytes(4, "big") + 0x02235A00.to_bytes(4, "big") + 0x0022D702.to_bytes(4, "big") + 0x21.to_bytes(1, "big")
		idat_crc32 = zlib.crc32(idat)
		iend = "IEND".encode('ascii')
		iend_crc32 = zlib.crc32(iend)
		file_footer = (len(idat) - 4).to_bytes(4, "big") + idat + idat_crc32.to_bytes(4, "big") + 0x0.to_bytes(4, "big") + iend + iend_crc32.to_bytes(4, "big")
	elif file_type == "png24":	# 24-bit PNG
		iend = "IEND".encode('ascii')
		iend_crc32 = zlib.crc32(iend)
		file_footer = 0x0.to_bytes(4, "big") + iend + iend_crc32.to_bytes(4, "big")
	elif file_type == "riff":	# RIFF
		file_footer = 0x0.to_bytes(4, "little")
	else:
		file_footer = "".encode('ascii')
	return file_footer

parser = argparse.ArgumentParser(prog="palette_reformatter", formatter_class=argparse.RawDescriptionHelpFormatter, description="Palette Reformatter\nBy Mattrizzle - https://github.com/Mattrizzle/palette-reformatter\nThis script converts a single palette file from a specified input type to one \nor more specified output types.", epilog=palrfs.print_file_type_list())
parser.add_argument("-n", "--noprint", action="store_true", help="If present, information will not be displayed in the terminal.")
parser.add_argument("-c", "--oldconvmethod", action="store_true", help="If present, the old conversion method will be used for raw types less than 24-bit.")
parser.add_argument("infile", metavar="<input file>", help="Source file path.")
parser.add_argument("intype", metavar="<input type>", choices=palrfs.build_file_type_choice_list(is_input = True), help="Input file type. (See NOTE below)")
parser.add_argument("-a", "--inoffset", metavar="<input offset>", type=functools.wraps(int)(functools.partial(int, base=0)), default=0, help="Offset of palette to convert in source file. Input offset must not exceed the end of the source file. For GIMP, JASC and Paint.NET palettes (intypes gpl, jasc and pdn), a line number should be specified instead of an offset.")
parser.add_argument("-l", "--inlength", metavar="<input length>", type=functools.wraps(int)(functools.partial(int, base=0)), help="Number of palette indices to convert in source file. Input length must not exceed the end of the source file.")
parser.add_argument("outtype", metavar="<output types>", nargs="+", choices=palrfs.build_file_type_choice_list(is_output = True), help="Output file type(s). Can specify multiple types to write more than one file. (See NOTE below)")
parser.add_argument("-d", "--outdimensions", metavar="<width and height>", nargs=2, type=functools.wraps(int)(functools.partial(int, base=0)), help="Width and height of variable-sized output images.")

args = parser.parse_args()

args.infile = args.infile.replace("/", os.sep)

src_data = load_file(args.infile)
src_file_size = len(src_data)

intype_id = palrfs.find_in_list(args.intype, palrfs.formats)[0]

if intype_id == False:
	in_alias_id = palrfs.find_in_list(args.intype, palrfs.format_aliases)[0]
	resolved_intype = palrfs.format_aliases[in_alias_id][1]
	intype_id = palrfs.find_in_list(resolved_intype, palrfs.formats)[0]

input_index_size = palrfs.formats[intype_id][3]
input_content_type = palrfs.formats[intype_id][4]
input_length_type = palrfs.formats[intype_id][5]
input_byte_order = palrfs.formats[intype_id][6]

outtypes_unique = set(args.outtype)
outtypes_unique_list = list(outtypes_unique)
outtypes_unique_list.sort()

if args.noprint == False:
	print("\nInput file...")
	print("\tPath: " + args.infile)
	print("\tType: " + str(palrfs.format_names[intype_id]))
	print("\tIndex size: " + str(input_index_size) + (" line" if input_content_type == "text" else " byte") + ("" if input_index_size == 1 else "s"))
	print("\tContent type: " + f"{input_content_type[0].upper()}{input_content_type[1:]}")
	print("\tLength type: " + f"{input_length_type[0].upper()}{input_length_type[1:]}")
	print("\tByte order: " + f"{input_byte_order[0].upper()}{input_byte_order[1:]}" + "-endian")

# Check file format integrity
if args.intype == "act":	# ACT
	if src_file_size not in {768, 772}:
		print("ERROR: Invalid Adobe Color Table file size. Should be 768 or 772 bytes long.")
		exit()

elif args.intype == "amp":
	if src_file_size != 768:
		print("ERROR: Invalid file size for Adobe AMP file.")
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
		print("ERROR: Invalid BMP file signature. Expected 'BM'.")
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

elif args.intype == "col":	# COL
	col_sig_read = get_data_chunk(src_data, 0x200, 0x213).decode('ascii', 'ignore')
	col_sig_actual = "NAK1989 S-CG-CADVer"

	if col_sig_read != col_sig_actual:
		print("ERROR: Incorrect S-CG-CAD COL file signature.")
		exit()
	if src_file_size != 0x400:
		print("ERROR: Incorrect S-CG-CAD COL file size. Should be 1024 bytes long.")
		exit()

elif args.intype == "gs0": # GS0
	gs0_sig_read = get_data_chunk(src_data, 0x0, 0x3).decode('ascii', 'ignore')

	if gs0_sig_read != "GST":
		print("ERROR: Invalid GS0 file signature. Expected 'GST'.")
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
		index_0_search = re.search(r'^(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\s+(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\s+(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])', src_data_text_split[src_data_start_line])
		if index_0_search != None:
			found_index_0 = True
		else:
			src_data_start_line += 1
	else: 
		if src_data_start_line == len(src_data_text_split) and found_index_0 == False:
			print("ERROR: GIMP Palette file has no colors.")
			exit()

elif args.intype == "jasc":	# JASC
	try:
		src_data_text = src_data.decode('ascii', 'ignore')
	except AttributeError:
		print("ERROR: Input file is not a text file.")
		exit()

	src_data_text_split = src_data_text.splitlines()

	if src_data_text_split[0] != "JASC-PAL" or src_data_text_split[1] != "0100":
		print("ERROR: Incorrect JASC file signature.")
		exit()

	if src_data_text_split[2] not in {"256", "16"}:
		print("ERROR: Invalid JASC palette length.")
		exit()

	src_data_start_line = 3

elif args.intype == "pdn":
	try:
		src_data_text = src_data.decode('ascii', 'ignore')
	except AttributeError:
		print("ERROR: Input file is not a text file.")
		exit()

	src_data_text_split = src_data_text.splitlines()
	src_data_text_split = [l for l in src_data_text_split if not l.startswith(';')]
	
	src_data_start_line = 0

elif args.intype == "png24":
	inwidth, inheight, comp_bitmap = validate_png(src_data, src_file_size)
	bitmap_data = zlib.decompress(comp_bitmap)
	bitmap_data = unfilter_decomped_idat(bitmap_data, input_index_size, inwidth, inheight)

elif args.intype == "riff":	# RIFF
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

elif args.intype in {"tpl24", "tpl15"}:	# TPL
	tpl_sig_read =  get_data_chunk(src_data, 0x0, 0x3).decode('ascii', 'ignore')
	tpl_type = read_byte(src_data, 0x3)
	expected_tpl_type = 2 if args.intype == "tpl15" else 0

	if tpl_sig_read != "TPL":
		print("ERROR: Incorrect or missing TPL file signature.")
		exit()
	if tpl_type != expected_tpl_type:
		print("ERROR: Invalid TPL type. Expected " + str(expected_tpl_type) + ", but read " + str(tpl_type) + ".")
		exit()
	if src_file_size != (256 * input_index_size) + 4:
		print("ERROR: Incorrect TPL file size. Should be " + str((256 * input_index_size) + 4) + " bytes long.")
		exit()

elif args.intype == "zst":	# zs*
	zst_sig_read = get_data_chunk(src_data, 0x0, 0x17).decode('ascii', 'ignore')
	zst_sig_actual = "ZSNES Save State File V"

	if zst_sig_read != zst_sig_actual:
		print("ERROR: Incorrect ZSNES Savestate file signature.")
		exit()

if input_content_type == "text":
	src_base_address = get_base_address(src_data, args.intype, input_index_size, input_content_type, src_data_start_line)
else:
	src_base_address = get_base_address(src_data, args.intype, input_index_size, input_content_type)

if args.intype == "bmp24":
	src_offset = resolve_input_offset(src_data, args.intype, src_base_address, args.inoffset, input_index_size, input_content_type, input_length_type, input_width = bmp_width_read, input_height = bmp_height_read)
else:
	src_offset = resolve_input_offset(src_data, args.intype, src_base_address, args.inoffset, input_index_size, input_content_type, input_length_type)

if not args.inlength:				# If optional input length parameter isn't specified...
	if args.intype in {"gpl", "pdn"}:	# ...and input type is GIMP or Paint.NET palette...
		# ...use function to determine default input length based on input type with input offset and number of lines.
		args.inlength = get_default_input_length(src_data, args.intype, input_index_size, input_content_type, input_length_type, src_offset, line_count = len(src_data_text_split))
	elif input_content_type == "image" and input_length_type == "variable":	# If input type is a variable-sized image
		# ...use function to determine default input length based on input type, width and height.
		args.inlength = get_default_input_length(src_data, args.intype, input_index_size, input_content_type, input_length_type, input_width = inwidth, input_height = inheight)
	else:
		# Otherwise, use function to determine default input length based on input type.
		args.inlength = get_default_input_length(src_data, args.intype, input_index_size, input_content_type, input_length_type, args.inoffset)

if input_content_type == "image" and input_length_type == "variable":
	max_inlength = get_max_length(args.intype, input_content_type, input_length_type, args.inlength, inwidth, inheight)
else:
	max_inlength = get_max_length(args.intype, input_content_type, input_length_type, args.inlength)

if max_inlength == False:
	if input_content_type == "image":
		max_inlength = len(bitmap_data)
	elif input_content_type == "text":
		max_inlength = len(src_data_text_split)-src_base_address
	elif input_content_type == "raw" and input_length_type == "variable":
		max_inlength = src_file_size
	else:
		max_inlength = src_file_size // input_index_size

if input_content_type == "raw" and input_length_type == "variable":
	if args.noprint == False:
		print("\tStarting offset: 0x" + str(format(args.inoffset, '0X')[0:]))

	if args.inoffset not in range(max_inlength):
		print("ERROR: Starting offset 0x" + str(format(args.inoffset, '0X')[0:]) + " outside of range for input file " + args.infile + ".")
		exit()
else:	# (input_content_type == "image" or input_content_type == "headered-raw") and input_length_type == "fixed"
	if args.noprint == False:
		print("\tStarting index: " + str(args.inoffset))

	if args.inoffset not in range(max_inlength):
		print("ERROR: Starting index " + str(args.inoffset) + " invalid for input file " + args.infile + ".")
		exit()

if args.noprint == False and input_content_type == "image" and input_length_type == "variable":
	print("\tDimensions: " + str(inwidth) + " x " + str(inheight) + "px")

if args.intype == "png24":
	pass
elif input_content_type == "text":
	palette_end_offset = args.inoffset + args.inlength
	if palette_end_offset > max_inlength:
		print("ERROR: Ending line number " + str(palette_end_offset+1) + " outside of range for file " + args.infile + ".")
		exit()
else:
	if args.intype == "bmp24":
		palette_end_offset = src_offset - (input_index_size * (args.inlength - bmp_width_read))	# End offset is before start offset because the bitmap data in BMP files is inverted
	else:
		palette_end_offset = args.inoffset + (input_index_size * args.inlength)
	if palette_end_offset not in range(src_file_size+1):
		print("ERROR: Ending offset 0x" + str(format(palette_end_offset, '0x').upper()[0:]) + " outside of range for file " + args.infile + ".")
		exit()

if args.noprint == False:
	if input_content_type == "raw" and input_length_type == "variable":
		print("\tPalette indices: " + str(args.inlength) + " / " + str(max_inlength // input_index_size))
	else:
		print("\tPalette indices: " + str(args.inlength) + " / " + str(max_inlength))

if args.outdimensions:
	output_dimensions = list(args.outdimensions)
else:
	output_dimensions = list()
	if args.inlength < 16:
		output_dimensions.append(args.inlength)
		output_dimensions.append(1)
	else:
		output_dimensions.append(16)
		output_dimensions.append(math.ceil(args.inlength/16))

for x, value in enumerate(outtypes_unique_list):
	outtype_id = palrfs.find_in_list(value, palrfs.formats)[0]

	if intype_id == False:
		out_alias_id = palrfs.find_in_list(value, palrfs.format_aliases)[0]
		resolved_outtype = palrfs.format_aliases[out_alias_id][1]
		outtype_id = palrfs.find_in_list(resolved_outtype, palrfs.formats)[0]

	output_index_size = palrfs.formats[outtype_id][3]
	output_content_type = palrfs.formats[outtype_id][4]
	output_length_type = palrfs.formats[outtype_id][5]
	output_byte_order = palrfs.formats[outtype_id][6]

	output_path_parts = args.infile.split(os.sep)	# Split the entered file path into multiple list items on slashes and backslashes

	output_filename = output_path_parts.pop()	# Remove the last entry in the list and populate this variable. This should input filename, but not the name of any folders.

	if len(output_path_parts) > 0:
	 	output_directory = (os.sep).join(output_path_parts) + os.sep + format_outfile_folders[outtype_id]
	else:
		output_directory = format_outfile_folders[outtype_id]
	Path(output_directory).mkdir(parents=True, exist_ok=True)

	if args.intype == "zst":
		zst_extension_find = r'(?i)\.(z[1-9s][0-9t])$'
		zst_extension_replace =  r'_\1'

		outfile = output_directory + os.sep + re.sub(zst_extension_find, zst_extension_replace, output_filename)
	elif args.intype == "gs0":
		gsx_extension_find = r'(?i)\.(gs[0-9x])$'
		gsx_extension_replace =  r'_\1'

		outfile = output_directory + os.sep + re.sub(gsx_extension_find, gsx_extension_replace, output_filename)
	elif len(args.infile.split(format_outfile_ends[intype_id])) > 1:
		outfile = output_directory + os.sep + output_filename.rsplit(format_outfile_ends[intype_id], 1)[0]
	else:
		outfile = output_directory + os.sep + output_filename.rsplit(".", 1)[0]

	if args.inoffset:
		outfile += "-" + str(format(args.inoffset, '0X')) + format_outfile_ends[outtype_id]
	else:
		outfile += format_outfile_ends[outtype_id]

	if value in {"gpl", "pdn"}:
		label = output_filename.rsplit(".", 1)[0]
	
	try:
		with open(outfile, 'w'):
			pass					# This creates an empty file, since a file must already exist for r+ mode to work later.
	except IOError:
		print("ERROR: Failed to open file " + outfile + ".")

	max_outlength = get_max_length(value, output_content_type, output_length_type, args.inlength)
	outlength = get_output_length(output_content_type, args.inlength, max_outlength, output_dimensions[0], output_dimensions[1])

	if args.noprint == False:
		print("\nOutput file " + str(x+1) + " of " + str(len(outtypes_unique_list)) + "...")
		print("\tPath: " + outfile)
		print("\tType: " + str(palrfs.format_names[outtype_id]))
		print("\tIndex size: " + str(output_index_size) + (" line" if output_content_type == "text" else " byte") + ("" if output_index_size == 1 else "s"))
		print("\tContent type: " +  f"{output_content_type[0].upper()}{output_content_type[1:]}")
		print("\tLength type: " + f"{output_length_type[0].upper()}{output_length_type[1:]}")
		print("\tByte order: " +  f"{output_byte_order[0].upper()}{output_byte_order[1:]}" + "-endian")
		if output_content_type == "image" and output_length_type == "variable":
			print("\tDimensions: " + str(output_dimensions[0]) + " x " + str(output_dimensions[1]) + "px")
		print("\tPalette indices: " + str(outlength) + (" (padded from " + str(args.inlength) + ")" if outlength > args.inlength else " (trimmed from " + str(args.inlength) + ")" if output_length_type == "fixed" and args.inlength > outlength else ""))

	if output_length_type == "fixed" and args.inlength > outlength:
		args.inlength = outlength

	with open(outfile, 'r+b') as output_file:	# The r+b argument allows us to open with the ability to read AND write		
		src_pos = src_offset			# Set offset for reading from input file
		
		if value in {"png8", "png24"}:
			palette_buffer = bytearray()
		if value == "png24":
			header = generate_header(value, outlength, output_index_size, output_dimensions[0], output_dimensions[1])
		else:
			header = generate_header(value, outlength, output_index_size)	# Generate output file header based on the output file type argument
		output_file.write(header)
		palette_start = output_file.tell()	# Store current offset. After writing the header to the output file, this will be where the actual palette data starts.

		i = 0

		# print("inlength: " + str(args.inlength) + " max_inlength: " + str(max_inlength) + " outlength: " + str(outlength) + " max_outlength: " + str(max_outlength))

		if value == "bmp24":	# Check if output file type is BMP
			write_seek_address = palette_start+(0xF0 * output_index_size)	# -If so, we have to do this because bitmaps are stored inverted. The topmost row is the last one stored in the file.
			output_file.seek(write_seek_address)				# /

		while i < args.inlength:
			# print("i: " + str(i) + " src_pos: " + str(src_pos) + " inlength: " + str(args.inlength))
			if args.intype == "png24":
				red, green, blue = decode_color(bitmap_data, src_pos, args.intype, input_content_type, input_byte_order)
			elif input_content_type == "text":
				red, green, blue = decode_color(src_data_text_split, src_pos, args.intype, input_content_type, input_byte_order)
			else: 
				red, green, blue = decode_color(src_data, src_pos, args.intype, input_content_type, input_byte_order, args.oldconvmethod)
				
			if value == "amp":
				red_start = i
				green_start = red_start+0x100
				blue_start = red_start+0x200
				
				output_file.seek(red_start)
				write_value = red.to_bytes(1, output_byte_order)
				output_file.write(write_value)

				output_file.seek(green_start)
				write_value = green.to_bytes(1, output_byte_order)
				output_file.write(write_value)

				output_file.seek(blue_start)
				write_value = blue.to_bytes(1, output_byte_order)
				output_file.write(write_value)
			elif value == "png8":
				palette_buffer.append(red)
				palette_buffer.append(green)
				palette_buffer.append(blue)			
			elif value == "png24":
				index_modulo = i % output_dimensions[0]
				if index_modulo == 0:	 	 # If beginning of row,
					palette_buffer.append(0) # Append filter byte

				palette_buffer.append(red)
				palette_buffer.append(green)
				palette_buffer.append(blue)
			else:
				write_value = encode_color(output_file, value, red, green, blue, output_byte_order, i, args.oldconvmethod)
				output_file.write(write_value)

			src_pos += input_index_size
			i += 1

			if args.intype == "bmp24": # Check if input file type is BMP
				index_modulo = i % 0x10
				if index_modulo == 0:
					src_pos = src_pos-(input_index_size * 0x20)

			if value == "bmp24":	# Check if output file type is BMP
				index_modulo = i % 0x10
				if index_modulo == 0:
					if write_seek_address == palette_start:
						i = args.inlength
					else:
						write_seek_address = write_seek_address - (0x10 * output_index_size)
						output_file.seek(write_seek_address)
		while i < outlength:
			if value == "jasc":
				filler_line = "000 000 000" + os.linesep
				output_file.write(filler_line.encode('ascii'))
			elif value == "gpl":
				filler_line = "0\t0\t0\tIndex " + str(i) + os.linesep
				output_file.write(filler_line.encode('ascii'))
			elif value == "pdn":
				filler_line = "FFFFFFFF" + os.linesep
				output_file.write(filler_line.encode('ascii'))
			elif value == "amp":
				red_start = i
				green_start = red_start+0x100
				blue_start = red_start+0x200
				write_value = 0x0.to_bytes(1, output_byte_order)

				output_file.seek(red_start)
				output_file.write(write_value)

				output_file.seek(green_start)
				output_file.write(write_value)

				output_file.seek(blue_start)
				output_file.write(write_value)
			elif value == "png8":
				palette_buffer.append(0)
				palette_buffer.append(0)
				palette_buffer.append(0)			
			elif value == "png24":
				index_modulo = i % output_dimensions[0]
				if index_modulo == 0:	 	 # If beginning of row,
					palette_buffer.append(0) # Append filter byte

				palette_buffer.append(0)
				palette_buffer.append(0)
				palette_buffer.append(0)
			else:
				output_file.write(0x0.to_bytes(output_index_size, "big"))
			i += 1

			if value == "bmp24":
				index_modulo = i % 0x10
				if index_modulo == 0:
					if write_seek_address == palette_start:
						i = outlength
					else:
						write_seek_address = write_seek_address - (0x10 * output_index_size)
						output_file.seek(write_seek_address)
		if value == "png8":
			plte_length = (outlength * output_index_size).to_bytes(4, "big")
			plte = "PLTE".encode('ascii') + palette_buffer
			plte_crc32 = zlib.crc32(plte).to_bytes(4, "big")
			output_file.write(plte_length + plte + plte_crc32)
		elif value == "png24":
			palette_buffer_comp = zlib.compress(palette_buffer)
			idat_length = len(palette_buffer_comp).to_bytes(4, "big")
			idat = "IDAT".encode('ascii') + palette_buffer_comp
			idat_crc32 = zlib.crc32(idat).to_bytes(4, "big")
			output_file.write(idat_length + idat + idat_crc32)
		
		if value == "act" or output_content_type != "raw":
			footer = generate_footer(output_file, value, outlength, output_index_size)
			output_file.write(footer)