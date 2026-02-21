formats = [
#	Short Name	Input type?	Output type?	Index Size	Content Type	Length Type	Byte Order
	["32x",		True,		True,		2,		"raw",		"variable",	"big"],
	["act",		True,		True,		3,		"raw",		"fixed",	"big"],
	["amp",		True,		True,		1,		"raw",		"fixed",	"big"],
	["bmp24",	True,		True,		3,		"image",	"fixed",	"big"],
	["col",		True,		True,		2,		"headered-raw",	"fixed",	"little"],
	["gen",		True,		True,		2,		"raw",		"variable",	"big"],
	["gg",		True,		True,		2,		"raw",		"variable",	"little"],
	["gpl",		True,		True,		1,		"text",		"variable",	"big"],		# Index size is in lines rather than bytes, as GIMP palettes are text-based
	["gs0",		True,		False,		2,		"raw",		"fixed",	"big"],
	["jasc",	True,		True,		1,		"text",		"variable",	"big"],		# Index size is in lines rather than bytes, as JASC palettes are text-based
	["pdn",		True,		True,		1,		"text",		"fixed",	"big"],		# Index size is in lines rather than bytes, as Paint.NET palettes are text-based
	["png8",	True,		True,		3,		"image",	"fixed",	"big"],	
	["png24",	True,		True,		3,		"image",	"variable",	"big"],	
	["rgb15",	True,		True,		2,		"raw",		"variable",	"little"],
	["rgb18",	True,		True,		3,		"raw",		"variable",	"big"],
	["riff",	True,		True,		4,		"headered-raw",	"fixed",	"big"],	
	["sms",		True,		True,		1,		"raw",		"variable",	"little"],
	["snes",	True,		True,		2,		"raw",		"variable",	"little"],	
	["tpl15",	True,		True,		2,		"headered-raw",	"fixed",	"little"],
	["tpl24",	True,		True,		3,		"headered-raw",	"fixed",	"big"],
	["wsc",		True,		True,		2,		"raw",		"variable",	"little"],
	["zst",		True,		False,		2,		"raw",		"fixed",	"little"]
]

format_aliases = [
#	Alias		Type Name
	["gba",		"snes"],
	["gbc",		"snes"],
	["md",		"gen"],
	["psx",		"snes"],
	["rgb24",	"act"]
]

# Input type?: True if this format appears in the list of valid input types, False if it does not
# Output type?: True if this format appears in the list of valid output types, False if it does not
# Index Size: Length of each color in the file
# Content Type: "raw" = binary file; "headered-raw" = binary file with a consistent header or footer; "image" = 2-dimensional bitmap; "text" = text-based palette file
# Length Type: "variable" = length differs between multiple files of this type; "fixed" = length is always the same
# Byte Order: Endianness of the file; "big" = most significant byte comes first; "little" = least significant byte comes first

format_names = [
	"Raw 15-bit BGR, Big Endian (32X)",
	"Adobe Color Table (Raw 24-bit RGB)",
	"Adobe Arbitrary Map File (AMP)",
	"16x16 24Bpp Bitmap (BMP)",
	"S-CG-CAD COL File (15-bit BGR)",
	"Raw 9-bit BGR, Big Endian (Mega Drive/Genesis)",
	"Raw 12-bit BGR, Little Endian (Game Gear)",
	"GIMP Palette (GPL) (24-bit RGB)",
	"Genecyst/Kega/Gens MD/Genesis Savestate (GS*)",
	"JASC Palette (24-bit RGB)",
	"Paint.NET 96-color TXT",
	"16x16 256-color PNG",
	"24-bit RGB color (8 bits per channel) PNG",
	"Raw 15-bit RGB, Little Endian (Midway IMG files)",
	"Raw 18-bit RGB, Big Endian",
	"RIFF Palette (24-bit RGB)",
	"Raw 6-bit BGR (Sega Master System)",
	"Raw 15-bit BGR, Little Endian (SNES, PSX, GBC, GBA)",
	"Tile Layer Pro 15-bit BGR (TPL)",
	"Tile Layer Pro 24-bit RGB (TPL)",
	"Raw 12-bit BGR, Little Endian (WonderSwan Color)",
	"ZSNES Savestate (ZS*)"
]

def find_in_list(value_to_search, list_to_search):
	for x in range(0, len(list_to_search)):
		try:
			pos = list_to_search[x].index(value_to_search)
			return [x, pos]
		except:
			continue
	return [False, False]  # whatever one wants to get if value not found

def print_file_type_list(content_type = None, length_type = None):
	file_type_list = "NOTE: The following input/output file types are available:\n"

	for x, value in enumerate(formats):
		if content_type != None and value[4] != content_type:
			continue
		elif length_type != None and value[5] != length_type:
			continue
		elif value[1] == False and value[2] == False:
			continue
		else:
			shortname = value[0] + ":"
			file_type_list += f"  {shortname:<7}{format_names[x]}" 
			file_type_list += " **OUTPUT ONLY**\n" if value[1] == False else " **INPUT ONLY**\n" if value[2] == False else "\n"
	for x, value in enumerate(format_aliases):
		resolved_type_id = find_in_list(value[1], formats)[0]
		short_aliasname = value[0] + ":"
		file_type_list += f"  {short_aliasname:<7}Alias for {formats[resolved_type_id][0]}\n"

	return file_type_list

def build_file_type_choice_list(is_input = None, is_output = None, content_type = None, length_type = None):
	choice_list = []

	for x in formats:
		if content_type != None and x[4] != content_type:
			continue
		elif length_type != None and x[5] != length_type:
			continue
		elif is_input != None and x[1] != is_input:
			continue
		elif is_output != None and x[2] != is_output:
			continue
		else:
			choice_list.append(x[0])

	for x in format_aliases:
		resolved_type_id = find_in_list(x[1], formats)[0]
		resolved_is_input = formats[resolved_type_id][1]
		resolved_is_output = formats[resolved_type_id][2]
		resolved_content_type = formats[resolved_type_id][4]
		resolved_length_type = formats[resolved_type_id][5]

		if content_type != None and resolved_content_type != content_type:
			continue
		elif length_type != None and resolved_length_type != length_type:
			continue
		elif is_input != None and resolved_is_input != is_input:
			continue
		elif is_output != None and resolved_is_output != is_output:
			continue
		else:
			choice_list.append(x[0])

	return choice_list