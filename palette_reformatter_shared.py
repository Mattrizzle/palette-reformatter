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
	["riff",	True,		True,		4,		"headered-raw",	"fixed",	"big"],	
	["sms",		True,		True,		1,		"raw",		"variable",	"little"],
	["snes",	True,		True,		2,		"raw",		"variable",	"little"],	
	["tpl15",	True,		True,		2,		"headered-raw",	"fixed",	"little"],
	["tpl24",	True,		True,		3,		"headered-raw",	"fixed",	"big"],
	["wsc",		True,		True,		2,		"raw",		"variable",	"little"],
	["zst",		True,		False,		2,		"raw",		"fixed",	"little"]
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
	"Genecyst/Kega/Gens Savestate (GS*)",
	"JASC Palette (24-bit RGB)",
	"Paint.NET 96-color TXT",
	"16x16 256-color PNG",
	"24-bit RGB color (8 bits per channel) PNG",
	"Raw 15-bit RGB, Little Endian (Midway IMG files)",
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

def generate_file_type_list():
	file_type_list = "NOTE: The following input/output file types are available:\n"

	for x, value in enumerate(formats):
		if value[1] == False and value[2] == False:
			continue
		else:
			shortname = value[0] + ":"
			file_type_list += f"  {shortname:<7}{format_names[x]}" 
			file_type_list += " **OUTPUT ONLY**\n" if value[1] == False else " **INPUT ONLY**\n" if value[2] == False else "\n"
	return file_type_list