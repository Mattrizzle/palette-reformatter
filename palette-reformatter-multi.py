import sys
import os
import argparse
import subprocess
import re

multi_parser = argparse.ArgumentParser(prog="palette-reformatter-multi", formatter_class=argparse.RawDescriptionHelpFormatter, description="Multiple-File Palette Reformatter\nBy Mattrizzle - https://github.com/Mattrizzle/palette-reformatter\nThis script searches a directory for files of the specified input type and \nconverts them to one or more specified output types.", epilog="NOTE: The following input/output file types are available:\n  32x:   Raw 15-bit BGR, Big Endian (32X)\n  act:   Adobe Color Table (Raw 24-bit RGB)\n  amp:   Adobe Arbitrary Map File (AMP)\n  bmp24: 16x16 24Bpp Bitmap (BMP)\n  col:   S-CG-CAD COL File (15-bit BGR)\n  gen:   Raw 9-bit BGR, Big Endian (Mega Drive/Genesis)\n  gpl:   GIMP Palette (GPL) (24-bit RGB)\n  gs0:   Genecyst/Kega/Gens Savestate (GS*) **INPUT ONLY**\n  jasc:  JASC Palette (24-bit RGB)\n  png8:  16x16 256-color PNG **OUTPUT ONLY**\n  rgb15: Raw 15-bit RGB, Little Endian (Midway IMG files)\n  riff:  RIFF Palette (24-bit RGB)\n  snes:  Raw 15-bit BGR, Little Endian (SNES, PSX, GBC, GBA)\n  tpl15: Tile Layer Pro 15-bit BGR (TPL)\n  tpl24: Tile Layer Pro 24-bit RGB (TPL)\n  zst:   ZSNES Savestate (ZS*) **INPUT ONLY**")
multi_parser.add_argument("-d", "--directory", metavar="<input directory>", default=os.getcwd().replace("\\", "/"), help="Input directory path. Default is current working directory.")
multi_parser.add_argument("intype", metavar="<input type>", choices=["32x", "act", "amp", "bmp24", "col", "gen", "gs0", "gpl", "jasc", "rgb15", "riff", "snes", "tpl15", "tpl24", "zst"], help="Input file type. (See NOTE below)")
multi_parser.add_argument("-o", "--outtype", metavar="<output types>", nargs="+", choices=["32x", "act", "amp", "bmp24", "col", "gen", "gpl", "jasc", "png8", "rgb15", "riff", "snes", "tpl15", "tpl24"], default=["32x", "act", "amp", "bmp24", "col", "gen", "gpl", "jasc", "png8", "rgb15", "riff", "snes", "tpl15", "tpl24"], help="Output file type(s). Can specify multiple types to write more than one file. (See NOTE below)")

multi_args = multi_parser.parse_args()

multi_format_shortnames = [
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

multi_format_syntaxes = [
	"(?i)-32X\.bin",
	"(?i)\.act",
	"(?i)\.amp",
	"(?i)(-RGB24){0,1}\.bmp",
	"(?i)\.COL",
	"(?i)-GEN\.bin",
	"(?i)\.gpl",
	"(?i)\.gs[0-9x]",
	"(?i)(-JASC){0,1}\.pal",
	"",
	"(?i)-RGB15\.bin",
	"(?i)(-RIFF){0,1}\.pal",
	"(?i)-SNES\.pal",
	"(?i)(-BGR15){0,1}\.tpl",
	"(?i)(-RGB24){0,1}\.tpl",
	"(?i)\.z[1-9s][0-9t]"
]

intype_id = multi_format_shortnames.index(multi_args.intype)

outtypes_unique = set(multi_args.outtype)
outtypes_unique_list = list(outtypes_unique)
outtypes_unique_list.sort()

outtypes_string = ""

for o in outtypes_unique_list:
	outtypes_string += " " + o

filelist = os.listdir(multi_args.directory)
filteredlist = [s for s in filelist if re.search(multi_format_syntaxes[intype_id], s) != None]
occurrences = len(filteredlist)

for x, multi_filename in enumerate(filteredlist):
	print("\r\nConverting occurrence " + str(x+1) + " of " + str(occurrences) + " of type " + multi_format_shortnames[intype_id] + " in directory\r\n" + multi_args.directory + ":")
	subprocess.run("python \"" + os.path.dirname(__file__).replace("\\", "/") + "/palette-reformatter.py\" \"" + multi_filename + "\" " + multi_args.intype + outtypes_string)
else:
  	print("Done!")