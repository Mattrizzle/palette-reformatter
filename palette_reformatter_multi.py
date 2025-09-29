import palette_reformatter_shared as palrfs
import os
import argparse
import subprocess
import re

multi_parser = argparse.ArgumentParser(prog="palette_reformatter_multi", formatter_class=argparse.RawDescriptionHelpFormatter, description="Multiple-File Palette Reformatter\nBy Mattrizzle - https://github.com/Mattrizzle/palette-reformatter\nThis script searches a directory for files of the specified input type and \nconverts them to one or more specified output types.", epilog=palrfs.generate_file_type_list())
multi_parser.add_argument("-d", "--directory", metavar="<input directory>", default=os.getcwd().replace("\\", "/"), help="Input directory path. Default is current working directory.")
multi_parser.add_argument("intype", metavar="<input type>", choices=[ x[0] for x in palrfs.formats if x[1] == True ], help="Input file type. (See NOTE below)")
multi_parser.add_argument("-o", "--outtype", metavar="<output types>", nargs="+", choices=[ x[0] for x in palrfs.formats if x[2] == True ], help="Output file type(s). Can specify multiple types to write more than one file. (See NOTE below)")

multi_args = multi_parser.parse_args()

multi_format_syntaxes = [
	"(?i)-32X\.bin",
	"(?i)\.act",
	"(?i)\.amp",
	"(?i)(-RGB24){0,1}\.bmp",
	"(?i)\.COL",
	"(?i)-GEN\.bin",
	"(?i)-GG\.bin",
	"(?i)\.gpl",
	"(?i)\.gs[0-9x]",
	"(?i)(-JASC){0,1}\.pal",
	"(?i)(-PDN){0,1}\.txt",
	"(?i)(-RGB8){0,1}\.png",
	"(?i)(-RGB24){0,1}\.png",
	"(?i)-RGB15\.bin",
	"(?i)(-RIFF){0,1}\.pal",
	"(?i)-SMS\.bin",
	"(?i)-SNES\.pal",
	"(?i)(-BGR15){0,1}\.tpl",
	"(?i)(-RGB24){0,1}\.tpl",
	"(?i)-WSC\.bin",
	"(?i)\.z[1-9s][0-9t]"
]

intype_id = palrfs.find_in_list(args.intype, palrfs.formats)[0]

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
	print("\r\nConverting occurrence " + str(x+1) + " of " + str(occurrences) + " of type " + multi_args.intype + " in directory\r\n" + multi_args.directory + ":")
	subprocess.run("python \"" + os.path.dirname(__file__).replace("\\", "/") + "/palette_reformatter.py\" \"" + multi_filename + "\" " + multi_args.intype + outtypes_string)
else:
  	print("Done!")