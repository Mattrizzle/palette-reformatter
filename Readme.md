# Palette Reformatter
A Python command-line based tool to convert between multiple palette formats.

Palette Reformatter currently converts the following file types:
* 32x:   Raw 15-bit BGR, Big Endian (32X)
* act:   Adobe Color Table (RAW 24-bit RGB)
* amp:   Adobe Arbitrary Map File (AMP)
* bmp24: 16x16 24Bpp Bitmap (BMP)
* col:   S-CG-CAD COL File (15-bit BGR)
* gen:   Raw 9-bit BGR, Big Endian (Mega Drive/Genesis)
* gg:    Raw 12-bit BGR, Little Endian (Game Gear)
* gpl:   GIMP Palette (GPL) (24-bit RGB)
* gs0:   Genecyst/Kega/Gens Savestate (GS\*) \*\*INPUT ONLY\*\*
* jasc:  JASC Palette (24-bit RGB)
* pdn:   Paint.NET 96-color TXT
* png8:  16x16 256-color PNG
* png24: 24-bit RGB color (8 bits per channel) PNG
* rgb15: Raw 15-bit RGB, Little Endian (Midway IMG files)
* riff:  RIFF Palette (24-bit RGB)
* sms:   Raw 6-bit BGR (Sega Master System)
* snes:  Raw 15-bit BGR, Little Endian (SNES, PSX, GBC, GBA)
* tpl15: Tile Layer Pro 15-bit BGR (TPL)
* tpl24: Tile Layer Pro 24-bit RGB (TPL)
* wsc:   Raw 12-bit BGR, Little Endian (WonderSwan Color)
* zst:   ZSNES Savestate (ZS\*) \*\*INPUT ONLY\*\*

Tested with Python 3.8.5 on Windows 7.

It is recommended that you add both palette_reformatter.py and palette_reformatter_multi.py to your operating system's PATH variable.

## palette_reformatter.py
This script converts a single file from the specified input type to one or more specified output types.

### Usage:
palette_reformatter \[-h\] \[-n\] \[-c\] \<input file\> \<input type\> \[-a \<input offset\>\] \[-l \<input length\>\] \<output types\> \[\<output types\> ...\] \[-d \<width and height\>\]

### Positional arguments:
  \<input file\>        Source file path.
 
  \<input type\>        Input file type.

  \<output types\>      Output file type(s). Can specify multiple types to write more than one file.

### Optional arguments:
  -h, --help            Show help message and exit.
  
  -n, --noprint         If present, information will not be displayed in the terminal.

  -c, --oldconvmethod   If present, the old conversion method will be used for raw types less than 24-bit.
  
  -a \<input offset\>, --inoffset \<input offset\>
                        Offset of palette to convert in source file. Input offset must not exceed the end of the source file. For GIMP, JASC and Paint.NET palettes (intypes gpl, jasc and pdn), a line number should be specified instead of an offset.

  -l \<input length\>, --inlength \<input length\>
                        Number of palette indices to convert in source file. Input length must not exceed the end of the source file.

  -d \<width and height\>, --outdimensions \<width and height\>
                        Width and height of variable-sized output images.

## palette_reformatter_multi.py
This script searches a directory for files of the specified input type and converts them to one or more specified output types.

### Usage:
palette_reformatter_multi \[-h\] \[-d \<input directory\>\] \<input type\> \[-o \<output types\> \[\<output types\> ...\]\]

### Positional Arguments:
  \<input type\>        Input file type.

### Optional arguments:
  -h, --help            Show help message and exit.

  -d \<input directory\>, --directory \<input directory\>
                        Input directory path. Default is current working directory.

  -o \<output types\> \[\<output types\> ...\], --outtype \<output types\> \[\<output types\> ...\]
                        Output file type(s). Can specify multiple types to
                        write more than one file.
