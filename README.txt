lua-miniz - Lua module for miniz support

This module add deflate/inflate and zip file operations support to Lua
language. some code from luvit's miniz module, thanks for that work!

license:
This module has the same license with Lua (the Lua license here[1]).
note that the modified version of miniz.c has its own license (see miniz.c file).

[1]: https://www.lua.org/license.html

build:

use your fabourite compiler to build lminiz.c and miniz.c, get miniz.dll
or miniz.so

usage:

local miniz = require "miniz"


functions:

miniz.adler32([string[, prev: number]]) -> number
miniz.crc32([string[, prev: number]]) -> number
    calculate adler32 and crc32 checksum for string. without arguments, give a
    initialize checksum.

    local a = miniz.crc32("hello")
    local b = miniz.crc32("world", a)
    -- a is the checksum of "hello", and b is the checksum of "helloworld"

miniz.compress(string[, flags: number]) -> [string]
miniz.decompress(string[, flags: number]) -> [string]
miniz.deflate(string[, flags: number]) -> [string]
miniz.inflate(string[, flags: number]) -> [string]
    compress/decompress string, use given flags.
    deflate will compress a string to zlib-compatible result, and inflate will
    decompress a zlib-compatible result.

    flags for compress/deflate: (from miniz.c)
        The low 12 bits are reserved to control the max # of hash probes per
        dictionary lookup. (default is 128)

        0x1000: If set, the compressor outputs a zlib header before the
                deflate data, and the Adler-32 of the source data at the end.
                Otherwise, you'll get raw deflate data.
        0x2000: Always compute the adler-32 of the input data (even when not
                writing zlib headers).
        0x4000: Set to use faster greedy parsing, instead of more efficient
                lazy parsing.
        0x8000: Enable to decrease the compressor's initialization time to the
                minimum, but the output may vary from run to run given the
                same input (depending on the contents of memory).
        0x10000: Only look for RLE matches (matches with a distance of 1)
        0x20000: Discards matches <= 5 chars if enabled.
        0x40000: Disable usage of optimized Huffman tables.
        0x80000: Only use raw (uncompressed) deflate blocks.

    flags for decompress/inflate: (from miniz.c)
        1: If set, the input has a valid zlib header and ends with an adler32 checksum
           (it's a valid zlib stream). Otherwise, the input is a raw deflate stream.
        2: If set, there are more input bytes available beyond the end of the supplied
           input buffer. If clear, the input buffer contains all remaining input.
        4: If set, the output buffer is large enough to hold the entire decompressed
           stream. If clear, the output buffer is at least the size of the dictionary
           (typically 32KB).
        8: Force adler-32 checksum computation of the decompressed bytes.

miniz.zip_read_file(filename: string[, flags: number]) -> [miniz.ZipReader]
miniz.zip_read_string(content: string[, flags: number]) -> [miniz.ZipReader]
    read a zip from file (given filename) or content string.

    flags: (from miniz.c)
	0x100: case sensitive file name in zip file.
	0x200: ignore path of file in zip.
	0x400: file is compressed data.
	0x800: do not sort central directory in zip file.

miniz.zip_write_file(filename: string[, reserved: number]) -> miniz.ZipWriter
miniz.zip_write_string([reserved: number[, init_size: number]]) -> miniz.ZipWriter
    write files to a zip file or a string.
    reserved is the reserved size before zip file itself. init_size is the
    first allocated memory for write file content. 

#ZipReader -> number
ZipReader:get_num_files() -> number
    get the file count in zip file.

ZipReader[idx:number] -> string
ZipReader:get_filename(idx:number) -> string
    get the idx-th file name in zip file.

ZipReader:close() -> boolean
    close zip file, return success or not.

ZipReader:locate_file(filename: string) -> number
    get the index from file name

ZipReader:stat(idx: number) -> table
    get file information from given index.

    returned table fields:
	index: index of file
	version_made_by: zip version
	version_needed: extract file need version
	bit_flag: flags of file
	method: compress method
	time: file time
	crc32: file crc32 checksum
	comp_size: compressed size
	uncomp_size: uncompressed size
	internal_attr: internal attribute
	external_attr: external attribute
	filename: filename
	comment: comment

ZipReader:is_file_a_directory(idx: number) -> boolean
    return whether given idx of file is a directory.

ZipReader:get_offset() -> number
    get the start offset of zip file in given file/string.

ZipReader:extract(idx: number[, flags: number]) -> [string]
ZipReader:extract(filename: string[, flags: number]) -> [string]
    extract a file from zip. flags see miniz.zip_read_file()

ZipWriter:close() -> boolean
    close a zip file

ZipWriter:add_string(path: string, content: string[, comment: string[, flags: number]]) -> ZipWriter
ZipWriter:add_file(path: string, filename: string[, comment: string[, flags: number]]) -> ZipWriter
    add a file to zip.

ZipWriter:add_from_zip_reader(src: miniz.ZipReader, idx: number) -> ZipWriter
    add a file from zip reader to zip.

ZipWriter:finalize() -> string
ZipWriter:finalize() -> ZipWriter
ZipWriter:finalize() -> nil, string
    finalize the write of zip. if zip writer is created from zip_write_string,
    then the result string is returned; if zip writer is created from
    zip_write_file, then ZipWriter itself is returned, otherwire a nil and a
    error message is returned.

