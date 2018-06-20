#define LUA_LIB
#include <lua.h>
#include <lauxlib.h>

#define MINIZ_NO_ZLIB_APIS
#include "miniz.h"
#include "miniz.c"

#define return_self(L) do { lua_settop(L, 1); return 1; } while (0)

#if LUA_VERSION_NUM < 502
#  define luaL_setfuncs(L,libs,nups) luaL_register(L,NULL,libs)
#  define luaL_newlib(L,libs) (\
        lua_createtable(L, 0, sizeof(libs)/sizeof(libs[0])), \
        luaL_register(L, NULL, libs))
static int lua_relindex(int idx, int onstack) {
    return idx >= 0 || idx <= LUA_REGISTRYINDEX ?
        idx : idx - onstack;
}
static void luaL_setmetatable(lua_State *L, const char *name) {
    luaL_getmetatable(L, name);
    lua_setmetatable(L, -2);
}
static void lua_rawsetp(lua_State *L, int idx, const void *p) {
    lua_pushlightuserdata(L, (void*)p);
    lua_insert(L, -2);
    lua_rawset(L, lua_relindex(idx, 1));
}
static void *luaL_testudata (lua_State *L, int ud, const char *tname) {
    void *p = lua_touserdata(L, ud);
    if (p != NULL) {
        if (lua_getmetatable(L, ud)) {
            luaL_getmetatable(L, tname);
            if (!lua_rawequal(L, -1, -2))
                p = NULL;
            lua_pop(L, 2);
            return p;
        }
    }
    return NULL;
}
static const char *luaL_tolstring (lua_State *L, int idx, size_t *len) {
    if (!luaL_callmeta(L, idx, "__tostring")) {  /* no metafield? */
        switch (lua_type(L, idx)) {
        case LUA_TNUMBER:
        case LUA_TSTRING:
            lua_pushvalue(L, idx);
            break;
        case LUA_TBOOLEAN:
            lua_pushstring(L, (lua_toboolean(L, idx) ? "true" : "false"));
            break;
        case LUA_TNIL:
            lua_pushliteral(L, "nil");
            break;
        default:
            lua_pushfstring(L, "%s: %p", luaL_typename(L, idx),
                    lua_topointer(L, idx));
            break;
        }
    }
    return lua_tolstring(L, -1, len);
}
#endif

static int Ladler32(lua_State *L) {
    size_t len;
    const char *s = luaL_optlstring(L, 1, NULL, &len);
    mz_ulong init;
    if (!lua_isnoneornil(L, 2))
        init = (mz_ulong)luaL_checkinteger(L, 2);
    else
        init = mz_adler32(0, NULL, 0);
    if (s == NULL) {
        lua_pushinteger(L, init);
        return 1;
    }
    lua_pushinteger(L, (lua_Integer)mz_adler32(init, (const unsigned char*)s, len));
    return 1;
}

static int Lcrc32(lua_State *L) {
    size_t len;
    const char *s = luaL_optlstring(L, 1, NULL, &len);
    mz_ulong init;
    if (!lua_isnoneornil(L, 2))
        init = (mz_ulong)luaL_checkinteger(L, 2);
    else
        init = mz_crc32(0, NULL, 0);
    if (s == NULL) {
        lua_pushinteger(L, init);
        return 1;
    }
    lua_pushinteger(L, (lua_Integer)mz_crc32(init, (const unsigned char*)s, len));
    return 1;
}

static int lmz_compress(lua_State *L, int def_flags) {
    size_t len, offset = 0;
    const char *s = luaL_checklstring(L, 1, &len);
    int flags = (int)luaL_optinteger(L, 2, def_flags);
    luaL_Buffer b;
    tdefl_compressor comp;
    mz_uint8 outb[LUAL_BUFFERSIZE];
    luaL_buffinit(L, &b);
    if (tdefl_init(&comp, NULL, NULL, flags) != TDEFL_STATUS_OKAY)
        luaL_error(L, "compress failure");
    for (;;) {
        size_t in_size = len - offset;
        size_t out_size = LUAL_BUFFERSIZE;
        tdefl_status status = tdefl_compress(&comp,
                s + offset, &in_size, outb, &out_size, TDEFL_FINISH);
        offset += in_size;
        if (out_size != 0)
            luaL_addlstring(&b, (char*)outb, out_size);
        if (status == TDEFL_STATUS_DONE) {
            luaL_pushresult(&b);
            break;
        }
        else if (status != TDEFL_STATUS_OKAY)
            luaL_error(L, "compress failure");
    }
    luaL_pushresult(&b);
    return 1;
}

static int lmz_decompress(lua_State *L, int def_flags) {
    size_t len, offset = 0, dict_offset = 0;
    const char *s = luaL_checklstring(L, 1, &len);
    int flags = (int)luaL_optinteger(L, 2, def_flags);
    luaL_Buffer b;
    tinfl_decompressor decomp;
    mz_uint8 dict[TINFL_LZ_DICT_SIZE];
    luaL_buffinit(L, &b);
    tinfl_init(&decomp);
    for (;;) {
        size_t in_size  = len - offset;
        size_t out_size = TINFL_LZ_DICT_SIZE - dict_offset;
        const int flags_mask = ~(TINFL_FLAG_HAS_MORE_INPUT
                               | TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
        tinfl_status status = tinfl_decompress(&decomp,
                (const mz_uint8*)s + offset, &in_size,
                dict, dict + dict_offset, &out_size, flags & flags_mask);
        offset += in_size;
        if (out_size != 0)
            luaL_addlstring(&b, (char*)dict + dict_offset, out_size);
        if (status != TINFL_STATUS_HAS_MORE_OUTPUT) {
            luaL_pushresult(&b);
            if (status != TINFL_STATUS_DONE)
                luaL_error(L, "decompress failure");
            break;
        }
        dict_offset = (dict_offset + out_size) & (TINFL_LZ_DICT_SIZE - 1);
    }
    if (offset != len) {
        lua_pushinteger(L, offset);
        return 2;
    }
    return 1;
}

static int Lcompress(lua_State *L)
{ return lmz_compress(L, TDEFL_DEFAULT_MAX_PROBES); }

static int Ldecompress(lua_State *L)
{ return lmz_decompress(L, 0); }

static int Ldeflate(lua_State *L)
{ return lmz_compress(L, TDEFL_DEFAULT_MAX_PROBES|TDEFL_WRITE_ZLIB_HEADER); }

static int Linflate(lua_State *L)
{ return lmz_decompress(L, TINFL_FLAG_PARSE_ZLIB_HEADER); }

/* zip reader */

#define LMZ_ZIP_READER "miniz.ZipReader"

static int Lzip_read_string(lua_State *L) {
    size_t len;
    const char *s = luaL_checklstring(L, 1, &len);
    mz_uint32 flags = (mz_uint32)luaL_optinteger(L, 2, 0);
    mz_zip_archive *za = lua_newuserdata(L, sizeof(mz_zip_archive));
    memset(za, 0, sizeof(mz_zip_archive));
    if (!mz_zip_reader_init_mem(za, s, len, flags))
        return 0;
    luaL_setmetatable(L, LMZ_ZIP_READER);
    lua_pushvalue(L, 1);
    lua_rawsetp(L, LUA_REGISTRYINDEX, za);
    return 1;
}

static int Lzip_read_file(lua_State *L) {
    const char *filename = luaL_checkstring(L, 1);
    mz_uint32 flags = (mz_uint32)luaL_optinteger(L, 2, 0);
    mz_zip_archive *za = lua_newuserdata(L, sizeof(mz_zip_archive));
    memset(za, 0, sizeof(mz_zip_archive));
    if (!mz_zip_reader_init_file(za, filename, flags))
        return 0;
    luaL_setmetatable(L, LMZ_ZIP_READER);
    return 1;
}

static int Lreader_close(lua_State *L) {
    mz_zip_archive* za = luaL_checkudata(L, 1, LMZ_ZIP_READER);
    lua_pushboolean(L, mz_zip_reader_end(za));
    lua_pushnil(L);
    lua_rawsetp(L, LUA_REGISTRYINDEX, za);
    return 1;
}

static int Lreader___index(lua_State* L) {
    mz_zip_archive *za = luaL_checkudata(L, 1, LMZ_ZIP_READER);
    int type = lua_type(L, 2);
    if (type == LUA_TSTRING) {
        if (lua_getmetatable(L, 1)) {
            lua_pushvalue(L, 2);
            lua_rawget(L, -2);
            return 1;
        }
        return 0;
    }
    else if (type == LUA_TNUMBER) {
        mz_uint file_index = (mz_uint)luaL_checkinteger(L, 2) - 1;
        char filename[MZ_ZIP_MAX_ARCHIVE_FILENAME_SIZE];
        if (!mz_zip_reader_get_filename(za, file_index,
                    filename, MZ_ZIP_MAX_ARCHIVE_FILENAME_SIZE))
            lua_pushnil(L);
        else
            lua_pushstring(L, filename);
        return 1;
    }
    return 0;
}

static int Lreader___tostring(lua_State* L) {
    mz_zip_archive *za = luaL_testudata(L, 1, LMZ_ZIP_READER);
    if (za) lua_pushfstring(L, "miniz.ZipReader: %p", za);
    else luaL_tolstring(L, 1, NULL);
    return 1;
}

static int Lreader_get_num_files(lua_State *L) {
    mz_zip_archive *za = luaL_checkudata(L, 1, LMZ_ZIP_READER);
    lua_pushinteger(L, mz_zip_reader_get_num_files(za));
    return 1;
}

static int Lreader_locate_file(lua_State *L) {
    mz_zip_archive *za = luaL_checkudata(L, 1, LMZ_ZIP_READER);
    const char *path = luaL_checkstring(L, 2);
    mz_uint32 flags = (mz_uint32)luaL_optinteger(L, 3, 0);
    int index = mz_zip_reader_locate_file(za, path, NULL, flags);
    if (index < 0) {
        lua_pushnil(L);
        lua_pushfstring(L, "Can't find file %s.", path);
        return 2;
    }
    lua_pushinteger(L, index + 1);
    return 1;
}

static int Lreader_stat(lua_State* L) {
    mz_zip_archive *za = luaL_checkudata(L, 1, LMZ_ZIP_READER);
    mz_uint file_index = (mz_uint)luaL_checkinteger(L, 2) - 1;
    mz_zip_archive_file_stat stat;
    if (!mz_zip_reader_file_stat(za, file_index, &stat)) {
        lua_pushnil(L);
        lua_pushfstring(L, "%d is an invalid index", file_index);
        return 2;
    }
    lua_newtable(L);
    lua_pushinteger(L, file_index);
    lua_setfield(L, -2, "index");
    lua_pushinteger(L, stat.m_version_made_by);
    lua_setfield(L, -2, "version_made_by");
    lua_pushinteger(L, stat.m_version_needed);
    lua_setfield(L, -2, "version_needed");
    lua_pushinteger(L, stat.m_bit_flag);
    lua_setfield(L, -2, "bit_flag");
    lua_pushinteger(L, stat.m_method);
    lua_setfield(L, -2, "method");
    lua_pushinteger(L, stat.m_time);
    lua_setfield(L, -2, "time");
    lua_pushinteger(L, stat.m_crc32);
    lua_setfield(L, -2, "crc32");
    lua_pushinteger(L, stat.m_comp_size);
    lua_setfield(L, -2, "comp_size");
    lua_pushinteger(L, stat.m_uncomp_size);
    lua_setfield(L, -2, "uncomp_size");
    lua_pushinteger(L, stat.m_internal_attr);
    lua_setfield(L, -2, "internal_attr");
    lua_pushinteger(L, stat.m_external_attr);
    lua_setfield(L, -2, "external_attr");
    lua_pushstring(L, stat.m_filename);
    lua_setfield(L, -2, "filename");
    lua_pushstring(L, stat.m_comment);
    lua_setfield(L, -2, "comment");
    return 1;
}

static int Lreader_get_filename(lua_State* L) {
    mz_zip_archive *za = luaL_checkudata(L, 1, LMZ_ZIP_READER);
    mz_uint file_index = (mz_uint)luaL_checkinteger(L, 2) - 1;
    char filename[MZ_ZIP_MAX_ARCHIVE_FILENAME_SIZE];
    if (!mz_zip_reader_get_filename(za, file_index,
                filename, MZ_ZIP_MAX_ARCHIVE_FILENAME_SIZE)) {
        lua_pushnil(L);
        lua_pushfstring(L, "%d is an invalid index", file_index);
        return 2;
    }
    lua_pushstring(L, filename);
    return 1;
}

static int Lreader_is_file_a_directory(lua_State  *L) {
    mz_zip_archive *za = luaL_checkudata(L, 1, LMZ_ZIP_READER);
    mz_uint file_index = (mz_uint)luaL_checkinteger(L, 2) - 1;
    lua_pushboolean(L, mz_zip_reader_is_file_a_directory(za, file_index));
    return 1;
}

static size_t Lwriter(void *ud, mz_uint64 file_ofs, const void *p, size_t n) {
    (void)file_ofs;
    luaL_addlstring((luaL_Buffer*)ud, p, n);
    return n;
}

static int Lreader_extract(lua_State *L) {
    mz_zip_archive *za = luaL_checkudata(L, 1, LMZ_ZIP_READER);
    mz_uint flags = (mz_uint)luaL_optinteger(L, 3, 0);
    int type = lua_type(L, 2);
    luaL_Buffer b;
    mz_bool result = 0;
    luaL_buffinit(L, &b);
    if (type == LUA_TSTRING)
        result = mz_zip_reader_extract_file_to_callback(za,
                lua_tostring(L, 2),
                Lwriter, &b, flags);
    else if (type == LUA_TNUMBER)
        result = mz_zip_reader_extract_to_callback(za,
                (mz_uint)lua_tointeger(L, 2) - 1,
                Lwriter, &b, flags);
    luaL_pushresult(&b);
    return result ? 1 : 0;
}

static int Lreader_get_offset(lua_State *L) {
    mz_zip_archive *za = luaL_checkudata(L, 1, LMZ_ZIP_READER);
    lua_pushinteger(L, za->m_central_directory_file_ofs);
    return 1;
}

static void open_zipreader(lua_State *L) {
    luaL_Reg libs[] = {
        { "__len", Lreader_get_num_files },
        { "__gc", Lreader_close },
#define ENTRY(name) { #name, Lreader_##name }
        ENTRY(__index),
        ENTRY(__tostring),
        ENTRY(close),
        ENTRY(get_num_files),
        ENTRY(locate_file),
        ENTRY(stat),
        ENTRY(get_filename),
        ENTRY(is_file_a_directory),
        ENTRY(extract),
        ENTRY(get_offset),
#undef  ENTRY
        { NULL, NULL }
    };
    if (luaL_newmetatable(L, LMZ_ZIP_READER))
        luaL_setfuncs(L, libs, 0);
}

/* zip writer */

#define LMZ_ZIP_WRITER "miniz.ZipWriter"

typedef struct lmz_zip_archive {
    mz_zip_archive base;
    int has_heap;
} lmz_zip_archive;

static int Lwriter___tostring(lua_State* L) {
    mz_zip_archive *za = luaL_testudata(L, 1, LMZ_ZIP_WRITER);
    if (za) lua_pushfstring(L, "miniz.ZipWriter: %p", za);
    else luaL_tolstring(L, 1, NULL);
    return 1;
}

static int Lzip_write_string(lua_State *L) {
    size_t size_to_reserve_at_beginning = (size_t)luaL_optinteger(L, 1, 0);
    size_t initial_allocation_size = (size_t)luaL_optinteger(L, 2, LUAL_BUFFERSIZE);
    lmz_zip_archive* za = (lmz_zip_archive*)lua_newuserdata(L, sizeof(lmz_zip_archive));
    memset(za, 0, sizeof(lmz_zip_archive));
    za->has_heap = 1;
    if (!mz_zip_writer_init_heap(&za->base,
                size_to_reserve_at_beginning, initial_allocation_size))
        return 0;
    luaL_setmetatable(L, LMZ_ZIP_WRITER);
    return 1;
}

static int Lzip_write_file(lua_State *L) {
    const char *filename = luaL_checkstring(L, 1);
    size_t size_to_reserve_at_beginning = (size_t)luaL_optinteger(L, 2, 0);
    lmz_zip_archive* za = (lmz_zip_archive*)lua_newuserdata(L, sizeof(lmz_zip_archive));
    memset(za, 0, sizeof(lmz_zip_archive));
    if (!mz_zip_writer_init_file(&za->base, filename, size_to_reserve_at_beginning))
        return 0;
    luaL_setmetatable(L, LMZ_ZIP_WRITER);
    return 1;
}

static int Lwriter_close(lua_State *L) {
    mz_zip_archive *za = luaL_checkudata(L, 1, LMZ_ZIP_WRITER);
    lua_pushboolean(L, mz_zip_writer_end(za));
    return 1;
}

static int Lwriter_add_from_zip_reader(lua_State *L) {
    mz_zip_archive *za = luaL_checkudata(L, 1, LMZ_ZIP_WRITER);
    mz_zip_archive *src = luaL_checkudata(L, 2, LMZ_ZIP_READER);
    mz_uint file_index = (mz_uint)luaL_checkinteger(L, 3) - 1;
    if (!mz_zip_writer_add_from_zip_reader(za, src, file_index)) {
        lua_pushnil(L);
        lua_pushstring(L, "Failure to copy file between zips");
        return 2;
    }
    return_self(L);
}

static int Lwriter_add_string(lua_State *L) {
    mz_zip_archive *za = luaL_checkudata(L, 1, LMZ_ZIP_WRITER);
    const char* path = luaL_checkstring(L, 2);
    size_t len, comment_len;
    const char* s = luaL_checklstring(L, 3, &len);
    const char *comment =luaL_optlstring(L, 5, NULL, &comment_len);
    mz_uint flags = (mz_uint)luaL_optinteger(L, 4, MZ_DEFAULT_LEVEL);
    if (!mz_zip_writer_add_mem_ex(za, path, s, len,
            comment, (mz_uint16)comment_len, flags, 0, 0)) {
        lua_pushnil(L);
        lua_pushstring(L, "Failure to add entry to zip");
        return 2;
    }
    return_self(L);
}

static int Lwriter_add_file(lua_State *L) {
    mz_zip_archive *za = luaL_checkudata(L, 1, LMZ_ZIP_WRITER);
    const char* path = luaL_checkstring(L, 2);
    const char* filename = luaL_optstring(L, 3, path);
    mz_uint flags = (mz_uint)luaL_optinteger(L, 4, MZ_DEFAULT_LEVEL);
    size_t len;
    const char *comment =luaL_optlstring(L, 5, NULL, &len);
    if (!mz_zip_writer_add_file(za, path, filename, comment, (mz_uint16)len, flags)) {
        lua_pushnil(L);
        lua_pushstring(L, "Failure to add entry to zip");
        return 2;
    }
    return_self(L);
}

static int Lwriter_finalize(lua_State *L) {
    lmz_zip_archive *za = (lmz_zip_archive*)luaL_checkudata(L, 1, LMZ_ZIP_WRITER);
    if (za->has_heap) {
        size_t len = 0;
        void* s = NULL;
        mz_bool result = mz_zip_writer_finalize_heap_archive(&za->base, &s, &len);
        lua_pushlstring(L, s, len);
        free(s);
        if (!result) {
            lua_pushstring(L, "Problem finalizing archive");
            return 2;
        }
        return 1;
    }
    if (!mz_zip_writer_finalize_archive(&za->base)) {
        lua_pushnil(L);
        lua_pushstring(L, "Problem finalizing archive");
        return 2;
    }
    return_self(L);
}

static void open_zipwriter(lua_State *L) {
    luaL_Reg libs[] = {
        { "__gc", Lwriter_close },
#define ENTRY(name) { #name, Lwriter_##name }
        ENTRY(__tostring),
        ENTRY(close),
        ENTRY(add_from_zip_reader),
        ENTRY(add_string),
        ENTRY(add_file),
        ENTRY(finalize),
#undef  ENTRY
        { NULL, NULL }
    };
    if (luaL_newmetatable(L, LMZ_ZIP_WRITER)) {
        luaL_setfuncs(L, libs, 0);
        lua_pushvalue(L, -1);
        lua_setfield(L, -2, "__index");
    }
}

LUAMOD_API int luaopen_miniz(lua_State *L) {
    luaL_Reg libs[] = {
        { "new_reader", Lzip_read_file },
        { "new_writer", Lzip_write_string },
#define ENTRY(name) { #name, L##name }
        ENTRY(adler32),
        ENTRY(crc32),
        ENTRY(compress),
        ENTRY(decompress),
        ENTRY(inflate),
        ENTRY(deflate),
        ENTRY(zip_read_file),
        ENTRY(zip_read_string),
        ENTRY(zip_write_file),
        ENTRY(zip_write_string),
#undef  ENTRY
        { NULL, NULL }
    };
    open_zipreader(L);
    open_zipwriter(L);
    luaL_newlib(L, libs);
    return 1;
}

/* win32cc: flags+='-s -O3 -mdll -DLUA_BUILD_AS_DLL -fno-strict-aliasing'
 * win32cc: libs+='-llua53' output='miniz.dll'
 * maccc: flags+='-O3 -shared -undefined dynamic_lookup' output='miniz.so' */

