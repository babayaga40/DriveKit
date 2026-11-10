/*  zlib_decomp_stubs.c
 *  Stub definitions for symbols declared in zutil.h that belong to the
 *  deflate/compress side of zlib.  When building only the decompression
 *  engine (inflate + uncompress) we don't compile deflate.c, so these
 *  symbols would be unresolved at link time.  The strings are never
 *  referenced by the inflate path; they exist only to satisfy the linker.
 */
const char deflate_copyright[]  = " deflate 1.x (stub) ";
const char inflate9_copyright[] = " inflate9 1.x (stub) ";
