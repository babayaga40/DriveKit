/* Compile the editor in a separate translation unit to avoid static-name clashes. */
#define main dk_embedded_editor_main
#include "drivekit_asm_editor.c"
