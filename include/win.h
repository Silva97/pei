#ifndef _WIN_COMPATIBILITY_H
#define _WIN_COMPATIBILITY_H

// For compatibility with MinGW-w64
#ifdef _WIN32

#define __USE_MINGW_ANSI_STDIO 1
#define _CRT_SECURE_NO_WARNINGS

#endif /* _WIN32 */

#endif /* _WIN_COMPATIBILITY_H */
