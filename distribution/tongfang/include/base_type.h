
#ifndef __BASE_TYPE_DEF_H__
#define __BASE_TYPE_DEF_H__ 1

#ifdef _WIN32

#ifdef WINCE
#define WINVER _WIN32_WCE
#else
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#endif

//#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifndef HDEV_DEF
typedef HANDLE	HDEV;
#endif

#else /* linux */

typedef int		HDEV;
typedef void*	HANDLE;

#define _GNU_SOURCE
#define __USE_GNU

#endif

#ifndef FALSE
#define FALSE               0
#endif

#ifndef TRUE
#define TRUE                1
#endif
typedef unsigned char	u8;
typedef unsigned short	u16;
typedef unsigned long	u32;

typedef char CHAR;
typedef short SHORT;
typedef long LONG;
typedef unsigned long ULONG;

typedef unsigned long       DWORD;
typedef int                 BOOL;
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef float               FLOAT;
typedef int                 INT;
typedef unsigned int        UINT;
typedef char INT8;
typedef short int INT16;
typedef int INT32;
typedef unsigned char UINT8;
typedef unsigned short UINT16;
typedef unsigned int UINT32;
typedef int BOOL;
typedef UINT8 BYTE;

#include <xchar.h>

#endif /* __BASE_TYPE_DEF_H__ */
