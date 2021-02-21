typedef uchar BYTE;
typedef ushort USHORT;
typedef wchar_t* PWSTR;
typedef uint DWORD;
typedef ulong ULONG;
typedef void* PVOID;

typedef struct _LIST_ENTRY {
  struct _LIST_ENTRY *Flink;
  struct _LIST_ENTRY *Blink;
} LIST_ENTRY;

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    DWORD DllBase;
    DWORD EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY;

typedef struct {
    BYTE Reserved1[0xc];
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA;

typedef struct {
    BYTE Reserved1[0x2];
    BYTE BeingDebugged;
    BYTE Reserved2[0x5];
    DWORD ImageBaseAddress;
    PEB_LDR_DATA *Ldr;
    BYTE Reserved3[0x94];
    ULONG OSMajorVersion;
    BYTE Reserved4[0x164];
    DWORD FlsCallback;
    BYTE Reserved5[0x1c];
    DWORD FlsHighIndex;
} PEB;

typedef struct _EXCEPTION_REGISTRATION_RECORD
{
  struct _EXCEPTION_REGISTRATION_RECORD *Prev;
  PVOID Handler;
} EXCEPTION_REGISTRATION_RECORD;

typedef struct {
    EXCEPTION_REGISTRATION_RECORD *ExceptionList;
    BYTE Reserved1[0x18];
} NT_TIB;

typedef struct {
    NT_TIB Tib;
    BYTE Reserved1[0x14];
    PEB *ProcessEnvironmentBlock;
} TEB;