unit MemoryModule;

{ * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
  * Memory DLL loading code
  * ------------------------
  *
  * Original C Code
  * Memory DLL loading code
  * Version 0.0.4
  *
  * Copyright (c) 2004-2015 by Joachim Bauch / mail@joachim-bauch.de
  * http://www.joachim-bauch.de
  *
  * The contents of this file are subject to the Mozilla Public License Version
  * 2.0 (the "License"); you may not use this file except in compliance with
  * the License. You may obtain a copy of the License at
  * http://www.mozilla.org/MPL/
  *
  * Software distributed under the License is distributed on an "AS IS" basis,
  * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
  * for the specific language governing rights and limitations under the
  * License.
  *
  * The Original Code is MemoryModule.c
  *
  * The Initial Developer of the Original Code is Joachim Bauch.
  *
  * Portions created by Joachim Bauch are Copyright (C) 2004-2015
  * Joachim Bauch. All Rights Reserved.
  *
  * ================== MemoryModule "Conversion to Delphi" ==================
  *
  * Copyright (c) 2018 by Fr0sT / https://github.com/Fr0sT-Brutal
  *
  * Initially based on the code by:
  *   Copyright (c) 2005 - 2006 by Martin Offenwanger / coder@dsplayer.de / http://www.dsplayer.de
  *   Carlo Pasolini / cdpasop@hotmail.it / http://pasotech.altervista.org
  *
  * NOTE
  *   This code is Delphi translation of original C code taken from https://github.com/fancycode/MemoryModule
  *     (commit c8dae9 from May 18, 2018).
  *   Resource loading and exe loading, custom functions not implemented yet.
  *   Tested under RAD Studio XE2 and XE6 32/64-bit, Lazarus 32-bit
  * }

interface

// To compile under FPC, Delphi mode must be used
{$IFDEF FPC}
  {$mode delphi}
{$ENDIF}
// For Delphi define CPU64 for x64 arch (FPC-style)
{$IFDEF CPUX64}
  {$DEFINE CPU64}
{$ENDIF}

uses
  Windows;

type
  HMEMORYMODULE = Pointer;
  HMEMORYRSRC = Pointer;
  HCUSTOMMODULE = Pointer;

  TCustomAllocFunc = function(Address: Pointer; Size: SIZE_T; AllocationType: DWORD; Protect: DWORD; UserData: Pointer): Pointer;
  TCustomFreeFunc = function(Address: Pointer; Size: SIZE_T; dwFreeType: DWORD; UserData: Pointer): BOOL;
  TCustomLoadLibraryFunc = function(Filename: LPCSTR; UserData: Pointer): HCUSTOMMODULE;
  TCustomGetProcAddressFunc = function(Module: HCUSTOMMODULE; Name: LPCSTR; UserData: Pointer): FARPROC;
  TCustomFreeLibraryFunc = procedure(Module: HCUSTOMMODULE; UserData: Pointer);

  { ++++++++++++++++++++++++++++++++++++++++++++++++++
    ***  Memory DLL loading functions Declaration  ***
    -------------------------------------------------- }

// return value is nil if function fails
function MemoryLoadLibary(Data: Pointer; Size: SIZE_T): HMEMORYMODULE;
// return value is nil if function fails
function MemoryLoadLibaryEx(Data: Pointer; Size: SIZE_T;
                            AllocMemory: TCustomAllocFunc;
                            FreeMemory: TCustomFreeFunc;
                            LoadLibrary: TCustomLoadLibraryFunc;
                            GetProcAddress: TCustomGetProcAddressFunc;
                            FreeLibrary: TCustomFreeLibraryFunc;
                            UserData: Pointer): HMEMORYMODULE;
// return value is nil if function fails
function MemoryGetProcAddress(Modul: HMEMORYMODULE; Name: LPCSTR): FARPROC;
// free Module
procedure MemoryFreeLibrary(Modul: HMEMORYMODULE);

implementation

  { ++++++++++++++++++++++++++++++++++++++++
    ***  Missing Windows API Definitions ***
    ---------------------------------------- }
  {$IF NOT DECLARED(IMAGE_BASE_RELOCATION)}
  type
  {$ALIGN 4}
  IMAGE_BASE_RELOCATION = record
    VirtualAddress: DWORD;
    SizeOfBlock: DWORD;
  end;
  {$ALIGN ON}
  PIMAGE_BASE_RELOCATION = ^IMAGE_BASE_RELOCATION;
  {$IFEND}

  // Types that are declared in Pascal-style (ex.: PImageOptionalHeader); redeclaring them in C-style

  {$IF NOT DECLARED(PIMAGE_DATA_DIRECTORY)}
  type PIMAGE_DATA_DIRECTORY = PImageDataDirectory;
  {$IFEND}

  {$IF NOT DECLARED(PIMAGE_SECTION_HEADER)}
  type PIMAGE_SECTION_HEADER = PImageSectionHeader;
  {$IFEND}

  {$IF NOT DECLARED(PIMAGE_EXPORT_DIRECTORY)}
  type PIMAGE_EXPORT_DIRECTORY = PImageExportDirectory;
  {$IFEND}

  {$IF NOT DECLARED(PIMAGE_DOS_HEADER)}
  type PIMAGE_DOS_HEADER = PImageDosHeader;
  {$IFEND}

  {$IF NOT DECLARED(PIMAGE_NT_HEADERS)}
  type PIMAGE_NT_HEADERS = PImageNtHeaders;
  {$IFEND}

  {$IF NOT DECLARED(PUINT_PTR)}
  type PUINT_PTR = ^UINT_PTR;
  {$IFEND}

// Missing constants
const
  IMAGE_REL_BASED_ABSOLUTE = 0;
  IMAGE_REL_BASED_HIGHLOW = 3;
  IMAGE_REL_BASED_DIR64 = 10;

// Things that are incorrectly defined at least up to XE6 (miss x64 mapping)
{$IFDEF CPU64}
type
  PIMAGE_TLS_DIRECTORY = PIMAGE_TLS_DIRECTORY64;
const
  IMAGE_ORDINAL_FLAG = IMAGE_ORDINAL_FLAG64;
{$ENDIF}

{ +++++++++++++++++++++++++++++++++++++++++++++++
  ***  Internal MemoryModule Const Definition  ***
  ----------------------------------------------- }
const
  IMAGE_SIZEOF_BASE_RELOCATION = SizeOf(IMAGE_BASE_RELOCATION);
  {$IFDEF CPU64}
  HOST_MACHINE = IMAGE_FILE_MACHINE_AMD64;
  {$ELSE}
  HOST_MACHINE = IMAGE_FILE_MACHINE_I386;
  {$ENDIF}

type
{ +++++++++++++++++++++++++++++++++++++++++++++++
  ***  Internal MemoryModule Type Definition  ***
  ----------------------------------------------- }
  TExportNameEntry = record
    Name: LPCSTR;
    Idx: Word;
  end;
  PExportNameEntry = ^TExportNameEntry;

  TDllEntryProc = function(hinstDLL: HINST; fdwReason: DWORD; lpReserved: Pointer): BOOL; stdcall;
  TExeEntryProc = function: Integer; stdcall;

  {$IFDEF CPU64}
  PPOINTER_LIST = ^POINTER_LIST;
  POINTER_LIST = record
    Next: PPOINTER_LIST;
    Address: Pointer;
  end;
  {$ENDIF}

  MEMORYMODULEREC = record
    Headers: PIMAGE_NT_HEADERS;
    CodeBase: Pointer;
    Modules: array of HCUSTOMMODULE;
    NumModules: Integer;
    Initialized: Boolean;
    IsDLL: Boolean;
    IsRelocated: Boolean;
    Alloc: TCustomAllocFunc;
    Free: TCustomFreeFunc;
    LoadLibrary: TCustomLoadLibraryFunc;
    GetProcAddress: TCustomGetProcAddressFunc;
    FreeLibrary: TCustomFreeLibraryFunc;
    NameExportsTable: PExportNameEntry;
    UserData: Pointer;
    ExeEntry: TExeEntryProc;
    PageSize: DWORD;
    {$IFDEF CPU64}
    BlockedMemory: PPOINTER_LIST;
    {$ENDIF}
  end;
  PMEMORYMODULE = ^MEMORYMODULEREC;

  SECTIONFINALIZEDATA = record
    Address: Pointer;
    AlignedAddress: Pointer;
    Size: SIZE_T;
    Characteristics: DWORD;
    Last: Boolean;
  end;
  PSECTIONFINALIZEDATA = ^SECTIONFINALIZEDATA;

// Explicitly export these functions to allow hooking of their origins
{}{
function GetProcAddress_Internal(hModule: HMODULE; lpProcName: LPCSTR): FARPROC; stdcall; external kernel32 name 'GetProcAddress';
function LoadLibraryA_Internal(lpLibFileName: LPCSTR): HMODULE; stdcall; external kernel32 name 'LoadLibraryA';
function FreeLibrary_Internal(hLibModule: HMODULE): BOOL; stdcall; external kernel32 name 'FreeLibrary';
   }

  { +++++++++++++++++++++++++++++++++++++++++++++++++++++
    ***                Missing WinAPI macros          ***
    ----------------------------------------------------- }

{$IF NOT DECLARED(IMAGE_ORDINAL)}
//  #define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
//  #define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)
function IMAGE_ORDINAL(Ordinal: NativeUInt): Word; inline;
begin
  Result := Ordinal and $FFFF;
end;
{$IFEND}

{$IF NOT DECLARED(IMAGE_SNAP_BY_ORDINAL)}
//  IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
//  IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)
function IMAGE_SNAP_BY_ORDINAL(Ordinal: NativeUInt): Boolean; inline;
begin
  Result := ((Ordinal and IMAGE_ORDINAL_FLAG) <> 0);
end;
{$IFEND}

  { +++++++++++++++++++++++++++++++++++++++++++++++++++++
    ***               Local SysUtils copy             ***
    ----------------------------------------------------- }

type TSysCharSet = set of AnsiChar;
  
function StrComp(const Str1, Str2: PAnsiChar): Integer;
var
  P1, P2: PAnsiChar;
begin
  P1 := Str1;
  P2 := Str2;
  while True do
  begin
    if (P1^ <> P2^) or (P1^ = #0) then
      Exit(Ord(P1^) - Ord(P2^));
    Inc(P1);
    Inc(P2);
  end;
end;

function CharInSet(C: WideChar; const CharSet: TSysCharSet): Boolean;
begin
  Result := (Ord(C) < $7F) and (AnsiChar(C) in CharSet);
end;

function SysErrorMessage(ErrorCode: Cardinal): string;
var
  Buffer: PChar;
  Len: Integer;
begin
  { Obtain the formatted message for the given Win32 ErrorCode
    Let the OS initialize the Buffer variable. Need to LocalFree it afterward.
  }
  Len := FormatMessage(
    FORMAT_MESSAGE_FROM_SYSTEM or
    FORMAT_MESSAGE_IGNORE_INSERTS or
    FORMAT_MESSAGE_ARGUMENT_ARRAY or
    FORMAT_MESSAGE_ALLOCATE_BUFFER, nil, ErrorCode, 0, @Buffer, 0, nil);

  try
    { Remove the undesired line breaks and '.' char }
    while (Len > 0) and (CharInSet(Buffer[Len - 1], [#0..#32, '.'])) do Dec(Len);
    { Convert to Delphi string }
    SetString(Result, Buffer, Len);
  finally
    { Free the OS allocated memory block }
    LocalFree(HLOCAL(Buffer));
  end;
end;

  { +++++++++++++++++++++++++++++++++++++++++++++++++++++
    ***                 Helper functions              ***
    ----------------------------------------------------- }

procedure UNREFERENCED_PARAMETER(var X);
begin
end;                   

function GET_HEADER_DICTIONARY(Module: PMemoryModule; Idx: Integer): PIMAGE_DATA_DIRECTORY; inline;
begin
  Result := PIMAGE_DATA_DIRECTORY(@(Module.Headers.OptionalHeader.DataDirectory[Idx]));
end;

function AlignValueDown(Address: UINT_PTR; Alignment: UINT_PTR): UINT_PTR; inline;
begin
  Result := Address and not (Alignment - 1);
end;

function AlignAddressDown(Address: Pointer; Alignment: UINT_PTR): Pointer; inline;
begin
  Result := Pointer(AlignValueDown(UINT_PTR(Address), Alignment));
end;

function AlignValueUp(Value: SIZE_T; Alignment: SIZE_T): SIZE_T; inline;
begin
  Result := (Value + Alignment - 1) and not (Alignment - 1);
end;

function OffsetPointer(Data: Pointer; Offset: UINT_PTR): Pointer; inline;
begin
  Result := Pointer(UINT_PTR(Data) + Offset);
end;

procedure OutputLastError(const Msg: string);
begin
  {$IFNDEF DEBUG}
    UNREFERENCED_PARAMETER(Msg);
  {$ELSE}  
    OutputDebugString(PChar(SysErrorMessage(GetLastError)));
  {$ENDIF}
end;

{$IFDEF CPU64}
procedure FreePointerList(Head: PPOINTER_LIST; FreeMemory: TCustomFreeFunc; UserData: Pointer);
var Node, Next: PPOINTER_LIST;
begin
  Node := Head;
  while Node <> nil do
  begin
    FreeMemory(Head.Address, 0, MEM_RELEASE, UserData);
    Next := Node.Next;
    Dispose(Node);
    Node := Next;
  end;
end;
{$ENDIF}

function CheckSize(Size: SIZE_T; Expected: SIZE_T): Boolean;
begin
  if Size < Expected then
  begin
    SetLastError(ERROR_INVALID_DATA);
    Exit(False);
  end;
  Exit(True);
end;

function CopySections(Data: Pointer; Size: SIZE_T; Old_headers: PIMAGE_NT_HEADERS; Module: PMEMORYMODULE): Boolean;
var
  i, Section_Size: Integer;
  CodeBase: Pointer;
  Dest: Pointer;
  Section: PIMAGE_SECTION_HEADER;
begin
  CodeBase := Module.CodeBase;
  Section := PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(Module.Headers{$IFNDEF FPC}^{$ENDIF}));
  for i := 0 to Module.Headers.FileHeader.NumberOfSections - 1 do
  begin
    // Section doesn't contain data in the dll itself, but may define
    // uninitialized Data
    if Section.SizeOfRawData = 0 then
    begin
      Section_Size := Old_headers.OptionalHeader.SectionAlignment;
      if Section_Size > 0 then
      begin
        Dest := Module.Alloc(PByte(CodeBase) + Section.VirtualAddress,
          Section_Size,
          MEM_COMMIT,
          PAGE_READWRITE,
          Module.UserData);
        if Dest = nil then
          Exit(False);
        // Always use position from file to support alignments smaller
        // than page size.
        Dest := PByte(CodeBase) + Section.VirtualAddress;
        // NOTE: On 64bit systems we truncate to 32bit here but expand
        // again later when "PhysicalAddress" is used.
        Section.Misc.PhysicalAddress := DWORD(UINT_PTR(Dest) and $ffffffff);
        ZeroMemory(Dest, Section_Size);
      end;
      // Section is empty
      Inc(Section);
      Continue;
    end; // if

    if not CheckSize(Size, UINT_PTR(Section.PointerToRawData) + Section.SizeOfRawData) then
      Exit(False);

    // commit memory block and copy Data from dll
    Dest := Module.Alloc(PByte(CodeBase) + Section.VirtualAddress,
      Section.SizeOfRawData,
      MEM_COMMIT,
      PAGE_READWRITE,
      Module.UserData);
    if Dest = nil then
      Exit(False);

    // Always use position from file to support alignments smaller
    // than page size (allocation above will align to page size).
    Dest := PByte(CodeBase) + Section.VirtualAddress;
    CopyMemory(Dest, PByte(Data) + Section.PointerToRawData, Section.SizeOfRawData);
    // NOTE: On 64bit systems we truncate to 32bit here but expand
    // again later when "PhysicalAddress" is used.
    Section.Misc.PhysicalAddress := DWORD(UINT_PTR(Dest) and $ffffffff);
    Inc(Section);
  end; // for

  Result := True;
end;

// Protection flags for memory pages (Executable, Readable, Writeable)
const
  ProtectionFlags: array[Boolean, Boolean, Boolean] of DWORD =
  (
    (
        // not executable
        (PAGE_NOACCESS, PAGE_WRITECOPY),
        (PAGE_READONLY, PAGE_READWRITE)
    ),
    (
        // executable
        (PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY),
        (PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE)
    )
);

function GetRealSectionSize(Module: PMEMORYMODULE; Section: PIMAGE_SECTION_HEADER): SIZE_T;
var Size: DWORD;
begin
  Size := Section.SizeOfRawData;
  if Size = 0 then
    if (Section.Characteristics and IMAGE_SCN_CNT_INITIALIZED_DATA) <> 0 then
      Size := Module.Headers.OptionalHeader.SizeOfInitializedData
    else if (Section.Characteristics and IMAGE_SCN_CNT_UNINITIALIZED_DATA) <> 0 then
      Size := Module.Headers.OptionalHeader.SizeOfUninitializedData;
  Result := SIZE_T(Size);
end;

function FinalizeSection(Module: PMEMORYMODULE; const SectionData: SECTIONFINALIZEDATA): Boolean;
var
  Protect, OldProtect: DWORD;
  Executable, Readable, Writeable: Boolean;
begin
  if SectionData.Size = 0 then
    Exit(True);

  if (SectionData.Characteristics and IMAGE_SCN_MEM_DISCARDABLE) <> 0 then
  begin
    // Section is not needed any more and can safely be freed
    if (SectionData.Address = SectionData.AlignedAddress) and
       ( SectionData.Last or
         (Module.Headers.OptionalHeader.SectionAlignment = Module.PageSize) or
         (SectionData.Size mod Module.PageSize = 0)
       ) then
         // Only allowed to decommit whole pages
         Module.Free(SectionData.Address, SectionData.Size, MEM_DECOMMIT, Module.UserData);
    Exit(True);
  end;

  // determine protection flags based on Characteristics
  Executable := (SectionData.Characteristics and IMAGE_SCN_MEM_EXECUTE) <> 0;
  Readable   := (SectionData.Characteristics and IMAGE_SCN_MEM_READ) <> 0;
  Writeable  := (SectionData.Characteristics and IMAGE_SCN_MEM_WRITE) <> 0;
  Protect := ProtectionFlags[Executable][Readable][Writeable];
  if (SectionData.Characteristics and IMAGE_SCN_MEM_NOT_CACHED) <> 0 then
    Protect := Protect or PAGE_NOCACHE;

  // change memory access flags
  Result := VirtualProtect(SectionData.Address, SectionData.Size, Protect, OldProtect);
  if not Result then
    OutputLastError('Error protecting memory page');
end;

function FinalizeSections(Module: PMEMORYMODULE): Boolean;
var
  i: Integer;
  Section: PIMAGE_SECTION_HEADER;
  ImageOffset: UIntPtr;
  SectionData: SECTIONFINALIZEDATA;
  SectionAddress, AlignedAddress: Pointer;
  SectionSize: DWORD;
begin
  Section := PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(Module.Headers{$IFNDEF FPC}^{$ENDIF}));
  {$IFDEF CPU64}
  // "PhysicalAddress" might have been truncated to 32bit above, expand to
  // 64bits again.
  ImageOffset := UIntPtr(Module.Headers.OptionalHeader.ImageBase) and $ffffffff00000000;
  {$ELSE}
  ImageOffset := 0;
  {$ENDIF}

  SectionData.Address := Pointer(UIntPtr(Section.Misc.PhysicalAddress) or ImageOffset);
  SectionData.AlignedAddress := AlignAddressDown(SectionData.Address, Module.PageSize);
  SectionData.Size := GetRealSectionSize(Module, Section);
  SectionData.Characteristics := Section.Characteristics;
  SectionData.Last := False;
  Inc(Section);

  // loop through all sections and change access flags
  for i := 1 to Module.Headers.FileHeader.NumberOfSections - 1 do
  begin
    SectionAddress := Pointer(UIntPtr(Section.Misc.PhysicalAddress) or ImageOffset);
    AlignedAddress := AlignAddressDown(SectionData.Address, Module.PageSize);
    SectionSize := GetRealSectionSize(Module, Section);
    // Combine access flags of all sections that share a page
    // TODO(fancycode): We currently share flags of a trailing large section
    //   with the page of a first small section. This should be optimized.
    if (SectionData.AlignedAddress = AlignedAddress) or
       (UIntPtr(SectionData.Address) + SectionData.Size > UIntPtr(AlignedAddress)) then
    begin
      // Section shares page with previous
      if (Section.Characteristics and IMAGE_SCN_MEM_DISCARDABLE = 0) or
         (SectionData.Characteristics and IMAGE_SCN_MEM_DISCARDABLE = 0) then
        SectionData.Characteristics := (SectionData.Characteristics or Section.Characteristics) and not IMAGE_SCN_MEM_DISCARDABLE
      else
        SectionData.Characteristics := SectionData.Characteristics or Section.Characteristics;
      SectionData.Size := UIntPtr(SectionAddress) + UIntPtr(SectionSize) - UIntPtr(SectionData.Address);
      Inc(Section);
      Continue;
    end;

    if not FinalizeSection(Module, SectionData) then
      Exit(False);

    SectionData.Address := SectionAddress;
    SectionData.AlignedAddress := AlignedAddress;
    SectionData.Size := SectionSize;
    SectionData.Characteristics := Section.Characteristics;

    Inc(Section);
  end; // for

  SectionData.Last := True;
  if not FinalizeSection(Module, SectionData) then
    Exit(False);

  Result := True;
end;

function ExecuteTLS(Module: PMEMORYMODULE): Boolean;
var
  CodeBase: Pointer;
  Tls: PIMAGE_TLS_DIRECTORY;
  Callback: PPointer; // =^PIMAGE_TLS_CALLBACK; see note below
  Directory: PIMAGE_DATA_DIRECTORY;

  // Tls Callback pointers are VA's (ImageBase included) so if the module resides at
  // the other ImageBage they become invalid. This routine relocates them to the
  // actual ImageBase.
  // The case seem to happen with DLLs only and they rarely use Tls callbacks.
  // Moreover, they probably don't work at all when using DLL dynamically which is
  // the case in our code.
  //https://github.com/fancycode/MemoryModule/issues/31
  //https://github.com/DarthTon/Blackbone/blob/master/src/BlackBone/PE/PEImage.cpp  PEImage::GetTLSCallbacks
  {}function FixPtr(OldPtr: Pointer): Pointer;
  begin
    Result := OldPtr;  //Pointer(NativeInt(OldPtr) - Module.Headers.OptionalHeader.ImageBase + NativeInt(CodeBase));
  end;

begin
  Result := True;
  CodeBase := Module.CodeBase;

  Directory := GET_HEADER_DICTIONARY(Module, IMAGE_DIRECTORY_ENTRY_TLS);
  if Directory.VirtualAddress = 0 then
    Exit;

  Tls := PIMAGE_TLS_DIRECTORY(PByte(CodeBase) + Directory.VirtualAddress);
  // Delphi syntax is quite awkward when dealing with proc pointers so we have to
  // use casts to untyped pointers
  Callback := Pointer(Tls.AddressOfCallBacks);
  if Callback <> nil then
  begin
    Callback := FixPtr(Callback);
    while Callback^ <> nil do
    begin
      PIMAGE_TLS_CALLBACK(FixPtr(Callback^))(CodeBase, DLL_PROCESS_ATTACH, nil);
      Inc(Callback);
    end;
  end;
end;

function PerformBaseRelocation(Module: PMEMORYMODULE; Delta: NativeInt): Boolean;
var
  i: DWORD;
  CodeBase: Pointer;
  Directory: PIMAGE_DATA_DIRECTORY;
  Relocation: PIMAGE_BASE_RELOCATION;
  Dest: Pointer;
  RelInfo: ^USHORT;
  PatchAddrHL: PDWORD;
  {$IFDEF CPU64}
  PatchAddr64: PULONGLONG;
  {$ENDIF}
  RelType, Offset: Integer;
begin
  CodeBase := Module.CodeBase;
  Directory := GET_HEADER_DICTIONARY(Module, IMAGE_DIRECTORY_ENTRY_BASERELOC);
  if Directory.Size = 0 then
    Exit(Delta = 0);

  Relocation := PIMAGE_BASE_RELOCATION(PByte(CodeBase) + Directory.VirtualAddress);
  while Relocation.VirtualAddress > 0 do
  begin
    Dest := PByte(CodeBase) + Relocation.VirtualAddress;
    RelInfo := OffsetPointer(Relocation, IMAGE_SIZEOF_BASE_RELOCATION);
    for i := 0 to Trunc(((Relocation.SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / 2)) - 1 do
    begin
      // the upper 4 bits define the type of Relocation
      RelType := RelInfo^ shr 12;
      // the lower 12 bits define the Offset
      Offset := RelInfo^ and $FFF;

      case RelType of
        IMAGE_REL_BASED_ABSOLUTE:
          // skip Relocation
          ;
        IMAGE_REL_BASED_HIGHLOW:
          begin
            // change complete 32 bit address
            PatchAddrHL := Pointer(PByte(Dest) + Offset);
            Inc(PatchAddrHL^, Delta);
          end;

        {$IFDEF CPU64}
        IMAGE_REL_BASED_DIR64:
          begin
            PatchAddr64 := Pointer(PByte(Dest) + Offset);
            Inc(PatchAddr64^, Delta);
          end;
        {$ENDIF}
      end;

      Inc(RelInfo);
    end; // for

    // advance to next Relocation block
    Relocation := PIMAGE_BASE_RELOCATION(OffsetPointer(Relocation, Relocation.SizeOfBlock));
  end; // while

  Result := True;
end;

function BuildImportTable(Module: PMEMORYMODULE): Boolean; 
var
  CodeBase: Pointer;
  Directory: PIMAGE_DATA_DIRECTORY;
  ImportDesc: PIMAGE_IMPORT_DESCRIPTOR;
  ThunkRef: PUINT_PTR;
  FuncRef: ^FARPROC;
  Handle: HCUSTOMMODULE;
  ThunkData: PIMAGE_IMPORT_BY_NAME;
begin
  CodeBase := Module.CodeBase;
  Result := True;

  Directory := GET_HEADER_DICTIONARY(Module, IMAGE_DIRECTORY_ENTRY_IMPORT);
  if Directory.Size = 0 then
    Exit;

  ImportDesc := PIMAGE_IMPORT_DESCRIPTOR(PByte(CodeBase) + Directory.VirtualAddress);
  while (not IsBadReadPtr(ImportDesc, SizeOf(IMAGE_IMPORT_DESCRIPTOR))) and (ImportDesc.Name <> 0) do
  begin
    Handle := Module.LoadLibrary(PAnsiChar(PByte(CodeBase) + ImportDesc.Name), Module.UserData);
    if Handle = nil then
    begin
      SetLastError(ERROR_MOD_NOT_FOUND);
      Result := False;
      Break;
    end;

    try
      SetLength(Module.Modules, Module.NumModules + 1);
    except
      Module.FreeLibrary(Handle, Module.UserData);
      SetLastError(ERROR_OUTOFMEMORY);
      Result := False;
      Break;
    end;
    Module.Modules[Module.NumModules] := Handle;
    Inc(Module.NumModules);

    if ImportDesc.OriginalFirstThunk <> 0 then
    begin
      ThunkRef := Pointer(PByte(CodeBase) + ImportDesc.OriginalFirstThunk);
      FuncRef := Pointer(PByte(CodeBase) + ImportDesc.FirstThunk);
    end
    else
    begin
      // no hint table
      ThunkRef := Pointer(PByte(CodeBase) + ImportDesc.FirstThunk);
      FuncRef := Pointer(PByte(CodeBase) + ImportDesc.FirstThunk);
    end;

    while ThunkRef^ <> 0 do
    begin
      if IMAGE_SNAP_BY_ORDINAL(ThunkRef^) then
        FuncRef^ := Module.GetProcAddress(Handle, LPCSTR(IMAGE_ORDINAL(ThunkRef^)), Module.UserData)
      else
      begin
        ThunkData := PIMAGE_IMPORT_BY_NAME(PByte(CodeBase) + ThunkRef^);
        FuncRef^ := Module.GetProcAddress(Handle, LPCSTR(@(ThunkData.Name)), Module.UserData);
      end;
      if FuncRef^ = nil then
      begin
        Result := False;
        Break;
      end;
      Inc(FuncRef);
      Inc(ThunkRef);
    end; // while

    if not Result then
    begin
      Module.FreeLibrary(Handle, Module.UserData);
      SetLastError(ERROR_PROC_NOT_FOUND);
      Break;
    end;

    Inc(ImportDesc);
  end; // while
end;

function MemoryDefaultAlloc(Address: Pointer; Size: SIZE_T; AllocationType: DWORD; Protect: DWORD; UserData: Pointer): Pointer;
begin
	UNREFERENCED_PARAMETER(UserData);
	Result := VirtualAlloc(Address, Size, AllocationType, Protect);
end;

function MemoryDefaultFree(Address: Pointer; Size: SIZE_T; dwFreeType: DWORD; UserData: Pointer): BOOL;
begin
	UNREFERENCED_PARAMETER(UserData);
	Result := VirtualFree(Address, Size, dwFreeType);
end;

function MemoryDefaultLoadLibrary(Filename: LPCSTR; UserData: Pointer): HCUSTOMMODULE;
begin
	UNREFERENCED_PARAMETER(UserData);
  Result := HCUSTOMMODULE(LoadLibraryA(Filename));
end;

function MemoryDefaultGetProcAddress(Module: HCUSTOMMODULE; Name: LPCSTR; UserData: Pointer): FARPROC;
begin
	UNREFERENCED_PARAMETER(UserData);
  Result := GetProcAddress(HMODULE(Module), Name);
end;

procedure MemoryDefaultFreeLibrary(Module: HCUSTOMMODULE; UserData: Pointer);
begin
  UNREFERENCED_PARAMETER(UserData);
  FreeLibrary(HMODULE(Module));
end;

  { +++++++++++++++++++++++++++++++++++++++++++++++++++++
    ***  Memory DLL loading functions Implementation  ***
    ----------------------------------------------------- }

function MemoryLoadLibary(Data: Pointer; Size: SIZE_T): HMEMORYMODULE;
begin
  Result := MemoryLoadLibaryEx(Data, Size, MemoryDefaultAlloc, MemoryDefaultFree,
    MemoryDefaultLoadLibrary, MemoryDefaultGetProcAddress, MemoryDefaultFreeLibrary, nil);
end;

function MemoryLoadLibaryEx(Data: Pointer; Size: SIZE_T;
                            AllocMemory: TCustomAllocFunc;
                            FreeMemory: TCustomFreeFunc;
                            LoadLibrary: TCustomLoadLibraryFunc;
                            GetProcAddress: TCustomGetProcAddressFunc;
                            FreeLibrary: TCustomFreeLibraryFunc;
                            UserData: Pointer): HMEMORYMODULE;

  // Just an imitation to allow using try-except block without using SysUtils.
  // DO NOT try to handle this like "on E do ..." !
  procedure Abort;
  begin
    raise TObject.Create;
  end;

var
  Dos_header: PIMAGE_DOS_HEADER;
  Old_header: PIMAGE_NT_HEADERS;
  Code, Headers: Pointer;
  LocationDelta: NativeInt;
  SysInfo: SYSTEM_INFO;
  Section: PIMAGE_SECTION_HEADER;
  i: DWORD;
  OptionalSectionSize, LastSectionEnd, AlignedImageSize, EndOfSection: SIZE_T;
  {$IFDEF CPU64}
  BlockedMemory, Node: PPOINTER_LIST; 
  {$ENDIF}
  DllEntry: TDllEntryProc;
  Successfull: Boolean;
  Module: PMEMORYMODULE;
begin
  Result := nil; Module := nil; LastSectionEnd := 0; {$IFDEF CPU64} BlockedMemory := nil; {$ENDIF}

  if not CheckSize(Size, SizeOf(IMAGE_DOS_HEADER)) then
    Exit;

  Dos_header := PIMAGE_DOS_HEADER(Data);
  if (Dos_header.e_magic <> IMAGE_DOS_SIGNATURE) then
  begin
    SetLastError(ERROR_BAD_EXE_FORMAT);
    Exit;
  end;

  if not CheckSize(Size, Dos_header.e_lfarlc + SizeOf(IMAGE_NT_HEADERS)) then
    Exit;

  // old_header = (PIMAGE_NT_HEADERS)&((const unsigned char *)(data))[dos_header->e_lfanew];
  Old_header := PIMAGE_NT_HEADERS(PByte(Data) + Dos_header._lfanew);
  if Old_header.Signature <> IMAGE_NT_SIGNATURE then
  begin
    SetLastError(ERROR_BAD_EXE_FORMAT);
    Exit;
  end;

  if Old_header.FileHeader.Machine <> HOST_MACHINE then
  begin
    SetLastError(ERROR_BAD_EXE_FORMAT);
    Exit;
  end;

  if (Old_header.OptionalHeader.SectionAlignment and 1) <> 0 then
  begin
    // Only support section alignments that are a multiple of 2
    SetLastError(ERROR_BAD_EXE_FORMAT);
    Exit;
  end;

  Section := IMAGE_FIRST_SECTION(Old_header^);
  OptionalSectionSize := Old_header.OptionalHeader.SectionAlignment;
  for i := 1 to Old_header.FileHeader.NumberOfSections do
  begin
    if Section.SizeOfRawData = 0 then
      // Section without data in the DLL
      EndOfSection := Section.VirtualAddress + OptionalSectionSize
    else 
      EndOfSection := Section.VirtualAddress + Section.SizeOfRawData;

    if EndOfSection > LastSectionEnd then
      LastSectionEnd := EndOfSection;

    Inc(Section);
  end;

  GetNativeSystemInfo({$IFDEF FPC}@{$ENDIF}SysInfo);

  AlignedImageSize := AlignValueUp(Old_header.OptionalHeader.SizeOfImage, SysInfo.dwPageSize);
  if AlignedImageSize <> AlignValueUp(LastSectionEnd, SysInfo.dwPageSize) then
  begin
    SetLastError(ERROR_BAD_EXE_FORMAT);
    Exit;
  end;

  // reserve memory for image of library
  // XXX: is it correct to commit the complete memory region at once?
  //      calling DllEntry raises an exception if we don't...
  Code := AllocMemory(Pointer(Old_header.OptionalHeader.ImageBase),
                      AlignedImageSize,
                      MEM_RESERVE or MEM_COMMIT,
                      PAGE_READWRITE,
                      UserData);
  if Code = nil then
  begin
    // try to allocate memory at arbitrary position
    Code := AllocMemory(nil,
                        AlignedImageSize,
                        MEM_RESERVE or MEM_COMMIT,
                        PAGE_READWRITE,
                        UserData);
    if Code = nil then
    begin
      SetLastError(ERROR_OUTOFMEMORY);
      Exit;
    end;
  end;

  {$IFDEF CPU64}
  // Memory block may not span 4 GB boundaries.
  while UINT_PTR(Code) shr 32 < UINT_PTR(PByte(Code) + AlignedImageSize) shr 32 do
  begin
    Node := AllocMem(SizeOf(POINTER_LIST));
    if Node = nil then
    begin
      FreeMemory(Code, 0, MEM_RELEASE, UserData);
      FreePointerList(BlockedMemory, FreeMemory, UserData);
      SetLastError(ERROR_OUTOFMEMORY);
      Exit;
    end;

    Node.Next := BlockedMemory;
    Node.Address := Code;
    BlockedMemory := Node;

    Code := AllocMemory(nil,
      AlignedImageSize,
      MEM_RESERVE or MEM_COMMIT,
      PAGE_READWRITE,
      UserData);

    if Code = nil then
    begin
      FreePointerList(BlockedMemory, FreeMemory, UserData);
      SetLastError(ERROR_OUTOFMEMORY);
      Exit;
    end;

  end; // while
  {$ENDIF}

  Module := PMEMORYMODULE(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SizeOf(MEMORYMODULEREC)));
  if Module = nil then
  begin
    FreeMemory(Code, 0, MEM_RELEASE, UserData);
    {$IFDEF CPU64}
    FreePointerList(BlockedMemory, FreeMemory, UserData);
    {$ENDIF}
    SetLastError(ERROR_OUTOFMEMORY);
    Exit;
  end;

  try
    // memory is zeroed by HeapAlloc
    Module.CodeBase := Code;
    Module.IsDLL := (Old_header.FileHeader.Characteristics and IMAGE_FILE_DLL) <> 0;
    Module.Alloc := AllocMemory;
    Module.Free := FreeMemory;
    Module.LoadLibrary := LoadLibrary;
    Module.GetProcAddress := GetProcAddress;
    Module.FreeLibrary := FreeLibrary;
    Module.UserData := UserData;
    Module.PageSize := SysInfo.dwPageSize;
    {$IFDEF CPU64}
    Module.BlockedMemory := BlockedMemory;
    {$ENDIF}

    if not CheckSize(Size, Old_header.OptionalHeader.SizeOfHeaders) then
      Abort;
    
    // commit memory for Headers
    Headers := AllocMemory(Code,
                           Old_header.OptionalHeader.SizeOfHeaders,
                           MEM_COMMIT,
                           PAGE_READWRITE,
                           UserData);

    // copy PE header to Code
    CopyMemory(Headers, Dos_header, Old_header.OptionalHeader.SizeOfHeaders);
    // result->Headers = (PIMAGE_NT_HEADERS)&((const unsigned char * )(Headers))[Dos_header->e_lfanew];
    Module.Headers := PIMAGE_NT_HEADERS(PByte(Headers) + Dos_header._lfanew);

    // update position
    Module.Headers.OptionalHeader.ImageBase := UINT_PTR(Code);

    // copy sections from DLL file block to new memory location
    if not CopySections(Data, Size, Old_header, Module) then
      Abort;

    // adjust base address of imported data
    LocationDelta := PByte(Module.Headers.OptionalHeader.ImageBase) - PByte(Old_header.OptionalHeader.ImageBase);
    if LocationDelta <> 0 then
      Module.IsRelocated := PerformBaseRelocation(Module, LocationDelta)
    else
      Module.IsRelocated := True;

    // load required dlls and adjust function table of imports
    if not BuildImportTable(Module) then
      Abort;

    // mark memory pages depending on Section Headers and release
    // sections that are marked as "discardable"
    if not FinalizeSections(Module) then
      Abort;

    // TLS callbacks are executed BEFORE the main loading
    if not ExecuteTLS(Module) then
      Abort;

    // get entry point of loaded library
    if Module.Headers.OptionalHeader.AddressOfEntryPoint <> 0 then
      if Module.IsDLL then
      begin
        @DllEntry := Pointer(PByte(Code) + Module.Headers.OptionalHeader.AddressOfEntryPoint);
        // notify library about attaching to process
        Successfull := DllEntry(HINST(Code), DLL_PROCESS_ATTACH, nil);
        if not Successfull then
        begin
          SetLastError(ERROR_DLL_INIT_FAILED);
          Abort;
        end;
        Module.Initialized := True;
      end
      else
        @Module.ExeEntry := Pointer(PByte(Code) + Module.Headers.OptionalHeader.AddressOfEntryPoint)
    else
      @Module.ExeEntry := nil;

    Result := Module;
  except
    // cleanup
    MemoryFreeLibrary(Module);
    Exit;
  end;
end;

function MemoryGetProcAddress(Modul: HMEMORYMODULE; Name: LPCSTR): FARPROC;
var
  CodeBase: Pointer;
  Idx: DWORD;
  i: DWORD;
  NameRef: PDWORD;
  Ordinal: PWord;
  ExportDir: PIMAGE_EXPORT_DIRECTORY;
  Directory: PIMAGE_DATA_DIRECTORY;
  Temp: PDWORD;
  Module: PMEMORYMODULE;
  Found, Entry: PExportNameEntry;
begin
  Result := nil;
  Module := PMEMORYMODULE(Modul);
  CodeBase := Module.CodeBase;
  Idx := 0;
  Directory := GET_HEADER_DICTIONARY(Module, IMAGE_DIRECTORY_ENTRY_EXPORT);
  // no export table found
  if Directory.Size = 0 then
  begin
    SetLastError(ERROR_PROC_NOT_FOUND);
    Exit;
  end;

  ExportDir := PIMAGE_EXPORT_DIRECTORY(PByte(CodeBase) + Directory.VirtualAddress);
  // DLL doesn't export anything
  if (ExportDir.NumberOfNames = 0) or (ExportDir.NumberOfFunctions = 0) then
  begin
    SetLastError(ERROR_PROC_NOT_FOUND);
    Exit;
  end;

  // load function by ordinal value
  if HiWord(UIntPtr(Name)) = 0 then
  begin
    if LoWord(UIntPtr(Name)) < ExportDir.Base then
    begin
      SetLastError(ERROR_PROC_NOT_FOUND);
      Exit;
    end;
    Idx := LoWord(UIntPtr(Name)) - ExportDir.Base;
  end
  else if ExportDir.NumberOfNames = 0 then
  begin
    SetLastError(ERROR_PROC_NOT_FOUND);
    Exit;
  end
  else
  begin
    // Lazily build name table and sort it by names
    if Module.NameExportsTable = nil then
    begin
      NameRef := Pointer(PByte(CodeBase) + ExportDir.AddressOfNames);
      Ordinal := Pointer(PByte(CodeBase) + ExportDir.AddressOfNameOrdinals);
      Entry := AllocMem(ExportDir.NumberOfNames*SizeOf(TExportNameEntry));
      Module.NameExportsTable := Entry;
      if Entry = nil then
      begin
        SetLastError(ERROR_OUTOFMEMORY);
        Exit;
      end;

      for i := 1 to ExportDir.NumberOfNames do
      begin
        Entry.Name := LPCSTR(PByte(CodeBase) + NameRef^);
        Entry.Idx := Ordinal^;
        Inc(NameRef);
        Inc(Ordinal);
        Inc(Entry);
      end;
      {}//TODO: sort
    end;
    // search function name in list of exported names with binary search
    Found := nil; Entry := Module.NameExportsTable;
    for i := 1 to ExportDir.NumberOfNames do
    begin
      {}//TODO: binary search
      if StrComp(Name, Entry.Name) = 0 then
      begin
        Found := Entry;
        Break;
      end;
      Inc(Entry);
    end;
    
    if Found = nil then
    begin
      // exported symbol not found
      SetLastError(ERROR_PROC_NOT_FOUND);
      Exit;      
    end;

    Idx := Found.Idx;
  end;

  // name <-> Ordinal number don't match
  if (Idx > ExportDir.NumberOfFunctions) then
  begin
    SetLastError(ERROR_PROC_NOT_FOUND);
    Exit;
  end;

  // AddressOfFunctions contains the RVAs to the "real" functions   
  Temp := Pointer(PByte(CodeBase) + ExportDir.AddressOfFunctions + Idx*4);
  Result := Pointer(PByte(CodeBase) + Temp^);
end;

procedure MemoryFreeLibrary(Modul: HMEMORYMODULE);
var
  i: Integer;
  DllEntry: TDllEntryProc;
  Module: PMEMORYMODULE;
begin
  if Modul = nil then Exit;

  Module := PMEMORYMODULE(Modul);

  if Module.Initialized then
  begin
    // notify library about detaching from process
    @DllEntry := Pointer(PByte(Module.CodeBase) + Module.Headers.OptionalHeader.AddressOfEntryPoint);
    DllEntry(HINST(Module.CodeBase), DLL_PROCESS_DETACH, nil);
  end;

  Dispose(Module.NameExportsTable);

  if Length(Module.Modules) <> 0 then
  begin
    // free previously opened libraries
    for i := 0 to Module.NumModules - 1 do
      if Module.Modules[i] <> nil then
        Module.FreeLibrary(Module.Modules[i], Module.UserData);
    SetLength(Module.Modules, 0);
  end;

  if Module.CodeBase <> nil then
    // release memory of library
    Module.Free(Module.CodeBase, 0, MEM_RELEASE, Module.UserData);

  {$IFDEF CPU64}
    FreePointerList(Module.BlockedMemory, Module.Free, Module.UserData);
  {$ELSE}  
    HeapFree(GetProcessHeap, 0, Module);
  {$ENDIF}
end;

function MemoryCallEntryPoint(Modul: HMEMORYMODULE): Integer;
var
  Module: PMEMORYMODULE;
begin
  Module := PMEMORYMODULE(Modul);

  if (Module = nil) or Module.IsDLL or (@Module.ExeEntry = nil) or not Module.IsRelocated then
    Exit(-1);

  Result := Module.ExeEntry();
end;

end.
