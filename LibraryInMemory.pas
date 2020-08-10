unit LibraryInMemory;

interface

uses
  System.IOUtils, System.SysUtils;

type
  TLibraryLoader = function(lpLibFileName: string; out aCodes: TBytes): Boolean;

procedure Install(aLoader: TLibraryLoader);

procedure Uninstall;

implementation

uses
  Winapi.Windows, System.Classes, System.Generics.Collections,
  DDetours, MemoryModule;

type
  TLibrary = class
  strict private
    FRefCount: Integer;
    FCodes: TBytes;
    FHandle: HMODULE;
    FName: string;
  public
    constructor Create(aName: string; aHandle: HMODULE; aCodes: TBytes);
    procedure AfterConstruction; override;
    procedure BeforeDestruction; override;
    procedure AddRef;
    procedure RelRef;
    property Codes: TBytes read FCodes;
    property Name: string read FName;
    property Handle: THandle read FHandle;
    property RefCount: Integer read FRefCount;
  end;

  TDLLs = record
  private
    FItems: TObjectDictionary<string, TLibrary>;
    FHandles: TArray<HMODULE>; // Additional container to Handles to speed up HandleExist used by GetProcAddressHook
  public
    function HandleExist(aHandle: HMODULE): Boolean; inline;
    procedure NewLibrary(Name: string; Codes: TBytes; aHandle: HMODULE);
    function Release(aHandle: HMODULE): Boolean;
    function TryGetHandle(aName: string; out aHandle: HMODULE): Boolean;
    property Handles: TArray<HMODULE> read FHandles;
    class operator Initialize(out Dest: TDLLs);
    class operator Finalize(var Dest: TDLLs);
  end;

var DLLs: TDLLs;
    LibraryLoader: TLibraryLoader;
    LoadLibraryA_Old: function (lpLibFileName: LPCSTR): HMODULE; stdcall;
    LoadLibrary_Old: function (lpLibFileName: LPCWSTR): HMODULE; stdcall;
    GetProcAddress_Old: function (hModule: HMODULE; lpProcName: LPCSTR): FARPROC; stdcall;
    FreeLibrary_Old: function (hLibModule: HMODULE): BOOL; stdcall;

function LoadLibraryAHook(lpLibFileName: LPCSTR): HMODULE; stdcall;
begin
  if DLLs.TryGetHandle(string(lpLibFileName), Result) then Exit;

  var c: TBytes;
  if SameText(TPath.GetExtension(string(lpLibFileName)), '.dll') and LibraryLoader(string(lpLibFileName), c) then begin
    Result := HMODULE(MemoryLoadLibary(c));
    if Result <> 0 then
      DLLs.NewLibrary(string(lpLibFileName), c, Result);
  end else
    Exit(LoadLibraryA_Old(lpLibFileName));
end;

function LoadLibraryHook(lpLibFileName: LPCWSTR): HMODULE; stdcall;
begin
  if DLLs.TryGetHandle(lpLibFileName, Result) then Exit;

  var c: TBytes;
  if SameText(TPath.GetExtension(lpLibFileName), '.dll') and LibraryLoader(lpLibFileName, c) then begin
    Result := HMODULE(MemoryLoadLibary(c));
    if Result <> 0 then
      DLLs.NewLibrary(lpLibFileName, c, Result);
  end else
    Exit(LoadLibrary_Old(lpLibFileName));
end;

function GetProcAddressHook(hModule: HMODULE; lpProcName: LPCSTR): FARPROC; stdcall;
begin
  if DLLs.HandleExist(hModule) then
    Result := FARPROC(MemoryGetProcAddress(TMemoryModule(hModule), lpProcName))
  else
    Result := GetProcAddress_Old(hModule, lpProcName);
end;

function FreeLibraryHook(hLibModule: HMODULE): BOOL; stdcall;
begin
  if not DLLs.HandleExist(hLibModule) then
    Result := FreeLibrary_Old(hLibModule)
  else begin
    if DLLs.Release(hLibModule) then
      MemoryFreeLibrary(TMemoryModule(hLibModule));
    Result := True;
  end;
end;

procedure Install(aLoader: TLibraryLoader);
begin
  if not Assigned(aLoader) then Exit;
  if Assigned(LibraryLoader) then raise Exception.Create('Library Loader already installed.');

  var cs: RTL_CRITICAL_SECTION;;
  InitializeCriticalSection(cs);
  EnterCriticalSection(cs);
  try
    LoadLibraryA_Old := InterceptCreate(@LoadLibraryA, @LoadLibraryAHook);
    LoadLibrary_Old := InterceptCreate(@LoadLibrary, @LoadLibraryHook);
    GetProcAddress_Old := InterceptCreate(@GetProcAddress, @GetProcAddressHook);
    FreeLibrary_Old := InterceptCreate(@FreeLibrary, @FreeLibraryHook);
  finally
    DeleteCriticalSection(cs);
  end;

  LibraryLoader := aLoader;
end;

procedure Uninstall;
begin
  if not Assigned(LibraryLoader) then Exit;

  var cs: RTL_CRITICAL_SECTION;;
  InitializeCriticalSection(cs);
  EnterCriticalSection(cs);
  try
    for var H in DLLs.Handles do
      FreeLibrary(H);
    InterceptRemove(@LoadLibraryA_Old);
    InterceptRemove(@LoadLibrary_Old);
    InterceptRemove(@GetProcAddress_Old);
    InterceptRemove(@FreeLibrary_Old);
  finally
    DeleteCriticalSection(cs);
  end;

  LibraryLoader := nil;
end;

constructor TLibrary.Create(aName: string; aHandle: HMODULE; aCodes: TBytes);
begin
  FName := aName;
  FHandle := aHandle;
  FCodes := aCodes;
end;

procedure TLibrary.AddRef;
begin
  Inc(FRefCount);
end;

procedure TLibrary.AfterConstruction;
begin
  inherited;
  FRefCount := 0;
  AddRef;
end;

procedure TLibrary.BeforeDestruction;
begin
  SetLength(FCodes, 0);
  inherited;
end;

procedure TLibrary.RelRef;
begin
  if FRefCount = 0 then raise Exception.Create('Invalid reference counter');
  Dec(FRefCount);
end;

function TDLLs.HandleExist(aHandle: HMODULE): Boolean;
begin
  for var o in FHandles do
    if o = aHandle then
      Exit(True);
  Result := False;
end;

procedure TDLLs.NewLibrary(Name: string; Codes: TBytes; aHandle: HMODULE);
begin
  FItems.Add(Name, TLibrary.Create(Name, aHandle, Codes));
  FHandles := FHandles + [aHandle];
end;

function TDLLs.Release(aHandle: HMODULE): Boolean;
begin
  Result := False;
  for var o in FItems do
    if o.Value.Handle = aHandle then begin
      o.Value.RelRef;
      if o.Value.RefCount = 0 then begin
        FItems.Remove(o.Value.Name);

        var idx := -1;
        for var i := 0 to Length(FHandles) - 1 do begin
          if FHandles[i] = aHandle then begin
            idx := i;
            Break;
          end;
        end;
        Assert(idx <> -1);
        if idx < Length(FHandles) - 1 then
          Move(FHandles[idx + 1], FHandles[idx], (Length(FHandles) - idx + 1) * SizeOf(HMODULE));
        SetLength(FHandles, Length(FHandles) - 1);
        Exit(True);
      end;
    end;
end;

function TDLLs.TryGetHandle(aName: string; out aHandle: HMODULE): Boolean;
begin
  var L: TLibrary;
  if FItems.TryGetValue(aName, L) then begin
    aHandle := L.Handle;
    L.AddRef;
    Exit(True);
  end else
    Exit(False);
end;

class operator TDLLs.Finalize(var Dest: TDLLs);
begin
  Dest.FItems.Free;
end;

class operator TDLLs.Initialize(out Dest: TDLLs);
begin
  Dest.FItems := TObjectDictionary<string, TLibrary>.Create([doOwnsValues]);
  Dest.FHandles := [];
end;

end.
