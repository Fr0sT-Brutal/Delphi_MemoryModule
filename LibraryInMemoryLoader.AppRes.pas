unit LibraryInMemoryLoader.AppRes;

interface

uses
  System.SysUtils;

function LibraryLoader_AppRes(lpLibFileName: string; out aCodes: TBytes):
    Boolean;

implementation

uses
  System.Classes, System.IOUtils, System.Types,
  LibraryInMemory;

function LibraryLoader_AppRes(lpLibFileName: string; out aCodes: TBytes):
    Boolean;
begin
  if FindResource(MainInstance, PChar(TPath.GetFileNameWithoutExtension(lpLibFileName)), RT_RCDATA) = 0 then Exit(False);

  var M := TResourceStream.Create(MainInstance, TPath.GetFileNameWithoutExtension(lpLibFileName), RT_RCDATA);
  try
    SetLength(aCodes, M.Size);
    M.Read(aCodes, Integer(M.Size));
    Result := True;
  finally
    M.Free;
  end;
end;

initialization
  Install(LibraryLoader_AppRes);
finalization
  Uninstall;
end.
