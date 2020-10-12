unit LibraryInMemoryLoader.AppZZRes;

interface

uses
  System.SysUtils;

function LibraryLoader_AppZZRes(lpLibFileName: string; out aCodes: TBytes):
    Boolean;

implementation

uses
  System.Classes, System.IOUtils, System.Types, System.ZLib,
  LibraryInMemory;

function LibraryLoader_AppZZRes(lpLibFileName: string; out aCodes: TBytes):
    Boolean;
begin
  if FindResource(MainInstance, PChar(TPath.GetFileNameWithoutExtension(lpLibFileName)), RT_RCDATA) = 0 then Exit(False);

  var M := TResourceStream.Create(MainInstance, TPath.GetFileNameWithoutExtension(lpLibFileName), RT_RCDATA);
  try
    var B: TBytes;
    SetLength(B, M.Size);
    M.Read(B, Integer(M.Size));
    ZDecompress(B, aCodes);
    Result := True;
  finally
    M.Free;
  end;
end;

initialization
  Install(LibraryLoader_AppZZRes);
finalization
  Uninstall;
end.
