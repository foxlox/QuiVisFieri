program quivisfieri;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  windows,ShellAPI;


var
    CreateProcessWithTokenW:pointer;
    ProcessHandle, ImpersonateToken: THandle;
    StartupInfo: TStartupInfoW;
    ProcessInformation: TProcessInformation;
    TokenHandle       : THandle;

type
  TCreateProcessWithTokenW=function(hToken: THandle;
  dwLogonFlags: DWORD;
  lpApplicationName: PWideChar;
  lpCommandLine: PWideChar;
  dwCreationFlags: DWORD;
  lpEnvironment: Pointer;
  lpCurrentDirectory: PWideChar;
  lpStartupInfo: PStartupInfoW;
  lpProcessInformation: PProcessInformation): BOOL; stdcall;





const
  LOW_INTEGRITY_SID: PWideChar = ('S-1-16-4096');
  MEDIUM_INTEGRITY_SID: PWideChar = ('S-1-16-8192');
  HIGH_INTEGRITY_SID: PWideChar = ('S-1-16-12288');
  SYSTEM_INTEGRITY_SID: PWideChar = ('S-1-16-16384');


function enumprivileges:boolean;
type
  TPrivilegesArray = array [0..1024] of TLuidAndAttributes;
  PPrivilegesArray = ^TPrivilegesArray;
var
  TokenHandle: THandle;
  Size: Cardinal;
  Privileges: PTokenPrivileges;
  I: Integer;
  Luid: Int64;
  Name: string;
  Attr: Longword;
  function AttrToString: string;
  begin
    Result := '';
    if (Attr and SE_PRIVILEGE_ENABLED) <> 0 then
       Result := Result + 'Enabled ';
    if (Attr and SE_PRIVILEGE_ENABLED_BY_DEFAULT) <> 0
       then Result := Result + 'EnabledByDefault';
    Result := '[' + Trim(Result) + ']';
  end;
begin
  Win32Check(OpenProcessToken(GetCurrentProcess,
    TOKEN_QUERY, TokenHandle));
  try
    GetTokenInformation(TokenHandle, TokenPrivileges, nil,
      0, Size);
    Privileges := AllocMem(Size);
    Win32Check(GetTokenInformation(TokenHandle, TokenPrivileges, Privileges, Size, Size));
    for I := 0 to Privileges.PrivilegeCount - 1 do
    begin
      Luid := PPrivilegesArray(@Privileges^.Privileges)^[I].Luid;
      Attr := PPrivilegesArray(@Privileges^.Privileges)^[I].Attributes;
      Size := 0;
      LookupPrivilegeName(nil, Luid, nil, Size);
      SetLength(Name, Size);
      LookupPrivilegeName(nil, Luid, PChar(Name), Size);
      writeln(PChar(Name) + ' ' + AttrToString);
    end;
  finally
    CloseHandle(TokenHandle);
  end;
end;


procedure Impersonate(pid: cardinal);
var
  ProcessHandle: THandle;
  s:string;
  rt:boolean;

begin
 CreateProcessWithTokenW:=GetProcAddress(loadlibrary('advapi32.dll'),'CreateProcessWithTokenW');
 ZeroMemory(@StartupInfo, SizeOf(TStartupInfoW));
 FillChar(StartupInfo, SizeOf(TStartupInfoW), 0);
 FillChar(ProcessInformation, SizeOf(TProcessInformation), #0);
 StartupInfo.cb := SizeOf(TStartupInfoW);
 StartupInfo.lpDesktop := pwidechar(widestring('WinSta0\Default'));
 getdir(0,s);
 ProcessHandle := OpenProcess(MAXIMUM_ALLOWED, False, pid);
 if OpenProcessToken(ProcessHandle, MAXIMUM_ALLOWED, TokenHandle) then
  begin
   DuplicateTokenEx(TokenHandle, MAXIMUM_ALLOWED, nil, SecurityImpersonation, TokenPrimary, ImpersonateToken);
   TCreateProcessWithTokenW(CreateProcessWithTokenW)(ImpersonateToken, 0,  widestring('c:\windows\system32\cmd.exe'),'', NORMAL_PRIORITY_CLASS, nil, pchar(s), @StartupInfo, @ProcessInformation);
   end;
end;




begin
 if paramcount = 0
  then
   begin
    writeln('Qui Vis Fieri');
    writeln('(c) fox aka calipendula 2023122700');
    writeln('Usage: ');
    writeln('C:\> quivisfieri PID_TO_IMPERSONATE');
    exit;
   end;

  enumprivileges;
  Impersonate(strtoint(paramstr(1)));

end.
