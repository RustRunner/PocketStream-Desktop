; Transaction ownership only. No shell, previous uninstaller or force termination.
!include LogicLib.nsh
!define MUI_CUSTOMFUNCTION_ABORT PS_UserAbort
!define MUI_CUSTOMFUNCTION_UNABORT un.PS_UserAbort
Var PSInstallGate
Var PSExistingRoot
Var PSReplacementStarted
Var PSLaunchRequested
Var PSPhase

!macro PS_RELEASE_TRANSACTION
  ${If} $PSInstallGate P<> 0
    System::Call 'kernel32::ReleaseMutex(p $PSInstallGate)'
    System::Call 'kernel32::CloseHandle(p $PSInstallGate)'
    StrCpy $PSInstallGate 0
  ${EndIf}
!macroend

!macro PS_FAILURE_DIAGNOSTIC
  ${If} $PSReplacementStarted = 1
    DetailPrint 'PocketStream transaction incomplete after file changes; no rollback is claimed.'
    FileOpen $8 '$INSTDIR\pocketstream-transaction.json' w
    FileWrite $8 '{"version":2,"state":"incomplete","phase":"$PSPhase","rollback_claimed":false}$\r$\n'
    FileClose $8
  ${EndIf}
!macroend

!macro PS_FAIL message
  DetailPrint '${message}'
  !insertmacro PS_FAILURE_DIAGNOSTIC
  SetErrorLevel 71
  !insertmacro PS_RELEASE_TRANSACTION
  IfSilent +2
  MessageBox MB_OK|MB_ICONSTOP '${message}'
  Quit
!macroend

; Same rights, DACL and Medium integrity label as host_owner.rs. The main
; installer thread acquires/releases both mutexes; a namespace mismatch fails.
!macro PS_OPEN_MUTEX name wait
  StrCpy $9 0
  System::Call 'advapi32::ConvertStringSecurityDescriptorToSecurityDescriptorW(w "D:P(A;;0x001f0001;;;SY)(A;;0x001f0001;;;BA)(A;;0x00120001;;;IU)S:(ML;;NW;;;ME)", i1, *p.r1, p0)i.r0'
  ${If} $0 = 0
    !insertmacro PS_FAIL 'Cannot construct machine ownership security'
  ${EndIf}
  System::Call '*(i12, p r1, i0)p.r2'
  ; SECURITY_ATTRIBUTES is 12 bytes on the pinned 32-bit Unicode NSIS engine.
  System::Call '*$2(i12, p r1, i0)'
  System::Call 'kernel32::CreateMutexExW(p r2, w "${name}", i0, i0x120001)p.r9'
  System::Free $2
  System::Call 'kernel32::LocalFree(p r1)'
  ${If} $9 P= 0
    !insertmacro PS_FAIL 'Cannot open machine ownership namespace'
  ${EndIf}
  System::Call 'advapi32::GetSecurityInfo(p r9, i6, i0x14, p0, p0, p0, p0, *p.r2)i.r0'
  ${If} $0 <> 0
    System::Call 'kernel32::CloseHandle(p r9)'
    !insertmacro PS_FAIL 'Cannot verify machine ownership security'
  ${EndIf}
  System::Call 'advapi32::ConvertSecurityDescriptorToStringSecurityDescriptorW(p r2, i1, i0x14, *p.r3, p0)i.r0'
  System::Call 'kernel32::LocalFree(p r2)'
  ${If} $0 = 0
    System::Call 'kernel32::CloseHandle(p r9)'
    !insertmacro PS_FAIL 'Cannot read machine ownership descriptor'
  ${EndIf}
  System::Call '*$3(&w${NSIS_MAX_STRLEN}.r4)'
  System::Call 'kernel32::LocalFree(p r3)'
  ${If} $4 != 'D:P(A;;0x1f0001;;;SY)(A;;0x1f0001;;;BA)(A;;0x120001;;;IU)S:AI(ML;;NW;;;ME)'
  ${AndIf} $4 != 'D:P(A;;0x1f0001;;;SY)(A;;0x1f0001;;;BA)(A;;0x120001;;;IU)S:(ML;;NW;;;ME)'
    System::Call 'kernel32::CloseHandle(p r9)'
    !insertmacro PS_FAIL 'Machine ownership descriptor mismatch'
  ${EndIf}
  System::Call 'kernel32::WaitForSingleObject(p r9, i ${wait})i.r0'
  ${If} $0 <> 0
  ${AndIf} $0 <> 128
    System::Call 'kernel32::CloseHandle(p r9)'
    !insertmacro PS_FAIL 'PocketStream is busy; close the application and retry'
  ${EndIf}
!macroend

!macro PS_ACQUIRE_TRANSACTION
  !insertmacro PS_OPEN_MUTEX 'Global\PocketStream.Desktop.InstallGate.v2' 5000
  StrCpy $PSInstallGate $9
  !insertmacro PS_OPEN_MUTEX 'Global\PocketStream.Desktop.HostOwner.v2' 5000
  System::Call 'kernel32::ReleaseMutex(p r9)'
  System::Call 'kernel32::CloseHandle(p r9)'
!macroend

!macro PS_CHECK_PROCESSES
  ; v0.6.7 does not honor mutexes. Check all accounts again before replacement.
  nsis_tauri_utils::FindProcess '${MAINBINARYNAME}.exe'
  Pop $0
  ${If} $0 = 0
    !insertmacro PS_FAIL 'PocketStream is running; close it normally and retry'
  ${ElseIf} $0 <> 1
    !insertmacro PS_FAIL 'Unable to establish that PocketStream has exited'
  ${EndIf}
  ${If} ${FileExists} '$INSTDIR\${MAINBINARYNAME}.exe'
    ; Opening for read/write with no sharing changes no bytes and rejects a
    ; legacy mapped image/file-in-use before replacement. No process is killed.
    System::Call 'kernel32::CreateFileW(w "$INSTDIR\${MAINBINARYNAME}.exe", i0xC0000000, i0, p0, i3, i0x80, p0)p.r0'
    ${If} $0 P= -1
      !insertmacro PS_FAIL 'PocketStream files are in use; close the application normally and retry'
    ${EndIf}
    System::Call 'kernel32::CloseHandle(p r0)'
  ${EndIf}
!macroend

!macro PS_MAINTENANCE mode
  StrCpy $PSPhase 'firewall_${mode}'
  ; This is the new image in the protected root, never a caller-supplied path.
  nsExec::ExecToStack /TIMEOUT=65000 '"$INSTDIR\${MAINBINARYNAME}.exe" --firewall-maintenance ${mode}'
  Pop $0
  Pop $1
  DetailPrint 'Firewall maintenance ${mode}: exit=$0 result=$1'
  ; Fixed valid JSON even if native output exceeds NSIS string capacity.
  FileOpen $2 '$INSTDIR\pocketstream-maintenance.json' w
  FileWrite $2 '{"version":2,"operation":"${mode}","exit":"$0"}$\r$\n'
  FileClose $2
  ${If} $0 != 0
    !insertmacro PS_FAIL 'Firewall maintenance failed; installation is incomplete. Preserve pocketstream-maintenance.json and installer details.'
  ${EndIf}
!macroend

Function PS_PreflightInstall
  ReadRegStr $PSExistingRoot SHCTX '${MANUPRODUCTKEY}' ''
  ReadRegStr $0 SHCTX '${UNINSTKEY}' 'UninstallString'
  ${If} $PSExistingRoot != ''
    ${If} $0 != '$\"$PSExistingRoot\uninstall.exe$\"'
      !insertmacro PS_FAIL 'Unsupported predecessor; complete standalone uninstall before installing'
    ${EndIf}
    ${If} $INSTDIR != '${PLACEHOLDER_INSTALL_DIR}'
    ${AndIf} $INSTDIR != $PSExistingRoot
      !insertmacro PS_FAIL 'Relocation requires standalone uninstall before installing'
    ${EndIf}
    StrCpy $INSTDIR $PSExistingRoot
  ${ElseIf} $0 != ''
    !insertmacro PS_FAIL 'Unrecognized predecessor; complete standalone uninstall before installing'
  ${EndIf}
  ; Reject MSI/WiX predecessors rather than invoking their uninstaller.
  StrCpy $2 0
  ps_wix_loop:
    EnumRegKey $1 HKLM 'Software\Microsoft\Windows\CurrentVersion\Uninstall' $2
    StrCmp $1 '' ps_wix_done
    IntOp $2 $2 + 1
    ReadRegStr $3 HKLM 'Software\Microsoft\Windows\CurrentVersion\Uninstall\$1' 'DisplayName'
    ReadRegStr $4 HKLM 'Software\Microsoft\Windows\CurrentVersion\Uninstall\$1' 'Publisher'
    ${If} '$3$4' == '${PRODUCTNAME}${MANUFACTURER}'
    ${AndIf} $1 != '${PRODUCTNAME}'
      !insertmacro PS_FAIL 'Unsupported predecessor; complete standalone uninstall before installing'
    ${EndIf}
    Goto ps_wix_loop
  ps_wix_done:
  !insertmacro PS_CHECK_PROCESSES
FunctionEnd

Function PS_ValidateDestination
  ${If} $PSExistingRoot != ''
  ${AndIf} $INSTDIR != $PSExistingRoot
    !insertmacro PS_FAIL 'Relocation requires standalone uninstall before installing'
  ${EndIf}
  ; Per-machine executable and maintenance diagnostics stay below Program Files.
  GetFullPathName $INSTDIR $INSTDIR
  StrLen $0 '$PROGRAMFILES64\'
  StrCpy $1 $INSTDIR $0
  ${If} $1 != '$PROGRAMFILES64\'
    !insertmacro PS_FAIL 'Select a protected destination below Program Files'
  ${EndIf}
  ; Reject existing reparse components, including a redirected install root.
  StrCpy $2 $INSTDIR
  ps_parent:
    System::Call 'kernel32::GetFileAttributesW(w r2)i.r0'
    ${If} $0 <> -1
      IntOp $0 $0 & 0x400
      ${If} $0 <> 0
        !insertmacro PS_FAIL 'Reparse install destinations are unsupported'
      ${EndIf}
    ${EndIf}
    ${GetParent} '$2' $3
    StrCmp $3 $2 ps_parent_done
    StrCmp $3 '' ps_parent_done
    StrCpy $2 $3
    Goto ps_parent
  ps_parent_done:
FunctionEnd

Function un.PS_Preflight
  !insertmacro PS_CHECK_PROCESSES
FunctionEnd
