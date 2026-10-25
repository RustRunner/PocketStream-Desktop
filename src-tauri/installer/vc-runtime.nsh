; Fixed Microsoft prerequisite, checked at every NSIS compilation and installed
; only under InstallGate. NSIS 3.11 creates an admin-only plugin directory.
!system 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "${__FILEDIR__}\..\..\scripts\prepare-installer-prerequisites.ps1" -VerifyOnly' = 0
Var PSVcReady

Function PS_CheckVcFile
  Pop $3
  ClearErrors
  GetDLLVersion '$WINDIR\Sysnative\$3' $0 $1
  ${If} ${Errors}
    StrCpy $PSVcReady 0
    Return
  ${EndIf}
  IntOp $2 $0 >> 16
  ${If} $2 != 14
    StrCpy $PSVcReady 0
    Return
  ${EndIf}
  IntOp $2 $0 & 0xffff
  ${If} $2 < 50
    StrCpy $PSVcReady 0
  ${ElseIf} $2 = 50
    IntOp $2 $1 >> 16
    IntOp $2 $2 & 0xffff
    ${If} $2 < 35719
      StrCpy $PSVcReady 0
    ${EndIf}
  ${EndIf}
FunctionEnd

Function PS_ObserveVc
  StrCpy $PSVcReady 1
  Push 'vcruntime140.dll'
  Call PS_CheckVcFile
  Push 'vcruntime140_1.dll'
  Call PS_CheckVcFile
  Push 'msvcp140.dll'
  Call PS_CheckVcFile
FunctionEnd

!macro PS_ENSURE_VC
  Call PS_ObserveVc
  ${If} $PSVcReady != 1
    StrCpy $PSReplacementStarted 1
    StrCpy $PSPhase 'vc_runtime'
    CreateDirectory '$INSTDIR'
    InitPluginsDir
    File '/oname=$PLUGINSDIR\VC_redist.x64.exe' '${PS_INSTALLER_SOURCE_DIR}\prerequisites\VC_redist.x64.exe'
    ExecWait '"$PLUGINSDIR\VC_redist.x64.exe" /install /quiet /norestart /log "$INSTDIR\pocketstream-vc-runtime.log"' $0
    FileOpen $2 '$INSTDIR\pocketstream-prerequisite.json' w
    FileWrite $2 '{"version":1,"prerequisite":"vc_runtime_x64","pinned":"14.50.35719","exit":"$0","restart_requested":false}$\r$\n'
    FileClose $2
    ${If} $0 != 0
    ${AndIf} $0 != 3010
      !insertmacro PS_FAIL 'Microsoft Visual C++ x64 runtime installation failed. Preserve pocketstream-prerequisite.json and pocketstream-vc-runtime.log.'
    ${EndIf}
    Call PS_ObserveVc
    ${If} $PSVcReady != 1
      !insertmacro PS_FAIL 'Microsoft Visual C++ x64 runtime is unavailable after installation. A restart may be required; no restart was requested.'
    ${EndIf}
  ${EndIf}
!macroend
