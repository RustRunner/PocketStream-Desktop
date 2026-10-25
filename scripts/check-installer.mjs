import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = p => fs.readFileSync(path.join(root, p), "utf8");
const body = (source, name) => source.match(new RegExp(`Function ${name.replaceAll(".", "\\.")}\\s*\\n([\\s\\S]*?)FunctionEnd`))?.[1] ?? "";

export function checkInstaller(source, hooks) {
  const failures = [];
  const require = (condition, message) => { if (!condition) failures.push(message); };
  require(!/PageReinstall|PageLeaveReinstall|reinst_uninstall/.test(source), "previous-uninstaller branch returned");
  require(!/CheckIfAppIsRunning|KillProcess|taskkill|TerminateProcess/.test(source + hooks), "force-kill fallback returned");
  require(!/ExecWait[^\r\n]*(?:uninstall|msiexec|_\?=)/i.test(source + hooks), "chained uninstaller returned");
  for (const name of [".onInit", "un.onInit"]) {
    require(body(source, name).trimStart().startsWith("!insertmacro PS_ACQUIRE_TRANSACTION"), `${name} must acquire before initialization/pages`);
  }
  for (const name of [".onInstSuccess", ".onGUIEnd", ".onInstFailed", "PS_UserAbort", "un.onGUIEnd", "un.onUninstSuccess", "un.onUninstFailed", "un.PS_UserAbort"]) {
    require(body(source, name).includes("!insertmacro PS_RELEASE_TRANSACTION"), `${name} does not release transaction`);
  }
  require(body(source, "RunMainBinary").includes("StrCpy $PSLaunchRequested 1") && !body(source, "RunMainBinary").includes("RunAsUser"), "finish-page launch must wait until all callbacks complete");
  require(body(source, ".onInstSuccess").indexOf("PS_RELEASE_TRANSACTION") < body(source, ".onInstSuccess").indexOf("RunAsUser"), "silent/updater launch precedes release");
  const install = source.match(/Section Install\s*\n([\s\S]*?)SectionEnd/)?.[1] ?? "";
  const uninstall = source.match(/Section Uninstall\s*\n([\s\S]*?)SectionEnd/)?.[1] ?? "";
  require(install.indexOf("PS_ValidateDestination") >= 0 && install.indexOf("PS_ValidateDestination") < install.indexOf('File "${MAINBINARYSRCPATH}"'), "destination not checked before replacement");
  require(install.includes('PS_MAINTENANCE "install"'), "install maintenance missing");
  require(uninstall.indexOf('PS_MAINTENANCE "uninstall"') >= 0 && uninstall.indexOf('PS_MAINTENANCE "uninstall"') < uninstall.indexOf("Delete "), "uninstall deletes before maintenance");
  const resources = install.slice(install.indexOf("; Copy resources"), install.indexOf("; Create file associations"));
  require(resources.includes('${If} ${Errors}') && resources.includes('PS_FAIL "Resource replacement failed'), "resource extraction errors must fail installation");
  const uninstaller = install.slice(install.indexOf("; Create uninstaller"), install.indexOf("; Save $INSTDIR"));
  require(uninstaller.includes('${If} ${Errors}') && uninstaller.includes('PS_FAIL'), "uninstaller creation errors must fail installation");
  const deletion = uninstall.slice(uninstall.indexOf('; Delete the app directory'), uninstall.indexOf('; Delete app associations'));
  require(deletion.includes('ClearErrors') && deletion.includes('${If} ${Errors}') && deletion.includes('PS_FAIL "Payload deletion failed'), "payload deletion errors must fail before unregistering");
  require(deletion.indexOf('PS_FAIL "Payload deletion failed') < deletion.indexOf('Delete "$INSTDIR\\${MAINBINARYNAME}.exe"') && deletion.includes('PS_FAIL "Executable deletion failed'), "resource deletion must succeed before deleting the maintenance image");
  const metadataRemoval = uninstall.indexOf('DeleteRegValue SHCTX "${MANUPRODUCTKEY}" ""');
  require(metadataRemoval >= 0 && metadataRemoval < uninstall.indexOf('${If} $DeleteAppDataCheckboxState = 1'), "uninstall must clear installation location even when retaining app data");
  for (const contract of ["Global\\PocketStream.Desktop.InstallGate.v2", "Global\\PocketStream.Desktop.HostOwner.v2", "GetSecurityInfo", "Descriptor", "WaitForSingleObject", "PSExistingRoot", "GetFileAttributesW", "pocketstream-maintenance.json", "--firewall-maintenance ${mode}", "SetErrorLevel 71"]) {
    require(hooks.toLowerCase().includes(contract.toLowerCase()), `transaction contract missing: ${contract}`);
  }
  require(/PS_OPEN_MUTEX 'Global\\PocketStream\.Desktop\.InstallGate\.v2' 5000/.test(hooks), "installation gate must be bounded");
  require(/PS_OPEN_MUTEX 'Global\\PocketStream\.Desktop\.HostOwner\.v2' 5000/.test(hooks), "host wait must be bounded");
  require(hooks.includes("!define MUI_CUSTOMFUNCTION_ABORT PS_UserAbort") && hooks.includes("!define MUI_CUSTOMFUNCTION_UNABORT un.PS_UserAbort"), "MUI cancellation callbacks must invoke gate release hooks");
  require(!/ExecToStack[^\r\n]*-Verb|runas/i.test(hooks), "maintenance cannot launch nested elevation");
  return failures;
}

export function checkCompiledInstallerTrace(trace) {
  const failures=[];
  const functions=new Map([...trace.matchAll(/^Function: "([^"]+)"\r?\n([\s\S]*?)^FunctionEnd/gm)].map(m=>[m[1],m[2]]));
  for (const name of [".onInit","un.onInit"]) {
    const init=functions.get(name) ?? "";
    if (!init.includes("Global\\PocketStream.Desktop.InstallGate.v2") || !init.includes("Global\\PocketStream.Desktop.HostOwner.v2")) failures.push(`compiled ${name} lacks both machine guards`);
  }
  for (const name of [".onInstSuccess",".onGUIEnd",".onInstFailed","PS_UserAbort","un.onGUIEnd","un.onUninstSuccess","un.onUninstFailed","un.PS_UserAbort"]) {
    if (!(functions.get(name) ?? "").includes("ReleaseMutex")) failures.push(`compiled ${name} lacks release`);
  }
  if (!(functions.get(".onUserAbort") ?? "").includes("PS_UserAbort") || !(functions.get("un.onUserAbort") ?? "").includes("un.PS_UserAbort")) failures.push("compiled MUI cancellation does not reach transaction release");
  if (/^Plugin command:.*KillProcess|^ExecWait:.*(?:uninstall|msiexec)/im.test(trace)) failures.push("compiled destructive fallback returned");
  const success=functions.get(".onInstSuccess") ?? "";
  if (success.indexOf("ReleaseMutex")<0 || success.indexOf("ReleaseMutex")>success.indexOf("RunAsUser")) failures.push("compiled relaunch precedes release");
  if (!(functions.get("RunMainBinary") ?? "").includes("$PSLaunchRequested") || (functions.get("RunMainBinary") ?? "").includes("RunAsUser")) failures.push("compiled finish-page relaunch is not queued");
  for (const mode of ["install","uninstall"]) if (!trace.includes(`--firewall-maintenance ${mode}`)) failures.push(`compiled fixed ${mode} entry missing`);
  return failures;
}

export function checkRepository(generated, trace) {
  const source = read("src-tauri/installer/installer.nsi");
  const hooks = read("src-tauri/installer/transaction.nsh");
  const record = JSON.parse(read("src-tauri/installer/provenance.json"));
  const upstream = read("src-tauri/installer/installer.upstream.nsi").replaceAll("\r\n", "\n");
  const failures = checkInstaller(source, hooks);
  if (source.indexOf('!include "{{installer_hooks}}"') < source.indexOf("!addplugindir")) failures.push("transaction functions must follow plugin registration and template constants");
  if (crypto.createHash("sha256").update(upstream).digest("hex") !== record.source_sha256_lf) failures.push("upstream source hash drift");
  const config = JSON.parse(read("src-tauri/tauri.conf.json"));
  if (config.bundle.windows.nsis.template !== "installer/installer.nsi" || config.bundle.windows.nsis.installerHooks !== "installer/transaction.nsh" || config.bundle.windows.nsis.installMode !== "perMachine") failures.push("custom template/hook/per-machine configuration drift");
  const pkg=JSON.parse(read("package.json"));
  if (pkg.devDependencies["@tauri-apps/cli"] !== record.cli_version) failures.push("CLI must stay pinned to template provenance");
  if (pkg.scripts["check:installer:generated"] !== "node scripts/check-installer.mjs src-tauri/target/release/nsis/x64/installer.nsi --compile-trace") failures.push("generated installer contract must include the compiler trace");
  if (!read("src-tauri/pocketstream.exe.manifest").includes('level="requireAdministrator"')) failures.push("release elevation contract changed");
  if (generated) {
    const script = fs.readFileSync(generated, "utf8");
    failures.push(...checkInstaller(script, hooks).map(f => `generated: ${f}`));
    const includes = [...script.matchAll(/^!include "([^"]*transaction\.nsh)"/gm)];
    if (includes.length !== 1 || path.resolve(includes[0][1]) !== path.join(root, "src-tauri/installer/transaction.nsh")) failures.push("generated script does not include the reviewed transaction hook");
    if (/{{[#/]?\w/.test(script)) failures.push("unexpanded template in generated installer");
  }
  if (trace) failures.push(...checkCompiledInstallerTrace(trace));
  return failures;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let trace;
  const generated=process.argv[2];
  if (process.argv[3]==="--compile-trace") {
    const directory=path.resolve(path.dirname(generated));
    const cache=path.join(process.env.LOCALAPPDATA ?? "", "tauri/NSIS");
    const executable=[path.join(cache,"makensis.exe"),path.join(cache,"Bin/makensis.exe")].find(p=>fs.existsSync(p));
    if (!executable) throw new Error("Pinned NSIS compiler is unavailable; build the installer first");
    const args=["-INPUTCHARSET","UTF8","-OUTPUTCHARSET","UTF8","-DMUI_VERBOSE=4","-V4",path.resolve(generated)];
    const env={...process.env};
    delete env.NSISDIR; delete env.NSISCONFDIR;
    const result=spawnSync(executable,args,{cwd:directory,env,encoding:"utf8",maxBuffer:32*1024*1024,timeout:120000});
    fs.writeFileSync(path.join(directory,"compile-inspection.json"),JSON.stringify({executable,compiler_sha256:crypto.createHash("sha256").update(fs.readFileSync(executable)).digest("hex"),args,status:result.status,stderr:result.stderr,error:result.error?.message,installation_executed:false},null,2)+"\n");
    if (result.status!==0) throw new Error(`NSIS trace compilation failed: ${result.stderr || result.error}`);
    trace=result.stdout;
    fs.writeFileSync(path.join(directory,"installer.compile.log"),trace);
  }
  const failures = checkRepository(generated,trace);
  if (failures.length) { console.error(failures.join("\n")); process.exitCode = 1; }
  else console.log(`Installer ${trace ? "compiled-trace, generated-script and source" : generated ? "generated-script and source" : "source"} contracts passed; native transaction lifetime remains fixture qualification.`);
}
