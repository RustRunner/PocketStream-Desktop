const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');

const repository = path.resolve(__dirname, '..');
const guest = path.join(repository, 'scripts/qualification/Invoke-PrivilegeSandbox.ps1');
const windows = process.platform === 'win32';

for (const args of [
  ['-Mode', 'Preflight'],
  ['-Mode', 'Supported'],
  ['-Hold', 'HostOwner', '-SignalRoot', 'C:\\PocketStreamQualification\\Results\\host-guard-test'],
  ['-Hold', 'InstallGate', '-SignalRoot', 'C:\\PocketStreamQualification\\Results\\host-guard-test'],
]) {
  test(`Sandbox fixture rejects a host invocation: ${args.join(' ')}`, { skip: !windows }, () => {
    const before = fs.existsSync('C:\\PocketStreamQualification');
    const result = spawnSync('powershell.exe', [
      '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', guest, ...args,
    ], {
      cwd: repository,
      encoding: 'utf8',
      timeout: 15000,
      // Spoofing environment variables must not bypass the real token check.
      env: { ...process.env, USERNAME: 'WDAGUtilityAccount' },
      windowsHide: true,
    });
    assert.ifError(result.error);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /only inside Windows Sandbox/);
    assert.equal(fs.existsSync('C:\\PocketStreamQualification'), before);
  });
}

test('Sandbox fixture scripts parse in Windows PowerShell 5.1', { skip: !windows }, () => {
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `
    $ErrorActionPreference='Stop'
    foreach($path in @('scripts/prepare-privilege-sandbox.ps1','scripts/qualification/Invoke-PrivilegeSandbox.ps1')) {
      $tokens=$null; $errors=$null
      $null=[Management.Automation.Language.Parser]::ParseFile((Join-Path (Get-Location) $path),[ref]$tokens,[ref]$errors)
      if($errors.Count) { throw ($errors.Message -join '; ') }
    }
  `], { cwd: repository, encoding: 'utf8', timeout: 15000, windowsHide: true });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
});
