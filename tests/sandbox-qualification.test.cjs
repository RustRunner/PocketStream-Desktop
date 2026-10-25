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
    foreach($path in @('scripts/prepare-privilege-sandbox.ps1','scripts/qualification/Invoke-PrivilegeSandbox.ps1','scripts/qualification/Invoke-PrivilegeSandboxFailures.ps1','scripts/qualification/Invoke-PrivilegeSandboxRemaining.ps1','scripts/qualification/Invoke-PrivilegeSandboxControl.ps1','scripts/qualification/Inspect-A4Host.ps1','scripts/qualification/Invoke-A4HostSession.ps1','scripts/qualification/Invoke-A4HostUi.ps1','scripts/qualification/Observe-A4Host.ps1','src-tauri/installer/uninstall-bootstrap.ps1','scripts/prepare-installer-prerequisites.ps1')) {
      $tokens=$null; $errors=$null
      $null=[Management.Automation.Language.Parser]::ParseFile((Join-Path (Get-Location) $path),[ref]$tokens,[ref]$errors)
      if($errors.Count) { throw ($errors.Message -join '; ') }
    }
  `], { cwd: repository, encoding: 'utf8', timeout: 15000, windowsHide: true });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
});

test('Remaining A4 scenarios reject the host before prerequisite or policy access', { skip: !windows }, () => {
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', path.join(repository, 'scripts/qualification/Invoke-PrivilegeSandboxRemaining.ps1')], {
    cwd: repository, encoding: 'utf8', timeout: 15000, windowsHide: true,
    env: { ...process.env, USERNAME: 'WDAGUtilityAccount' },
  });
  assert.ifError(result.error);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /only inside Windows Sandbox/);
});

test('Standalone bootstrap rejects an unprotected repository copy before elevation or mutation', { skip: !windows }, () => {
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', path.join(repository, 'src-tauri/installer/uninstall-bootstrap.ps1'), '-Silent'], {
    cwd: repository, encoding: 'utf8', timeout: 15000, windowsHide: true,
  });
  assert.ifError(result.error);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /protected installation root/);
});

test('Supplemental payload failures reject host execution before accessing native state', { skip: !windows }, () => {
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', path.join(repository, 'scripts/qualification/Invoke-PrivilegeSandboxFailures.ps1')], {
    cwd: repository, encoding: 'utf8', timeout: 15000, windowsHide: true,
    env: { ...process.env, USERNAME: 'WDAGUtilityAccount' },
  });
  assert.ifError(result.error);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /only inside Windows Sandbox/);
});

test('Sandbox preservation setup creates three distinct native rule names', { skip: !windows }, () => {
  const declaration = fs.readFileSync(guest, 'utf8').match(/^\s*\$preserveNames\s*=\s*(.+)$/m);
  assert.ok(declaration, 'preservation declaration missing');
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
    `$seed='PocketStream.Qualification.test'; $preserveNames=${declaration[1]}; ConvertTo-Json -InputObject $preserveNames -Compress`,
  ], { cwd: repository, encoding: 'utf8', timeout: 15000, windowsHide: true });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), [
    'PocketStream.Qualification.test.block',
    'PocketStream.Qualification.test.foreign',
    'PocketStream.Qualification.test.unrelated',
  ]);
});

test('uninstall fixture waits for registry and rules after the image disappears', { skip: !windows }, () => {
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `
    $ErrorActionPreference='Stop'
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path (Get-Location) 'scripts/qualification/Invoke-PrivilegeSandbox.ps1'),[ref]$tokens,[ref]$errors)
    $fn=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Wait-Uninstalled'},$true)
    if(!$fn){throw 'Missing completion wait'}
    . ([scriptblock]::Create($fn.Extent.Text))
    $image='image'; $uninstallKey='registration'; $script:polls=0
    function Test-Path { param($LiteralPath)
      if($LiteralPath -eq 'image'){$script:polls++; return $false}
      return $script:polls -lt 3
    }
    function Owned { if($script:polls -lt 5){return 'still present'} }
    Wait-Uninstalled
    if($script:polls -lt 5){throw 'Completion was reported before all postconditions'}
    Write-Output $script:polls
  `], { cwd: repository, encoding: 'utf8', timeout: 15000, windowsHide: true });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.ok(Number(result.stdout.trim()) >= 5);
});

test('listener fixture resets the output protocol independently of its UDP input', { skip: !windows }, () => {
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `
    $ErrorActionPreference='Stop'
    function Assert([bool]$Condition,[string]$Reason){if(!$Condition){throw $Reason}}
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path (Get-Location) 'scripts/qualification/Invoke-PrivilegeSandboxRemaining.ps1'),[ref]$tokens,[ref]$errors)
    $fn=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Set-Section'},$true)
    . ([scriptblock]::Create($fn.Extent.Text))
    $config=[IO.Path]::GetTempFileName()
    try {
      [IO.File]::WriteAllText($config, 'restream_protocol = "srt"'+[Environment]::NewLine+'[stream]'+[Environment]::NewLine+'protocol = "udp"'+[Environment]::NewLine)
      Set-Section '' 'restream_protocol' '"rtsp"'
      $actual=[IO.File]::ReadAllText($config)
      if($actual -notmatch '(?m)^restream_protocol = "rtsp"\\s*$' -or $actual -notmatch '(?m)^protocol = "udp"\\s*$'){throw 'Output reset changed the input protocol or left SRT selected.'}
    } finally { [IO.File]::Delete($config) }
  `], { cwd: repository, encoding: 'utf8', timeout: 15000, windowsHide: true });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
});
