'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const {
  compareVersions,
  installUpdateIfAvailable,
} = require('../bin/feilian-cli.js');

test('compares release versions numerically', () => {
  assert.equal(compareVersions('1.0.2', '1.0.1'), 1);
  assert.equal(compareVersions('1.2.0', '1.2'), 0);
  assert.equal(compareVersions('1.2.3', '1.10.0'), -1);
  assert.equal(compareVersions('1.2.3-beta.1', '1.2.3'), 0);
});

test('--version reports the npm launcher version without starting native code', () => {
  const launcher = path.join(__dirname, '..', 'bin', 'feilian-cli.js');
  const result = spawnSync(process.execPath, [launcher, '--version'], {
    encoding: 'utf8',
  });

  assert.equal(result.status, 0);
  assert.equal(result.stdout.trim(), 'feilian-cli 1.0.4');
  assert.equal(result.stderr, '');
});

test('installs a newer version and returns its launcher', async () => {
  let installs = 0;
  const launcher = await installUpdateIfAvailable([], {
    installedVersion: '1.0.1',
    fetchVersion: async () => '1.0.2',
    installVersion: () => {
      installs += 1;
      return { status: 0 };
    },
    locateLauncher: () => '/npm/feilian-cli/bin/feilian-cli.js',
    log: () => {},
  });

  assert.equal(installs, 1);
  assert.equal(launcher, '/npm/feilian-cli/bin/feilian-cli.js');
});

test('--check-update remains read-only', async () => {
  let checked = false;
  const launcher = await installUpdateIfAvailable(['--check-update'], {
    fetchVersion: async () => {
      checked = true;
      return '99.0.0';
    },
  });

  assert.equal(checked, false);
  assert.equal(launcher, null);
});

test('continues the installed version when npm install fails', async () => {
  const launcher = await installUpdateIfAvailable([], {
    installedVersion: '1.0.1',
    fetchVersion: async () => '1.0.2',
    installVersion: () => ({ status: 1 }),
    locateLauncher: () => {
      throw new Error('must not locate launcher after a failed install');
    },
    log: () => {},
  });

  assert.equal(launcher, null);
});
