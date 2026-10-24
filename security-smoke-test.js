'use strict';
const assert = require('assert');
const security = require('./security');

assert.strictEqual(security.validateStartupCommand('node index.js').ok, true);
assert.strictEqual(security.validateStartupCommand('node -e process.exit()').ok, false);
assert.strictEqual(security.validateStartupCommand('npm install express').ok, true);
assert.strictEqual(security.validateStartupCommand('bash -c whoami').ok, false);
assert.strictEqual(security.isSafeExtractPath('/tmp/base', 'folder/file.txt'), true);
assert.strictEqual(security.isSafeExtractPath('/tmp/base', '../outside.txt'), false);
assert.strictEqual(security.isSafeExtractPath('/tmp/base', '/etc/passwd'), false);
assert.strictEqual(security.isAllowedGithubSource('github:user/repo#v1.2.3'), true);
assert.strictEqual(security.isAllowedGithubSource('git+ssh://github.com/user/repo.git'), false);
console.log('Security helper smoke tests passed.');
