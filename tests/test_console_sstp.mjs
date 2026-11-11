import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const html = fs.readFileSync(new URL('../vps/fanout/console.html', import.meta.url), 'utf8');
const region = (start, end) => html.slice(html.indexOf(start), html.indexOf(end, html.indexOf(start)));
const source = [region('      function loadResourceSstp(', '      function resourceSocksURL('),
  region('      function resourceResult(', '      function resourceFiltered('),
  region('      async function checkSstpResources(', '      async function resourceExport(')].join('\n');
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return {promise, resolve, reject}; };
const row = () => ({hostname:'test.opengw.net', result:{status:'not_tested'}});
const context = (api) => {
  const c = vm.createContext({api, resourceData:{nodes:[row()]}, resourceSubmitting:new Set(),
    resourceEpoch:0, resourcesPolling:null, currentPage:'resources', renderResources(){}});
  vm.runInContext(source, c); return c;
};

assert.match(html, /data-sstp-promote=/, 'verified SSTP has no VPS promotion control');
assert.match(html, /api\/resources\/sstp\/promote/, 'promotion control is not wired to the private API');
assert.match(html, /不会回落到 VPS 直连/, 'persistent SSTP does not explain fail-closed behavior');

// A terminal deferred/cancelled/save failure must never revert to "not tested".
for (const status of ['deferred', 'cancelled', 'failed', 'queued', 'running']) {
  const c = context(() => {}); const n = row(); n.attempt = {status,code:'candidate_in_use'};
  assert.equal(c.resourceResult(n).status, status);
}
{
  const c = context(() => {}); const n = row();
  n.result = {status:'passed', checked_at:'same', stale:true, ip_type:'unknown'};
  n.attempt = {status:'passed', checked_at:'same', stale:false};
  assert.equal(c.resourceResult(n).stale, true, 'expired/changed evidence was revived by a job snapshot');
}
{
  const oldGet = deferred(), post = deferred(), freshGet = deferred(); let gets = 0;
  const c = context((path) => path.endsWith('/check') ? post.promise : (++gets === 1 ? oldGet.promise : freshGet.promise));
  const oldRequest = c.loadResourceSstp();
  const checking = c.checkSstpResources({hosts:['test.opengw.net'], priority:true});
  assert.equal(c.resourceResult(c.resourceData.nodes[0]).status, 'submitting');
  post.resolve({status:'done', items:[{host:'test.opengw.net', status:'deferred', code:'candidate_in_use'}]});
  await new Promise(setImmediate);
  assert.equal(gets, 2, 'submission reused a GET started before the POST');
  freshGet.resolve({nodes:[{...row(), attempt:{status:'deferred',code:'candidate_in_use'}}],check:{status:'done'}});
  await checking;
  assert.equal(c.resourceResult(c.resourceData.nodes[0]).status, 'deferred');
  oldGet.resolve({nodes:[row()],check:null}); await oldRequest;
  assert.equal(c.resourceResult(c.resourceData.nodes[0]).status, 'deferred', 'late stale GET erased the terminal attempt');
  assert.equal(c.resourcesPolling, null);
}
{
  const get = deferred(); const c = context((path) => path.endsWith('/check')
    ? Promise.resolve({status:'running',items:[{host:'test.opengw.net',status:'running'}]}) : get.promise);
  const checking = c.checkSstpResources({all:true});
  assert.equal(c.resourceResult(c.resourceData.nodes[0]).status, 'submitting', 'batch click had no immediate feedback');
  await new Promise(setImmediate);
  get.reject(Error('temporary poll failure')); await assert.rejects(checking);
  assert.equal(c.resourceResult(c.resourceData.nodes[0]).status, 'running', 'accepted job disappeared after refresh failure');
  assert.equal(c.resourceSubmitting.size, 0);
}
console.log('SSTP terminal-state and stale-poll regressions passed');
