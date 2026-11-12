import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const read = name => fs.readFileSync(new URL('../vps/fanout/' + name, import.meta.url), 'utf8');
const section = (text, a, b) => text.slice(text.indexOf(a), text.indexOf(b, text.indexOf(a)));
const html = read('console.html');
const elements = Object.fromEntries(['targetCount','targetCountry','targetServer','targetHelp','targetDialog'].map(id => [id, {showModal() {this.open = true;}}]));
const c = vm.createContext({elements, summary:{capacity:8000,target:0,target_configured:false,suggested_target:16}, toast() {throw Error('unexpected toast');}});
vm.runInContext('const $ = id => elements[id];\n' + section(html, '      function openTarget()', '      function openExit('), c);
c.openTarget(); assert.equal(elements.targetCount.value, 16);
c.summary.target_configured = true;
c.openTarget(); assert.equal(elements.targetCount.value, 0, 'saved zero was overwritten');
c.summary.target = 24;
c.openTarget(); assert.equal(elements.targetCount.value, 24, 'existing target was overwritten');

const advanced = read('advanced.html');
const nodes = {'#list':{}, '#orphans':{}, '#hostConnections':{}, '#nativeConnections':{}, '#ecount':{}, '#exportAll':{}};
const s = vm.createContext({nodes, isNative:()=>true, view:{host_direct:[{id:1,port:30100,protocol:'vless',remark:'VPS',enable:true}], exits:[{slot:2,status:'waiting',inbounds:[{id:2,port:30002,protocol:'vless',enable:true,managed_slot:true},{id:3,port:32145,protocol:'vless',enable:false,manual:true}]}],direct:[{id:4,port:32146,protocol:'vless',enable:true}]},STATUS:{waiting:'等待候选'},esc:x=>String(x??''),exitName:e=>'出口 '+e.slot,connectionName:(i,e)=>'出口 '+e.slot});
vm.runInContext('const $ = id => nodes[id];\n' + section(advanced,'      function renderNativeConnections()',"      document.addEventListener('click', async e => {") + section(advanced,'      function exitOptions(', '      function renderDetail('), s);
s.renderNativeConnections();
assert.equal(nodes['#ecount'].textContent,'4 个入口');
assert.equal(nodes['#list'].hidden,true);
const output = nodes['#nativeConnections'].innerHTML;
assert.match(output,/自动入口/); assert.match(output,/手动入口/);
assert.match(output,/未绑定 · 阻断/);
assert.match(output,/data-entry-toggle="3"/);
assert.match(output,/data-delone="3"/);
assert.doesNotMatch(output,/data-delone="2"/, 'automatic entry offers misleading delete');
assert.match(output,/data-delone="4"/, 'unbound manual entry is hidden');
assert.match(s.exitOptions('',2),/value="slot:2" selected>出口 2 · 等待候选/,'waiting slot cannot be bound');
console.log('console flow regressions passed');

const warningNodes = {globalNotice: {}};
const warningContext = vm.createContext({nodes: [], s: {candidates: 0}, document: {}, errors: {}, renderPoolRefresh() {}, $: id => warningNodes[id]});
vm.runInContext(section(html, '        const missingPool =', '        renderProgress();'), warningContext);
assert.equal(warningNodes.globalNotice.hidden, false);
assert.match(warningNodes.globalNotice.textContent, /尚未取得 VPN Gate/);
assert.match(warningNodes.globalNotice.textContent, /第三方 SOCKS5/);
warningContext.nodes = [{}];
warningContext.s = {pool_generated_at: '2026-10-24T00:00:00Z'};
vm.runInContext('{\n' + section(html, '        const missingPool =', '        renderProgress();') + '\n}', warningContext);
assert.equal(warningNodes.globalNotice.hidden, true, 'outage notice survived a recovered pool');

const feedbackContext = vm.createContext({date: x => x});
vm.runInContext(section(html, '      function poolRefreshFeedback(', '      function renderPoolRefresh()'), feedbackContext);
let f = feedbackContext.poolRefreshFeedback({status:'running',elapsed_seconds:12,timeout_seconds:90},0);
assert.equal(f.running, true); assert.match(f.text,/12 秒/);
f = feedbackContext.poolRefreshFeedback({status:'failed',cause:'pool_refresh_timeout',checked_at:'test-time'},0);
assert.equal(f.error,true); assert.match(f.text,/刷新超时/); assert.match(f.text,/仍未取得候选/); assert.match(f.text,/test-time/);
assert.doesNotMatch(f.text,/保留旧清单/);
f = feedbackContext.poolRefreshFeedback({status:'passed'},99);
assert.match(f.text,/99 个候选/); assert.match(f.text,/仍需检测/);
const waitingWarning = vm.createContext({nodes:[],s:{refresh:{status:'failed'}},renderPoolRefresh(){},$:id=>warningNodes[id]});
vm.runInContext(section(html,'        const missingPool =','        renderProgress();'),waitingWarning);
assert.equal(warningNodes.globalNotice.hidden,true,'generic missing-pool banner masks actual failure');

let resolveRefresh;
let refreshCalls = 0;
const refreshContext = vm.createContext({AbortController,setTimeout,clearTimeout,summary:{},poolRefreshSubmitting:false,poolRefreshEpoch:0,render(){},
  api(){refreshCalls++;return new Promise(resolve=>{resolveRefresh=resolve;});},async poll(){}});
vm.runInContext(section(html,'      async function refreshPool()', '      function openTarget()'),refreshContext);
const refreshTask = refreshContext.refreshPool();
assert.equal(refreshContext.summary.refresh.status,'running','click has no immediate progress');
assert.equal(refreshContext.poolRefreshSubmitting,true);
await refreshContext.refreshPool(); assert.equal(refreshCalls,1,'double click starts duplicate request');
resolveRefresh({status:'running'}); await refreshTask;
assert.equal(refreshContext.poolRefreshSubmitting,false);
refreshContext.summary.refresh = {};
refreshContext.api = async()=>{throw Error('connection lost');};
await assert.rejects(refreshContext.refreshPool());
assert.equal(refreshContext.summary.refresh.status,'failed');
assert.equal(refreshContext.summary.refresh.cause,'pool_refresh_submit_failed');

const sourceTextContext = vm.createContext({date: x => x});
vm.runInContext(section(html,'      function poolSourceText(', '      function render()'),sourceTextContext);
let sourceText = sourceTextContext.poolSourceText({},'');
assert.match(sourceText,/本 VPS/); assert.match(sourceText,/尚未取得/);
sourceText = sourceTextContext.poolSourceText({kind:'mirror',label:'第三方镜像 · 本 VPS 获取',retrieved_at:'local-now',snapshot_fetched_at:'older-snapshot',stale:true,integrity_verified:true},'local-now');
assert.match(sourceText,/local-now/); assert.match(sourceText,/older-snapshot/); assert.match(sourceText,/快照较旧/);
assert.match(sourceText,/文件完整性/); assert.match(sourceText,/本 VPS 建连/); assert.doesNotMatch(sourceText,/检测通过/);

const sourceElements = Object.fromEntries(['sourceDialog','sourcePolicy','sourceTimeout','sourceMirrorMaxAge','sourceSettingsButton','sourceForm','saveSourceSettings'].map(id=>[id,{}]));
sourceElements.sourceDialog.showModal=function(){this.open=true;};
sourceElements.sourceDialog.close=function(){this.open=false;};
let sourceTask, savedSource, sourcePreference = false;
const sourceContext = vm.createContext({sourceSettingsLoading:false,sourceSettingsSaving:false,$:id=>sourceElements[id],toast(){},
  action(fn){sourceTask=fn();return sourceTask;}, async api(path,body){
    assert.equal(path,'api/console/source-settings');
    if(body!==undefined){savedSource=body;return body;}
    return {mirror_enabled:sourcePreference,source_timeout_seconds:10,mirror_max_age_hours:24};
  }});
vm.runInContext(section(html,'      async function openSourceSettings()', '      async function refreshPool()'),sourceContext);
await sourceContext.openSourceSettings();
assert.equal(sourceElements.sourcePolicy.value,'official_only','saved official-only choice overwritten');
sourceElements.sourcePolicy.value='official_then_mirror';
sourceElements.sourceForm.onsubmit({preventDefault(){}});await sourceTask;
assert.equal(savedSource.mirror_enabled,true); assert.equal(savedSource.source_timeout_seconds,10);
assert.equal(savedSource.mirror_max_age_hours,24);assert.equal(Object.keys(savedSource).length,3,'unrelated settings submitted');
sourcePreference = true;
await sourceContext.openSourceSettings();
assert.equal(sourceElements.sourcePolicy.value,'official_then_mirror','server default not displayed');
