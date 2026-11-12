const test = require('node:test');
const assert = require('node:assert/strict');
const core = require('../src/core.js');
const ORIGIN = 'https://example.okta.com';
const ID = '00u123456789abcdefghi';
const S = '2026-11-01T00:00:00Z';
const E = '2026-11-04T00:00:00Z';

test('builds bounded and encoded Okta log query', () => {
  const url = new URL(core.buildUserLogUrl(ORIGIN, ID, S, E, 'target.id'));
  assert.equal(url.pathname, '/api/v1/logs');
  assert.equal(url.searchParams.get('filter'), `target.id eq "${ID}"`);
  assert.equal(url.searchParams.get('until'), '2026-11-04T00:00:00.000Z');
  assert.equal(url.searchParams.get('since'), '2026-11-01T00:00:00.000Z');
});

test('rejects invalid query IDs and date windows', () => {
  assert.throws(()=>core.buildUserLogUrl(ORIGIN,'123" or eventType eq "abc',S,E));
  assert.throws(()=>core.validateWindow('2026-01-01','2026-03-01'),/31 days/);
  assert.throws(()=>core.validateWindow('2026-11-04','2026-11-01'),/end after/);
  const future=new Date(Date.now()+60*60*1000);
  assert.throws(()=>core.validateWindow(new Date(future.getTime()-86400000),future),/future/);
});

test('pagination follows same-origin next only',()=>{
  assert.equal(core.parseNextLink('<https://example.okta.com/api/v1/logs?after=opaque>; rel="next"',ORIGIN),'https://example.okta.com/api/v1/logs?after=opaque');
  assert.equal(core.parseNextLink('<https://example.okta.com/api/v1/logs>; rel="self"',ORIGIN),null);
  assert.throws(()=>core.parseNextLink('<https://malicious.example/collect>; rel="next"',ORIGIN),/Rejected/);
  assert.throws(()=>core.parseNextLink('<https://example.okta.com/api/v1/users>; rel="next"',ORIGIN),/Rejected/);
});

test('retrieves actor and target events, deduplicates, and reports pagination cap',async()=>{
  const calls=[];
  const fixture={uuid:'event-1',published:'2026-11-02T13:30:00Z',eventType:'user.session.start',outcome:{result:'FAILURE'}};
  const fetchPage=async url=>{calls.push(url);return {events:[fixture],link:url.includes('actor.id')?'<https://example.okta.com/api/v1/logs?after=next>; rel="next"':null};};
  const result=await core.collectLogs({origin:ORIGIN,userId:ID,since:S,until:E,requestPage:fetchPage,pagesPerFilter:1});
  assert.equal(result.events.length,1);assert.equal(result.pageLimitHit,true);assert.equal(calls.length,2);
});

test('classifies sign-in, provisioning, security separately',()=>{
  assert.equal(core.classify({eventType:'user.authentication.sso'}),'Sign-in');
  assert.equal(core.classify({eventType:'application.provision.user.push'}),'Provisioning');
  assert.equal(core.classify({eventType:'application.policy.sign_on.deny_access'}),'Security');
});

test('matches app target without guessing from message',()=>{
  const ev={target:[{id:'0oa123456789abc',type:'AppInstance'}],displayMessage:'Another app mentioned in text'};
  assert.equal(core.matchesApp(ev,'0oa123456789abc'),true);
  assert.equal(core.matchesApp(ev,'0oaBAD'),false);
});

test('CSV quotes fields and neutralizes spreadsheet formulas',()=>{
  const ev={published:'2026-11-01T00:00:00Z',eventType:'user.authentication.sso',displayMessage:'=HYPERLINK("https://bad.example","click")',actor:{alternateId:'"name",corp'},outcome:{result:'FAILURE',reason:'-VALUE'}};
  const csv=core.toCsv([ev]);
  assert.match(csv,/"'=HYPERLINK\(""https:\/\/bad.example""/);
  assert.match(csv,/"'-VALUE"/);
  assert.match(csv,/"""name"",corp"/);
  assert.equal(core.escapeCsv('\tcmd'),`"'\tcmd"`);
  assert.equal(core.escapeCsv('\rcmd'),`"'\rcmd"`);
  assert.equal(core.escapeCsv('plain text'),'"plain text"');
});

test('diagnostic hints only use actual failed event types',()=>{
  const events=[
    {eventType:'application.integration.authentication_failure',outcome:{result:'FAILURE'}},
    {eventType:'application.policy.sign_on.deny_access',outcome:{result:'SUCCESS'}},
    {eventType:'user.authentication.sso',outcome:{result:'FAILURE'}}
  ];
  const hints=core.triageHints(events);
  assert.equal(hints.length,1);
  assert.equal(hints[0].eventType,'application.integration.authentication_failure');
});

test('policy denials recorded as DENY are counted and produce hints',()=>{
  const events=[
    {eventType:'application.policy.sign_on.deny_access',outcome:{result:'DENY'}},
    {eventType:'user.authentication.sso',outcome:{result:'FAILURE'}},
    {eventType:'user.authentication.sso',outcome:{result:'SUCCESS'}}
  ];
  const s=core.summarize(events);
  assert.equal(s.failures,1);
  assert.equal(s.denials,1);
  assert.equal(core.isAdverse(events[0]),true);
  assert.equal(core.isAdverse(events[2]),false);
  const hints=core.triageHints(events);
  assert.equal(hints.length,1);
  assert.equal(hints[0].eventType,'application.policy.sign_on.deny_access');
});
