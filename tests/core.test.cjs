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

// ---- Provisioning diagnosis (synthetic fixtures) ----
const APP = {id:'0oaSYNTHAPP0001',type:'AppInstance',displayName:'Synthetic SCIM App'};
const USER = {id:ID,type:'User',alternateId:'test.user@example.com'};
function prov(over){
  return Object.assign({uuid:'u-'+Math.random().toString(36).slice(2),published:'2026-11-02T10:00:00.000Z',eventType:'application.provision.user.push',outcome:{result:'SUCCESS'},target:[USER,APP],transaction:{type:'JOB',id:'pujSYNTH1'}},over);
}

test('classifies recorded provisioning errors into specific causes',()=>{
  const cases=[
    [{outcome:{result:'FAILURE',reason:'Error while creating user: 409 Conflict - user already exists'}},'account_conflict'],
    [{outcome:{result:'FAILURE',reason:'401 Unauthorized: invalid API token'}},'downstream_auth'],
    [{outcome:{result:'FAILURE',reason:'HTTP 429 Too Many Requests'}},'rate_limited'],
    [{outcome:{result:'FAILURE'},debugContext:{debugData:{errorMessage:'Required attribute "department" is missing'}}},'attribute_mapping'],
    [{outcome:{result:'FAILURE',reason:'503 Service Unavailable'}},'downstream_unavailable'],
    [{outcome:{result:'FAILURE',reason:'No licenses available for this product'}},'license_or_quota'],
    [{outcome:{result:'FAILURE',reason:'Unable to parse response from SCIM server'}},'response_format'],
    [{outcome:{result:'FAILURE',reason:'Something unexpected happened'}},'unrecognized']
  ];
  for(const [over,id] of cases) assert.equal(core.provisioningCause(prov(over)).id,id,JSON.stringify(over));
});

test('failure with no error text points to Okta Tasks instead of guessing',()=>{
  // Shape based on a real low-detail SCIM sync failure: only appname in debugData.
  const ev=prov({eventType:'application.provision.user.sync',outcome:{result:'FAILURE'},legacyEventType:'app.user_management.provision_user_failed',debugContext:{debugData:{appname:'scim2headerauth'}}});
  assert.equal(core.isProvisioningFailure(ev),true);
  const cause=core.provisioningCause(ev);
  assert.equal(cause.id,'no_detail');
  assert.match(cause.checks.join(' '),/Dashboard > Tasks/);
});

test('error text ignores URLs and secrets in debugData',()=>{
  const ev=prov({outcome:{result:'FAILURE'},debugContext:{debugData:{requestUri:'/api/v1/apps/x/users/401',authToken:'error-secret',errorMessage:'Invalid email format'}}});
  assert.equal(core.provisioningErrorText(ev),'Invalid email format');
});

test('legacy provision_user_failed counts as failure even without FAILURE result',()=>{
  assert.equal(core.isProvisioningFailure(prov({outcome:{result:'UNKNOWN'},legacyEventType:'app.user_management.provision_user_failed'})),true);
  assert.equal(core.isProvisioningFailure(prov({})),false);
  assert.equal(core.isProvisioningFailure({eventType:'user.session.start',outcome:{result:'FAILURE'}}),false);
});

test('groups attempts by transaction, reports evidence and later recovery',()=>{
  const events=[
    prov({uuid:'a1',published:'2026-11-02T10:00:00.000Z',eventType:'application.user_membership.add',transaction:{type:'WEB',id:'txA'}}),
    prov({uuid:'a2',published:'2026-11-02T10:00:05.000Z',transaction:{type:'WEB',id:'txA'},outcome:{result:'FAILURE',reason:'400 Bad Request: invalid value for userName'}}),
    prov({uuid:'b1',published:'2026-11-03T09:00:00.000Z',transaction:{type:'JOB',id:'txB'}}),
    {uuid:'s1',published:'2026-11-02T09:59:00.000Z',eventType:'user.session.start',outcome:{result:'SUCCESS'},transaction:{id:'txS'}}
  ];
  const d=core.diagnoseProvisioning(events,null);
  assert.equal(d.attempts.length,2);
  assert.equal(d.failedAttempts,1);
  const failed=d.attempts.find(a=>a.failed);
  assert.equal(failed.transactionId,'txA');
  assert.equal(failed.app,'Synthetic SCIM App');
  assert.deepEqual(failed.eventTypes,['application.user_membership.add','application.provision.user.push']);
  assert.equal(failed.causes[0].id,'attribute_mapping');
  assert.equal(failed.causes[0].evidence[0].eventId,'a2');
  assert.match(failed.causes[0].evidence[0].recorded,/invalid value for userName/);
  assert.equal(d.lastFailure,'2026-11-02T10:00:05.000Z');
  assert.equal(d.recoveredAt,'2026-11-03T09:00:00.000Z');
});

test('interprets app-user syncState and status',()=>{
  const f=core.interpretAppUser({status:'STAGED',syncState:'ERROR',lastSync:'2026-11-02T10:00:05.000Z'});
  assert.equal(f[0].level,'error');assert.match(f[0].text,/ERROR.*Dashboard > Tasks/);
  assert.ok(f.some(x=>/STAGED/.test(x.text)));
  assert.ok(f.some(x=>/Last sync/.test(x.text)));
  assert.equal(core.interpretAppUser({syncState:'SYNCHRONIZED'})[0].level,'ok');
  assert.deepEqual(core.interpretAppUser(null),[]);
});

test('CSV includes provisioning cause column',()=>{
  const csv=core.toCsv([prov({outcome:{result:'FAILURE',reason:'409 Conflict'}})]);
  assert.match(csv.split('\r\n')[0],/"cause"$/);
  assert.match(csv.split('\r\n')[1],/"account_conflict"$/);
});


test('later success in another app, user, or operation is not presented as recovery',()=>{
  const failure=prov({uuid:'fail',published:'2026-11-02T10:00:00.000Z',
    transaction:{id:'txFailure'},outcome:{result:'FAILURE',reason:'409 Conflict'}});
  const otherApp={id:'0oaSYNTHAPP0002',type:'AppInstance',displayName:'Unrelated app'};
  const otherUser={id:'00uOTHERUSER12345',type:'User'};
  const later='2026-11-03T10:00:00.000Z';
  const unrelated=[
    prov({uuid:'other-app',published:later,target:[USER,otherApp],transaction:{id:'txOtherApp'}}),
    prov({uuid:'other-user',published:later,target:[otherUser,APP],transaction:{id:'txOtherUser'}}),
    prov({uuid:'other-operation',published:later,eventType:'application.provision.user.sync',transaction:{id:'txOtherAction'}})
  ];
  const d=core.diagnoseProvisioning([failure,...unrelated],null);
  assert.equal(d.failedAttempts,1);
  assert.equal(d.recoveredAt,'');
  assert.equal(d.attempts.find(a=>a.failed).recoveredAt,'');
});

test('matching subsequent success indicates only a matching retry, not all failures resolved',()=>{
  const first=prov({uuid:'failure-a',published:'2026-11-02T09:00:00.000Z',transaction:{id:'failure-a'},outcome:{result:'FAILURE',reason:'400 Invalid value'}});
  const second=prov({uuid:'failure-b',published:'2026-11-02T10:00:00.000Z',transaction:{id:'failure-b'},outcome:{result:'FAILURE',reason:'403 Forbidden'}});
  const success=prov({uuid:'retry-ok',published:'2026-11-03T12:00:00.000Z',transaction:{id:'retry-1'}});
  const d=core.diagnoseProvisioning([first,second,success],null);
  assert.equal(d.failedAttempts,2);
  assert.equal(d.recoveredAt,'2026-11-03T12:00:00.000Z');
  const differentActionFailure=prov({uuid:'failure-untreated',published:'2026-11-04T12:00:00.000Z',eventType:'application.provision.user.sync',
    transaction:{id:'sync-fail'},outcome:{result:'FAILURE',reason:'500 Failed'}});
  const next=core.diagnoseProvisioning([first,second,success,differentActionFailure],null);
  assert.equal(next.recoveredAt,'');
  assert.equal(next.lastFailure,'2026-11-04T12:00:00.000Z');
});

test('redacts embedded credentials, URL, email, and IP from error evidence and CSV',()=>{
  const event=prov({
    outcome:{result:'FAILURE',reason:'401 Unauthorized: Authorization: Bearer supersecret123 sent to https://example.invalid/api?token=hidden123 for jane.doe@example.com (192.0.2.8)'},
    debugContext:{debugData:{errorMessage:'api_key=privatekey42 client_secret="secretdetail99"',authToken:'do-not-include'}},
    displayMessage:'Token: password123 at https://example.invalid/x?api_key=moresecret'
  });
  const evidence=core.provisioningErrorText(event);
  const csv=core.toCsv([event]);
  const table=core.rowFor(event);
  for(const value of ['supersecret123','hidden123','jane.doe@example.com','192.0.2.8','privatekey42','secretdetail99','password123','moresecret','do-not-include']){
    assert.equal(evidence.includes(value),false,'evidence leaked '+value);
    assert.equal(csv.includes(value),false,'CSV leaked '+value);
    assert.equal((table.reason + table.message).includes(value),false,'table leaked '+value);
  }
  assert.match(evidence,/401 Unauthorized/);
  assert.match(evidence,/redacted/);
});

test('missing user or app identity cannot create a recovered signal',()=>{
  const fail=prov({published:'2026-11-02T10:00:00.000Z',outcome:{result:'FAILURE',reason:'failed'},
    transaction:{id:'fail'},target:[APP]});
  const next=prov({published:'2026-11-03T10:00:00.000Z',transaction:{id:'ok'},target:[APP]});
  assert.equal(core.diagnoseProvisioning([fail,next],null).recoveredAt,'');
});
