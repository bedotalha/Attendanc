const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict'),path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'../server.js'),'utf8');
const start=source.indexOf('function locationInput('),end=source.indexOf('\nfunction signalHash(',start);
const ctx=vm.createContext({});vm.runInContext(source.slice(start,end),ctx);
const loc=(latitude,longitude,accuracy=10)=>({latitude,longitude,accuracy});
const state={courses:[{id:'a',locationLat:40,locationLon:40,locationPolicy:'block'}],sessionSettings:{locationPolicy:'block',locationRadiusM:200,devicePolicy:'warn'}};
const teacherA={courseId:'a',verificationSettings:{locationPolicy:'block',locationRadiusM:200,locationLat:30,locationLon:31,locationAccuracy:10}};
const teacherB={courseId:'a',verificationSettings:{locationPolicy:'block',locationRadiusM:200,locationLat:31,locationLon:32,locationAccuracy:10}};
const settings=session=>ctx.sessionVerificationSettings(state,session);
const check=(session,point,peers=[])=>ctx.assessLocation(settings(session),point,peers);

assert.equal(check(teacherA,loc(30,31)).status,'precise');
assert.equal(check(teacherA,loc(31,32)).status,'verify');
assert.equal(check(teacherB,loc(31,32)).status,'precise');
assert.equal(check(teacherB,loc(30,31)).status,'verify');

const noTeacher={courseId:'a',verificationSettings:{locationPolicy:'block',locationRadiusM:200}};
const first=check(noTeacher,loc(40,40));
assert.equal(first.status,'precise');assert.equal(first.source,'class');assert.equal(first.provisional,true);
const secondAway=check(noTeacher,loc(30,31),[loc(40,40)]);
assert.equal(secondAway.status,'verify');assert.equal(secondAway.provisional,true);
assert.equal(check(noTeacher,loc(30.0002,31),[loc(40,40),loc(30,31)]).status,'precise');
assert.equal(check(noTeacher,loc(30,31),[loc(30.0002,31)]).status,'precise');
assert.equal(check(noTeacher,loc(30.01,31),[loc(30,31),loc(30.0001,31),loc(30.0002,31)]).status,'verify');
assert.equal(check(noTeacher,loc(30,31,260),[loc(30,31)]).status,'low_accuracy');
assert.equal(check({...noTeacher,verificationSettings:{locationPolicy:'off'}},null).status,'disabled');

const pending={status:'awaiting_peers',source:'class',provisional:true};
const record=(deviceKey,point)=>({status:'present',deviceKey,locationPoint:point,verification:{location:{...pending}}});
const session={verificationSettings:{locationPolicy:'review',locationRadiusM:200},records:{
  seed:record('a',loc(40,40)),
  two:record('b',loc(30,31)),
  three:record('c',loc(30.0002,31))
}};
ctx.refreshPendingLocations(session,settings(session));
assert.equal(session.records.seed.status,'present');
assert.equal(session.records.seed.verification.location.status,'verify');
assert.equal(session.records.two.verification.location.status,'precise');
assert.equal(session.records.three.verification.location.source,'class');
const resolved=session.records.two.verification.location;
ctx.refreshPendingLocations(session,settings(session));
assert.equal(session.records.two.verification.location,resolved);

const shared={verificationSettings:session.verificationSettings,records:{
  first:record('shared',loc(30,31)), second:record('shared',loc(30.0001,31))
}};
ctx.finalizeSessionLocations(state,shared);
assert.equal(shared.records.first.verification.location.status,'unverified');
assert.equal(shared.records.first.verification.location.reason,'missing_peer_reference');
assert.equal(shared.records.first.locationPoint,undefined);
assert.equal(shared.records.first.status,'present');

const area={latitude:30,longitude:31,city:'Cairo',countryCode:'EG'};
const withTeacher={...settings(teacherA),teacherNetworkArea:area};
assert.equal(ctx.assessSessionLocation(withTeacher,loc(31,32),area,[],true).source,'teacher');
assert.equal(ctx.assessSessionLocation(withTeacher,loc(31,32),area,[],true).status,'verify');
const fallback=ctx.assessSessionLocation(withTeacher,loc(30,31,300),area,[],true);
assert.equal(fallback.status,'insufficient_accuracy');
assert.equal(fallback.reference,'teacher');

vm.runInContext(source.slice(source.indexOf('function mergeWorkspaceAttendance('),source.indexOf('function writeState(')),ctx);
for (const action of ['تعديل حضور','تعديل جماعي','مراجعة التحقق','مراجعة جماعية']) {
  const saved={sessions:[{id:'s',active:true,records:{student:{status:'present',source:'student',time:'original',verification:{location:{status:'precise'},network:'same_network'}}}}],auditLog:[]};
  const incoming={sessions:[{id:'s',active:true,records:{student:{status:'excused',verification:{location:pending,reviewedAt:'new'}}}}],auditLog:[{id:'e',at:'new',action,after:{sessionId:'s',studentId:'student',studentIds:['student'],status:'excused'}}]};
  ctx.mergeWorkspaceAttendance(incoming,saved);
  const latest=incoming.sessions[0].records.student;
  assert.equal(latest.verification.location.status,'precise');
  assert.equal(latest.verification.network,'same_network');
  assert.equal(latest.verification.reviewedAt,'new');
  assert.equal(latest.time,'original');
  assert.equal(latest.status,action.includes('مراجعة')?'present':'excused');
}

const current={status:'excused',manual:true,verification:{location:pending,reviewedAt:'new',device:'unique'}};
ctx.selectAttendanceRecord={get:()=>({record:JSON.stringify(current)})};
ctx.updateAttendance={run:data=>Object.assign(current,JSON.parse(data))};
vm.runInContext(source.slice(source.indexOf('function applyCheckinWrite('),source.indexOf('function flushPendingCheckinWrites(')),ctx);
const before={status:'present',verification:{location:pending,device:'unique'}};
ctx.applyCheckinWrite({id:'s',records:{student:{...before,verification:{...before.verification,location:{status:'precise'}}}}},new Map([['student',JSON.stringify(before)]]),[]);
assert.equal(current.status,'excused');
assert.equal(current.verification.reviewedAt,'new');
assert.equal(current.verification.location.status,'precise');

assert.ok(source.includes("const peerRecords = Object.entries(session.records || {}).filter(([studentId, record]) => studentId !== student.id && record);"));
assert.ok(source.includes("const peerLocations = peerRecords.filter(([, record]) => record.locationPoint).map(([, record]) => record.locationPoint);"));
assert.ok(source.includes('student = state.studentById.get(body.studentId);'));
assert.ok(source.includes('if (student?.courseId !== session.courseId) student = null;'));
assert.ok(source.includes('!locationAccepted && !locationCheck.provisional'));
assert.ok(source.includes("delete record.locationPoint"));
const html=fs.readFileSync(path.join(__dirname,'../index.html'),'utf8');
assert.ok(!html.includes('followup=locationStatus'));
assert.ok(!html.includes('locationVerificationPanel'));
assert.ok(html.includes('verificationCell(record,session.id,student.id)'));
assert.ok(html.includes('}},3500)'));
assert.ok(html.includes("if(record?.status==='verify'&&(record.source==='student'||record.time||record.verification?.reviewedAt))return record.lateByMinutes>0?'tardy':'present';"));
console.log('PASS teacher and cohort comparisons, first-location seeding, live cluster updates, no student location notice, and location review still counts as attendance.');
