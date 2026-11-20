const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync(require('node:path').join(__dirname,'../index.html'),'utf8');
const names=['countedSessions','studentsFor','studentsForSession','localDate','getStatus','reportRate','selectedReportSessions','reportStudentSummary'];
const extracted=names.map(name=>{const line=source.split(/\r?\n/).find(l=>l.trimStart().startsWith('function '+name+'('));assert.ok(line,name);return line}).join('\n');
const controls={'#reportCourse':{value:'a'},'#reportFrom':{value:''},'#reportTo':{value:''},'#reportPeriod':{value:'all'},'#reportDailySession':{value:''},'#reportAbsenceFilter':{checked:false}};
const db={courses:[{id:'a',name:'حركة',code:'BSC36',sectionName:'أ'},{id:'b',name:'حركة',code:'BSC36',sectionName:'ب'},{id:'c',name:'مقرر آخر'}],students:[{id:'sa',courseId:'a'},{id:'sb',courseId:'b'},{id:'sc',courseId:'c'}],sessions:[{id:'xa',courseId:'a',startedAt:'2026-10-10T11:00:00',active:false,records:{sa:{status:'present'}}},{id:'xb',courseId:'b',startedAt:'2026-10-10T11:00:00',active:false,records:{sb:{status:'absent'}}},{id:'xc',courseId:'c',startedAt:'2026-10-17T11:00:00',active:false,records:{sc:{status:'present'}}}]};
const context=vm.createContext({db,$:id=>controls[id],attendanceReviewPending:()=>false});vm.runInContext(extracted,context);
let passed=0;function check(label,fn){fn();passed++;console.log('PASS '+label)}
const ids=items=>Array.from(items,x=>x.id);
check('Students stay within each offering',()=>{for(const [course,student] of [['a','sa'],['b','sb'],['c','sc']])assert.deepEqual(ids(context.studentsFor(course)),[student])});
check('Session roster uses the correct offering',()=>assert.deepEqual(ids(context.studentsForSession(db.sessions[1])),['sb']));
check('Same name and code do not mix group reports',()=>{let rows=context.reportStudentSummary();assert.equal(rows.length,1);assert.equal(rows[0].student.id,'sa');assert.equal(rows[0].rate,100);controls['#reportCourse'].value='b';rows=context.reportStudentSummary();assert.equal(rows[0].student.id,'sb');assert.equal(rows[0].rate,0)});
check('New enrollment updates only its own offering',()=>{db.students.push({id:'sa2',courseId:'a'});assert.equal(context.studentsFor('a').length,2);assert.equal(context.studentsFor('b').length,1);controls['#reportCourse'].value='a';const rows=context.reportStudentSummary();assert.equal(rows[1].absent,1);assert.equal(rows[1].total,1)});
check('Date filters exclude other sessions',()=>{controls['#reportPeriod'].value='custom';controls['#reportFrom'].value='2026-10-17';assert.equal(context.selectedReportSessions().length,0);controls['#reportFrom'].value='';controls['#reportPeriod'].value='all'});
check('Daily session selection cannot cross course boundaries',()=>{controls['#reportPeriod'].value='day';controls['#reportDailySession'].value='xb';assert.equal(context.selectedReportSessions().length,0);controls['#reportPeriod'].value='all'});
check('Unassigned students are excluded from every offering',()=>{db.students.push({id:'global',courseId:null});assert.ok(!context.studentsFor('a').some(s=>s.id==='global'));assert.ok(!context.studentsFor('b').some(s=>s.id==='global'));assert.ok(!context.studentsFor('c').some(s=>s.id==='global'))});
console.log(passed+' checks passed. Fixtures are in memory; no live data read or changed.');
