const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const net = require('node:net');
const { DatabaseSync } = require('node:sqlite');
const QRCode = require('qrcode');

const PORT = Number(process.env.PORT || 4173);
const HOST = process.env.ATTEND_BIND_HOST || '127.0.0.1';
const MAX_BODY_BYTES = 8 * 1024 * 1024;
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const IP_AREA_CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const IP_AREA_NEGATIVE_CACHE_TTL_MS = 5 * 60 * 1000;
const IP_AREA_CACHE_LIMIT = 2048;
const IP_AREA_MATCH_RADIUS_M = 50_000;
const ipAreaCache = new Map();
const peerVerificationRefreshTimers = new Map();
const pendingCheckinWrites = [];
const pendingStudentCheckins = new Map();
const pendingDeviceCheckins = new Map();
let checkinWriteTimer = null;
const sessionsEnding = new Set();
const sessionsChanging = new Set();
let checkinBaseStateCache = null;
const dataDirectory = path.join(__dirname, 'data');
fs.mkdirSync(dataDirectory, { recursive: true });

const database = new DatabaseSync(path.join(dataDirectory, 'attendance.sqlite'));
database.exec(`
  CREATE TABLE IF NOT EXISTS app_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    data TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
  PRAGMA journal_mode = WAL;
  PRAGMA busy_timeout = 3000;
  CREATE TABLE IF NOT EXISTS attendance_records (session_id TEXT, student_id TEXT, record TEXT NOT NULL, PRIMARY KEY(session_id,student_id)) WITHOUT ROWID;
  CREATE TABLE IF NOT EXISTS checkin_audit (event TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS checkin_students (id TEXT PRIMARY KEY, student TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS instructor_credentials (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS app_settings (
    setting_key TEXT PRIMARY KEY,
    setting_value TEXT NOT NULL
  );
  INSERT OR IGNORE INTO app_state (singleton, data, updated_at)
    VALUES (1, '{"courses":[],"students":[],"sessions":[],"auditLog":[]}', CURRENT_TIMESTAMP);
`);

const selectState = database.prepare('SELECT data FROM app_state WHERE singleton = 1');
const updateState = database.prepare(`
  UPDATE app_state SET data = ?, updated_at = ? WHERE singleton = 1
`);
const selectCredentials = database.prepare('SELECT salt, password_hash FROM instructor_credentials WHERE singleton = 1');
const insertCredentials = database.prepare(`
  INSERT INTO instructor_credentials (singleton, salt, password_hash, created_at)
  VALUES (1, ?, ?, ?)
`);
const pinSecretRow = database.prepare('SELECT setting_value FROM app_settings WHERE setting_key = ?').get('pin_secret');
const pinSecret = pinSecretRow?.setting_value || crypto.randomBytes(32).toString('hex');
if (!pinSecretRow) database.prepare('INSERT INTO app_settings (setting_key, setting_value) VALUES (?, ?)').run('pin_secret', pinSecret);
const activeSessions = new Map();
const failedLogins = new Map();

function securityHeaders(response) {
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Referrer-Policy', 'same-origin');
  response.setHeader('X-Frame-Options', 'DENY');
  response.setHeader('Permissions-Policy', 'geolocation=(self)');
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'");
}

function sendJson(response, status, value, extraHeaders = {}) {
  securityHeaders(response);
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...extraHeaders });
  response.end(JSON.stringify(value));
}

function parseCookies(request) {
  return Object.fromEntries((request.headers.cookie || '').split(';').map(part => part.trim()).filter(Boolean).map(part => {
    const separator = part.indexOf('=');
    return [part.slice(0, separator), decodeURIComponent(part.slice(separator + 1))];
  }));
}

function currentSession(request) {
  const token = parseCookies(request).attendzy_session;
  const session = token && activeSessions.get(token);
  if (!session || session.expiresAt < Date.now()) {
    if (token) activeSessions.delete(token);
    return null;
  }
  session.expiresAt = Date.now() + SESSION_TTL_MS;
  return { token, ...session };
}

function setSessionCookie(response, token) {
  response.setHeader('Set-Cookie', `attendzy_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_MS / 1000}`);
}

function clearSessionCookie(response) {
  response.setHeader('Set-Cookie', 'attendzy_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
}

function createSession(response) {
  const token = crypto.randomBytes(32).toString('base64url');
  activeSessions.set(token, { createdAt: Date.now(), expiresAt: Date.now() + SESSION_TTL_MS });
  setSessionCookie(response, token);
}

function requireInstructor(request, response) {
  if (currentSession(request)) return true;
  sendJson(response, 401, { error: 'يلزم تسجيل دخول عضو هيئة التدريس.' });
  return false;
}

function originIsLocal(request) {
  const origin = request.headers.origin;
  if (!origin) return true;
  try {
    const originUrl = new URL(origin).origin;
    if (originUrl === requestOrigin(request)) return true;
    const localHost = request.headers.host === `127.0.0.1:${PORT}` || request.headers.host === `localhost:${PORT}`;
    return localHost && originUrl === `http://${request.headers.host}`;
  } catch {
    return false;
  }
}

function requestOrigin(request) {
  const configuredOrigin = String(process.env.PUBLIC_ORIGIN || '').trim();
  if (configuredOrigin) {
    try {
      const parsed = new URL(configuredOrigin);
      if (parsed.protocol === 'http:' || parsed.protocol === 'https:') return parsed.origin;
    } catch {}
  }
  const trustForwardedProtocol = process.env.TRUST_PROXY === '1' || Boolean(request.headers['cf-connecting-ip']);
  const forwardedProtocol = trustForwardedProtocol
    ? String(request.headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase()
    : '';
  const protocol = request.socket.encrypted || forwardedProtocol === 'https' ? 'https:' : 'http:';
  return `${protocol}//${request.headers.host || `${HOST}:${PORT}`}`;
}

function readJsonBody(request) {
  return new Promise((resolve, reject) => {
    let body = '';
    let size = 0;
    request.setEncoding('utf8');
    request.on('data', chunk => {
      size += Buffer.byteLength(chunk);
      if (size > MAX_BODY_BYTES) {
        reject(new Error('حجم الطلب أكبر من الحد المسموح.'));
        request.resume();
        return;
      }
      body += chunk;
    });
    request.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); }
      catch { reject(new Error('صيغة البيانات غير صحيحة.')); }
    });
    request.on('error', reject);
  });
}

function normalizedState(value) {
  if (!value || typeof value !== 'object') throw new Error('بيانات النظام غير صالحة.');
  for (const key of ['courses', 'students', 'sessions']) {
    if (!Array.isArray(value[key])) throw new Error(`قائمة ${key} غير صالحة.`);
  }
  const state = {
    sessionSettings: value.sessionSettings && typeof value.sessionSettings === 'object' ? value.sessionSettings : {locationPolicy:'off',locationRadiusM:200,devicePolicy:'warn'},
    courses: value.courses,
    students: value.students,
    sessions: value.sessions,
    auditLog: Array.isArray(value.auditLog) ? value.auditLog.slice(0, 2000) : []
  };
  for (const session of state.sessions) {
    if (!session.records || typeof session.records !== 'object') session.records = {};
    if (typeof session.welcomeTitle === 'string') session.welcomeTitle = session.welcomeTitle.slice(0, 60);
    if (typeof session.welcomeMessage === 'string') session.welcomeMessage = session.welcomeMessage.slice(0, 42);
  }
  return state;
}

const selectAttendance = database.prepare('SELECT session_id, student_id, record FROM attendance_records');
const selectAttendanceForSession = database.prepare('SELECT student_id, record FROM attendance_records WHERE session_id = ?');
const selectCachedState = database.prepare('SELECT data, updated_at FROM app_state WHERE singleton = 1');
const selectCheckinAudit = database.prepare('SELECT event FROM checkin_audit ORDER BY rowid DESC LIMIT 2000');
const selectAttendanceRecord = database.prepare('SELECT record FROM attendance_records WHERE session_id = ? AND student_id = ?');
const insertAttendance = database.prepare('INSERT INTO attendance_records VALUES (?, ?, ?)');
const updateAttendance = database.prepare('UPDATE attendance_records SET record = ? WHERE session_id = ? AND student_id = ?');
const insertCheckinAudit = database.prepare('INSERT INTO checkin_audit(event) VALUES (?)');
const selectCheckinStudents = database.prepare('SELECT student FROM checkin_students');
const insertCheckinStudent = database.prepare('INSERT INTO checkin_students VALUES (?, ?)');

function inTransaction(action) {
  database.exec('BEGIN IMMEDIATE');
  try {
    const result = action();
    database.exec('COMMIT');
    return result;
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  }
}

function readState() {
  const state = JSON.parse(selectState.get().data);
  const sessions = new Map(state.sessions.map(session => [session.id, session]));
  for (const row of selectAttendance.all()) {
    const session = sessions.get(row.session_id);
    if (session) (session.records ||= {})[row.student_id] = JSON.parse(row.record);
  }
  state.students.push(...selectCheckinStudents.all().map(row => JSON.parse(row.student)));
  state.auditLog = [...selectCheckinAudit.all().map(row => JSON.parse(row.event)), ...(state.auditLog || [])].slice(0, 2000);
  return state;
}

function readCheckinContext(code) {
  const row = selectCachedState.get();
  if (!checkinBaseStateCache || checkinBaseStateCache.updatedAt !== row.updated_at) {
    const data = JSON.parse(row.data);
    checkinBaseStateCache = {
      updatedAt: row.updated_at,
      data,
      sessionsByCode: new Map(data.sessions.map(session => [session.code, session]))
    };
  }
  const base = checkinBaseStateCache;
  const originalSession = base.sessionsByCode.get(code);
  if (!originalSession) {
    return { session: null, state: { sessionSettings: base.data.sessionSettings || {}, courses: base.data.courses, students: [], sessions: [] } };
  }
  const session = { ...originalSession, records: { ...(originalSession.records || {}) } };
  for (const row of selectAttendanceForSession.all(session.id)) session.records[row.student_id] = JSON.parse(row.record);
  const students = [...base.data.students, ...selectCheckinStudents.all().map(row => JSON.parse(row.student))];
  const state = {
    sessionSettings: base.data.sessionSettings || {},
    courses: base.data.courses,
    students,
    studentById: new Map(students.map(student => [student.id, student])),
    sessions: [session]
  };
  return { session, state };
}

function mergeWorkspaceAttendance(state, savedState) {
  const savedSessions = new Map(savedState.sessions.map(session => [session.id, session]));
  const sessions = new Map(state.sessions.map(session => [session.id, session]));
  const savedEvents = new Set(savedState.auditLog.map(event => event.id));
  const incomingRecords = new Map(state.sessions.map(session => [session.id, session.records]));
  for (const session of state.sessions) {
    const saved = savedSessions.get(session.id);
    if (!saved) continue;
    session.records = saved.records;
    session.verificationSettings = saved.verificationSettings;
    if (!saved.active) {
      session.active = false;
      session.paused = false;
      session.endedAt = saved.endedAt;
    }
  }
  for (const event of [...state.auditLog].reverse()) {
    if (savedEvents.has(event.id)) continue;
    const review = ['مراجعة التحقق', 'مراجعة جماعية'].includes(event.action);
    if (!review && !['تعديل حضور', 'تعديل جماعي'].includes(event.action)) continue;
    const { sessionId, studentId, studentIds, status } = event.after || {};
    const session = sessions.get(sessionId);
    if (!session || !savedSessions.has(sessionId)) continue;
    for (const id of Array.isArray(studentIds) ? studentIds : [studentId]) {
      const incoming = incomingRecords.get(sessionId)?.[id];
      if (!id || !incoming) continue;
      const existing = session.records[id];
      if (review) {
        if (!existing) continue;
        existing.verification = { ...existing.verification, reviewedAt: incoming.verification?.reviewedAt || event.at };
        if (existing.status === 'verify') existing.status = existing.lateByMinutes > 0 ? 'tardy' : 'present';
        continue;
      }
      const record = { ...existing, status, time: existing?.time || incoming.time, updatedAt: incoming.updatedAt || event.at, manual: true, note: event.after.reason };
      if (record.verification) {
        record.verification = { ...record.verification };
        if (status === 'verify') delete record.verification.reviewedAt;
        else if (incoming.verification?.reviewedAt && (incoming.verification.reviewedAt === incoming.updatedAt || !record.verification.reviewedAt)) {
          record.verification.reviewedAt = incoming.verification.reviewedAt;
        }
      }
      session.records[id] = record;
    }
  }
}

function writeState(value, preserveCheckins = false, preserveSessionControls = false) {
  const state = normalizedState(value);
  return inTransaction(() => {
    if (preserveSessionControls) {
      mergeWorkspaceAttendance(state, readState());
      const current = new Map(JSON.parse(selectCachedState.get().data).sessions.map(session => [session.id, session]));
      const controlled = ['paused', 'pausedRemainingMs', 'autoEndAt', 'autoEndMinutes', 'pinGeneration', 'pinRotationSeconds', 'pinRotatedAt', 'previousPinGeneration', 'previousPinIntervalSeconds'];
      for (const session of state.sessions) {
        const saved = current.get(session.id);
        if (!saved?.active) continue;
        for (const key of controlled) {
          if (Object.hasOwn(saved, key)) session[key] = saved[key];
          else delete session[key];
        }
      }
    }
    if (preserveCheckins) {
      const sessions = new Map(state.sessions.map(session => [session.id, session]));
      for (const row of selectAttendance.all()) {
        const session = sessions.get(row.session_id);
        if (session && !Object.hasOwn(session.records, row.student_id)) {
          session.records[row.student_id] = JSON.parse(row.record);
        }
      }
      const studentIds = new Set(state.students.map(student => student.id));
      const courseIds = new Set(state.courses.map(course => course.id));
      for (const row of selectCheckinStudents.all()) {
        const student = JSON.parse(row.student);
        if (courseIds.has(student.courseId) && !studentIds.has(student.id)) state.students.push(student);
      }
      const eventIds = new Set(state.auditLog.map(event => event.id));
      state.auditLog = [...selectCheckinAudit.all().map(row => JSON.parse(row.event)).filter(event => !eventIds.has(event.id)), ...state.auditLog]
        .sort((a, b) => String(b.at).localeCompare(String(a.at))).slice(0, 2000);
    }
    updateState.run(JSON.stringify(state), new Date().toISOString());
    checkinBaseStateCache = null;
    database.exec('DELETE FROM attendance_records; DELETE FROM checkin_audit; DELETE FROM checkin_students;');
    return state;
  });
}

function applyCheckinWrite(session, previous, events, student) {
  for (const [id, record] of Object.entries(session.records || {})) {
    if (!previous.has(id)) {
      insertAttendance.run(session.id, id, JSON.stringify(record));
      continue;
    }
    const before = JSON.parse(previous.get(id));
    if (previous.get(id) === JSON.stringify(record)) continue;
    const row = selectAttendanceRecord.get(session.id, id);
    const latest = row ? JSON.parse(row.record) : JSON.parse(selectCachedState.get().data)
      .sessions.find(item => item.id === session.id)?.records?.[id];
    if (!latest) continue;
    for (const [key, value] of Object.entries(record.verification || {})) {
      if (JSON.stringify(value) !== JSON.stringify(before.verification?.[key])) {
        const verification = latest.verification ||= {};
        if (key === 'sharedWith') verification.sharedWith = [...new Set([...[verification.sharedWith].flat().filter(Boolean), ...value])];
        else verification[key] = value;
      }
    }
    const data = JSON.stringify(latest);
    if (row) updateAttendance.run(data, session.id, id);
    else insertAttendance.run(session.id, id, data);
  }
  if (student) insertCheckinStudent.run(student.id, JSON.stringify(student));
  for (const event of events) insertCheckinAudit.run(JSON.stringify(event));
}

function flushPendingCheckinWrites() {
  const batch = pendingCheckinWrites.splice(0);
  checkinWriteTimer = null;
  if (!batch.length) return;
  try {
    inTransaction(() => {
      for (const write of batch) applyCheckinWrite(write.session, write.previous, write.events, write.student);
    });
    for (const write of batch) write.resolve();
  } catch (error) {
    for (const write of batch) write.reject(error);
  }
  if (pendingCheckinWrites.length && !checkinWriteTimer) {
    checkinWriteTimer = setTimeout(flushPendingCheckinWrites, 10);
  }
}

function persistCheckin(session, previous, events, student) {
  const newStudentIds = Object.keys(session.records || {}).filter(id => !previous.has(id));
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  const write = { session, previous, events, student, resolve, reject };
  pendingCheckinWrites.push(write);
  const pendingDeviceEntries = [];
  for (const id of newStudentIds) {
    const record = session.records[id];
    pendingStudentCheckins.set(session.id + ' : ' + id, { promise, record });
    if (!record.deviceKey) continue;
    const key = session.id + ' : ' + record.deviceKey;
    const entry = { studentId: id, record, promise };
    pendingDeviceEntries.push([key, entry]);
    const entries = pendingDeviceCheckins.get(key) || [];
    entries.push(entry);
    pendingDeviceCheckins.set(key, entries);
  }
  const clearPending = () => {
    for (const id of newStudentIds) {
      const key = session.id + ' : ' + id;
      if (pendingStudentCheckins.get(key)?.promise === promise) pendingStudentCheckins.delete(key);
    }
    for (const [key, entry] of pendingDeviceEntries) {
      const entries = (pendingDeviceCheckins.get(key) || []).filter(item => item.promise !== promise);
      if (entries.length) pendingDeviceCheckins.set(key, entries);
      else pendingDeviceCheckins.delete(key);
    }
  };
  promise.then(clearPending, clearPending);
  if (!checkinWriteTimer) checkinWriteTimer = setTimeout(flushPendingCheckinWrites, 10);
  return promise;
}

function waitForSessionCheckinWrites(sessionId) {
  return new Promise(resolve => {
    const check = () => {
      if (!pendingCheckinWrites.some(write => write.session.id === sessionId)) return resolve();
      setTimeout(check, 5);
    };
    check();
  });
}
function pinIntervalSeconds(session) {
  return Math.min(3600, Math.max(20, Number(session.pinRotationSeconds) || 60));
}

function makeRotatingPin(code, slot, intervalSeconds = 30, generation = 0) {
  const digest = crypto.createHmac('sha256', pinSecret).update(`${code}:${intervalSeconds}:${generation}:${slot}`).digest();
  return String(digest.readUInt32BE(0) % 10000).padStart(4, '0');
}

function pinIsValid(session, submitted, now = Date.now()) {
  if (!/^\d{4}$/.test(submitted)) return false;
  const intervalSeconds = pinIntervalSeconds(session);
  const intervalMs = intervalSeconds * 1000;
  const slot = Math.floor(now / intervalMs);
  const generation = Math.max(0, Number(session.pinGeneration) || 0);
  const current = makeRotatingPin(session.code, slot, intervalSeconds, generation);
  const candidate = Buffer.from(submitted);
  const expected = Buffer.from(current);
  if (candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected)) return true;
  const rotatedAt = Date.parse(session.pinRotatedAt || '');
  if (Number.isFinite(rotatedAt) && now - rotatedAt >= 0 && now - rotatedAt <= 10_000) {
    const previousInterval = Math.min(3600, Math.max(20, Number(session.previousPinIntervalSeconds) || intervalSeconds));
    const previousGeneration = Math.max(0, Number(session.previousPinGeneration) || 0);
    const previousSlot = Math.floor(rotatedAt / (previousInterval * 1000));
    const previousCode = Buffer.from(makeRotatingPin(session.code, previousSlot, previousInterval, previousGeneration));
    if (candidate.length === previousCode.length && crypto.timingSafeEqual(candidate, previousCode)) return true;
  }
  if (now % intervalMs > 10_000) return false;
  const previous = Buffer.from(makeRotatingPin(session.code, slot - 1, intervalSeconds, generation));
  return candidate.length === previous.length && crypto.timingSafeEqual(candidate, previous);
}

function boundedLateGraceMinutes(value, fallback = 15) {
  if (value === null || value === undefined || value === '') return fallback;
  const minutes = Number(value);
  return Number.isInteger(minutes) && minutes >= 0 && minutes <= 180 ? minutes : fallback;
}

function attendanceTiming(session, course, checkedAt) {
  const configuredStart = Date.parse(session.scheduledStartAt || '');
  const scheduledStart = Number.isFinite(configuredStart) ? configuredStart : Date.parse(session.startedAt || '');
  const graceMinutes = boundedLateGraceMinutes(session.lateGraceMinutes, boundedLateGraceMinutes(course.lateGraceMinutes, 15));
  const checkinTime = Date.parse(checkedAt);
  const tardyAfter = scheduledStart + graceMinutes * 60_000;
  const tardy = Number.isFinite(scheduledStart) && Number.isFinite(checkinTime) && checkinTime > tardyAfter;
  return {
    status: tardy ? 'tardy' : 'present',
    ...(tardy ? { lateByMinutes: Math.max(1, Math.ceil((checkinTime - scheduledStart) / 60_000)) } : {})
  };
}
function expireSessions(now = Date.now()) {
  let state = readState();
  if (pendingCheckinWrites.length && state.sessions.some(session => session.active && !session.paused && Date.parse(session.autoEndAt) <= now)) {
    clearTimeout(checkinWriteTimer);
    flushPendingCheckinWrites();
    state = readState();
  }
  let changed = false;
  for (const session of state.sessions) {
    const endAt = Date.parse(session.autoEndAt || '');
    if (!session.active || session.paused || !Number.isFinite(endAt) || endAt > now) continue;
    session.active = false;
    session.paused = false;
    session.endedAt = new Date(now).toISOString();
    finalizeSessionLocations(state, session);
    const course = state.courses.find(item => item.id === session.courseId) || {};
    state.auditLog.unshift({
      id: crypto.randomUUID(),
      at: session.endedAt,
      actor: 'النظام',
      action: 'إنهاء تلقائي',
      summary: `انتهت تلقائيًا جلسة ${course?.name || 'الحضور'}`,
      after: { sessionId: session.id, autoEndAt: session.autoEndAt }
    });
    changed = true;
  }
  if (changed) {
    state.auditLog = state.auditLog.slice(0, 2000);
    writeState(state);
  }
  return changed;
}

function locationInput(value) {
  if (!value || typeof value !== 'object') return null;
  const latitude = Number(value.latitude);
  const longitude = Number(value.longitude);
  const accuracy = Number(value.accuracy);
  if (!Number.isFinite(latitude) || latitude < -90 || latitude > 90) return null;
  if (!Number.isFinite(longitude) || longitude < -180 || longitude > 180) return null;
  if (!Number.isFinite(accuracy) || accuracy < 0 || accuracy > 10000) return null;
  return { latitude, longitude, accuracy };
}

function haversineMeters(latitude1, longitude1, latitude2, longitude2) {
  const radians = value => value * Math.PI / 180;
  const deltaLatitude = radians(latitude2 - latitude1);
  const deltaLongitude = radians(longitude2 - longitude1);
  const a = Math.sin(deltaLatitude / 2) ** 2
    + Math.cos(radians(latitude1)) * Math.cos(radians(latitude2)) * Math.sin(deltaLongitude / 2) ** 2;
  return 6371000 * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function sessionVerificationSettings(state, session) {
  const snapshot = session.verificationSettings || {};
  const preferences = state.sessionSettings || {};
  const locationPolicy = snapshot.locationPolicy || preferences.locationPolicy || (preferences.locationMode === "off" ? "off" : "review");
  const locationRadiusM = Math.min(2000, Math.max(25, Number(snapshot.locationRadiusM ?? preferences.locationRadiusM) || 200));
  const teacherLat = Number(snapshot.locationLat), teacherLon = Number(snapshot.locationLon);
  const hasTeacherLocation = snapshot.locationLat != null && snapshot.locationLon != null
    && Number.isFinite(teacherLat) && Math.abs(teacherLat) <= 90
    && Number.isFinite(teacherLon) && Math.abs(teacherLon) <= 180;
  return {
    ...snapshot,
    locationPolicy,
    locationRadiusM,
    devicePolicy: snapshot.devicePolicy || preferences.devicePolicy || "warn",
    locationLat: hasTeacherLocation ? teacherLat : null,
    locationLon: hasTeacherLocation ? teacherLon : null,
    locationAccuracy: hasTeacherLocation ? Math.max(0, Number(snapshot.locationAccuracy) || 0) : null
  };
}

function classLocationConsensus(settings, entries) {
  const radius = settings.locationRadiusM;
  const points = entries.filter(entry => entry?.point && Number.isFinite(entry.point.latitude) && Number.isFinite(entry.point.longitude)
    && Number.isFinite(entry.point.accuracy) && entry.point.accuracy <= Math.min(250, radius));
  let winningMembers = [];
  for (const center of points) {
    const members = points.filter(candidate => haversineMeters(center.point.latitude, center.point.longitude, candidate.point.latitude, candidate.point.longitude)
      <= radius + Math.min(center.point.accuracy + candidate.point.accuracy, 250));
    if (members.length > winningMembers.length) winningMembers = members;
  }
  const memberIds = new Set(winningMembers.map(entry => entry.id));
  return { points, members: winningMembers, memberIds, size: winningMembers.length };
}

function assessLocation(settings, location, peerLocations = []) {
  const policy = settings.locationPolicy || "off";
  if (policy === "off") return { policy, status: "disabled", source: "off" };
  if (!location) return { policy, status: "not_shared", source: "unknown" };
  const radius = settings.locationRadiusM;
  if (location.accuracy > Math.min(250, radius)) return { policy, status: "low_accuracy", source: settings.locationLat == null ? "class" : "teacher", accuracyBand: "low" };

  if (settings.locationLat != null && settings.locationLon != null) {
    const distance = haversineMeters(settings.locationLat, settings.locationLon, location.latitude, location.longitude);
    const tolerance = radius + Math.min(location.accuracy + (settings.locationAccuracy || 0), 250);
    if (distance <= tolerance) return { policy, status: "precise", source: "teacher", accuracyBand: location.accuracy <= 50 ? "high" : "medium" };
    return { policy, status: "verify", source: "teacher", accuracyBand: location.accuracy <= 100 ? "medium" : "low" };
  }

  const entries = peerLocations.map((point, index) => ({ id: "peer-" + index, point })).concat([{ id: "__incoming__", point: location }]);
  const consensus = classLocationConsensus(settings, entries);
  const provisional = consensus.size < 2;
  const status = consensus.memberIds.has("__incoming__") ? "precise" : "verify";
  return { policy, status, source: "class", peerCount: peerLocations.length, matchingPeers: consensus.members.filter(entry => entry.id !== "__incoming__").length, accuracyBand: "group", ...(provisional ? { provisional: true, clusterSize: consensus.size } : {}) };
}

function areaCoordinates(area) {
  if (!area || typeof area !== 'object' || area.latitude == null || area.longitude == null) return null;
  const latitude = Number(area.latitude), longitude = Number(area.longitude);
  if (!Number.isFinite(latitude) || Math.abs(latitude) > 90 || !Number.isFinite(longitude) || Math.abs(longitude) > 180) return null;
  return { latitude, longitude };
}

function normalizedAreaPart(value) {
  return String(value || '').trim().toLocaleLowerCase('en').replace(/\\s+/g, ' ');
}

function sameNetworkArea(first, second) {
  const countryA = normalizedAreaPart(first?.countryCode), countryB = normalizedAreaPart(second?.countryCode);
  if (countryA && countryB && countryA !== countryB) return false;
  const cityA = normalizedAreaPart(first?.city), cityB = normalizedAreaPart(second?.city);
  if (cityA && cityB) return cityA === cityB && (!countryA || !countryB || countryA === countryB);
  const regionA = normalizedAreaPart(first?.regionCode || first?.region), regionB = normalizedAreaPart(second?.regionCode || second?.region);
  if (regionA && regionB) return regionA === regionB && (!countryA || !countryB || countryA === countryB);
  return false;
}

function assessNetworkArea(settings, area, peerAreas = [], peerLocations = []) {
  const policy = settings.locationPolicy || 'off';
  if (policy === 'off') return { policy, status: 'disabled', source: 'off' };
  const point = areaCoordinates(area);
  if (!point) return { policy, status: 'not_shared', source: 'network', unavailable: true };

  if (settings.locationLat != null && settings.locationLon != null) {
    const distance = haversineMeters(settings.locationLat, settings.locationLon, point.latitude, point.longitude);
    return {
      policy,
      status: distance <= IP_AREA_MATCH_RADIUS_M ? 'in_range' : 'verify',
      source: 'network',
      accuracyBand: 'approximate',
      reference: 'teacher',
      distanceBand: distance <= 10_000 ? 'near' : distance <= IP_AREA_MATCH_RADIUS_M ? 'regional' : 'far'
    };
  }

  const peers = [
    ...peerAreas.filter(entry => areaCoordinates(entry)),
    ...peerLocations.map(locationInput).filter(Boolean)
  ];
  if (!peers.length) {
    return { policy, status: 'in_range', source: 'network', accuracyBand: 'approximate', provisional: true, peerCount: 0, matchingPeers: 0 };
  }
  const matchingPeers = peers.filter(peer => sameNetworkArea(area, peer)
    || haversineMeters(point.latitude, point.longitude, peer.latitude, peer.longitude) <= IP_AREA_MATCH_RADIUS_M).length;
  return {
    policy,
    status: matchingPeers ? 'in_range' : 'verify',
    source: 'network',
    accuracyBand: 'approximate',
    peerCount: peers.length,
    matchingPeers
  };
}

function requestClientIp(request) {
  const validIp = value => {
    const address = String(value || '').trim().replace(/^::ffff:/i, '').replace(/%.+$/, '');
    return net.isIP(address) ? address : '';
  };
  const cloudflareIp = validIp(request.headers['cf-connecting-ip']);
  if (cloudflareIp) return cloudflareIp;
  if (process.env.TRUST_PROXY === '1') {
    const forwardedIp = String(request.headers['x-forwarded-for'] || '').split(',').map(validIp).find(Boolean);
    if (forwardedIp) return forwardedIp;
    const realIp = validIp(request.headers['x-real-ip']);
    if (realIp) return realIp;
  }
  return validIp(request.socket.remoteAddress) || 'unknown';
}

function isPublicIp(address) {
  const value = String(address || '').toLowerCase();
  const version = net.isIP(value);
  if (version === 4) {
    const octets = value.split('.').map(Number);
    const [a, b] = octets;
    return !(a === 0 || a === 10 || a === 127 || a >= 224
      || (a === 100 && b >= 64 && b <= 127)
      || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && ((b === 0 && (octets[2] === 0 || octets[2] === 2)) || b === 168))
      || (a === 198 && (b === 18 || b === 19 || (b === 51 && octets[2] === 100)))
      || (a === 203 && b === 0 && octets[2] === 113));
  }
  if (version === 6) {
    return !(value === '::' || value === '::1' || value.startsWith('fc') || value.startsWith('fd')
      || /^fe[89ab]/.test(value) || value.startsWith('2001:db8:'));
  }
  return false;
}

async function lookupIpArea(ipAddress) {
  const address = String(ipAddress || '').replace(/^::ffff:/i, '');
  if (!isPublicIp(address)) return null;
  const cacheKey = signalHash('ip-area-cache', address);
  const now = Date.now();
  const cached = ipAreaCache.get(cacheKey);
  if (cached && cached.expiresAt > now) return cached.area;
  if (cached) ipAreaCache.delete(cacheKey);

  let area = null;
  try {
    const endpoint = `https://ipwho.is/${encodeURIComponent(address)}?fields=success,country,country_code,region,region_code,city,latitude,longitude`;
    const response = await fetch(endpoint, { signal: AbortSignal.timeout(2500) });
    if (response.ok) {
      const data = await response.json();
      const point = areaCoordinates(data);
      if (data.success === true && point && (data.country_code || data.country)) {
        area = {
          countryCode: String(data.country_code || '').slice(0, 8),
          country: String(data.country || '').slice(0, 80),
          regionCode: String(data.region_code || '').slice(0, 24),
          region: String(data.region || '').slice(0, 80),
          city: String(data.city || '').slice(0, 80),
          latitude: Math.round(point.latitude * 10) / 10,
          longitude: Math.round(point.longitude * 10) / 10
        };
        area.label = [area.city, area.region, area.country].filter(Boolean).join('، ');
      }
    }
  } catch {}

  if (ipAreaCache.size >= IP_AREA_CACHE_LIMIT) ipAreaCache.delete(ipAreaCache.keys().next().value);
  ipAreaCache.set(cacheKey, { area, expiresAt: now + (area ? IP_AREA_CACHE_TTL_MS : IP_AREA_NEGATIVE_CACHE_TTL_MS) });
  return area;
}

function sessionLocationPoint(location) {
  return { latitude: Math.round(location.latitude * 10000) / 10000, longitude: Math.round(location.longitude * 10000) / 10000, accuracy: location.accuracy };
}

function eligiblePeers(records, studentId, deviceKey) {
  const devices = new Set(deviceKey ? [deviceKey] : []);
  return Object.entries(records).filter(([id, record]) => {
    if (id === studentId || !record?.deviceKey || devices.has(record.deviceKey)) return false;
    devices.add(record.deviceKey);
    return true;
  }).map(([, record]) => record);
}

function assessSessionLocation(settings, location, area, peers, hasDevice) {
  const policy = settings.locationPolicy;
  if (policy === 'off') return { policy, status: 'disabled', source: 'off' };
  if (location && location.accuracy <= Math.min(250, settings.locationRadiusM)) {
    if (settings.locationLat != null) return assessLocation(settings, location);
    const points = peers.map(record => record.locationPoint).filter(Boolean);
    const result = assessLocation(settings, location, points);
    // Accurate GPS outranks the approximate IP area. Without independent peers,
    // retain the GPS observation as provisional rather than replacing it with IP.
    if (!hasDevice || result.provisional) return { ...result, status: 'awaiting_peers', provisional: true };
    return result;
  }
  if (areaCoordinates(area)) {
    const reference = settings.teacherNetworkArea;
    const areas = peers.map(record => record.networkArea).filter(entry => areaCoordinates(entry));
    if (!reference && !areas.length && hasDevice) {
      return { policy, status: 'awaiting_peers', source: 'network', reference: 'class', provisional: true };
    }
    if (reference || (hasDevice && areas.length)) {
      const nearby = (other) => sameNetworkArea(area, other)
        || haversineMeters(area.latitude, area.longitude, other.latitude, other.longitude) <= IP_AREA_MATCH_RADIUS_M;
      const matching = reference ? nearby(reference) : areas.some(nearby);
      return { policy, status: matching ? 'insufficient_accuracy' : 'verify',
        source: 'network', reference: reference ? 'teacher' : 'class', accuracyBand: 'approximate',
        reason: matching ? 'coarse_network_area' : 'different_network_area' };
    }
  }
  return { policy, status: location ? 'low_accuracy' : 'not_shared',
    source: location ? (settings.locationLat == null ? 'class' : 'teacher') : 'network',
    reason: location ? (location.accuracy > Math.min(250, settings.locationRadiusM) ? 'low_gps_accuracy' : 'missing_independent_devices') : 'missing_location' };
}

function refreshPendingLocations(session, settings) {
  for (const [id, record] of Object.entries(session.records || {})) {
    const previous = record.verification?.location;
    if (!previous || (!previous.provisional && !['awaiting_peers', 'unconfigured'].includes(previous.status))) continue;
    record.verification.location = assessSessionLocation(settings, locationInput(record.locationPoint),
      record.networkArea, eligiblePeers(session.records, id, record.deviceKey), Boolean(record.deviceKey));
  }
}

function finalizeSessionLocations(state, session) {
  refreshPendingLocations(session, sessionVerificationSettings(state, session));
  for (const record of Object.values(session.records || {})) {
    const location = record.verification?.location;
    if (location && (location.provisional || ['awaiting_peers', 'unconfigured', 'not_shared', 'low_accuracy', 'insufficient_accuracy'].includes(location.status))) {
      const { provisional, ...result } = location;
      record.verification.location = { ...result, status: 'unverified',
        reason: location.reason || (provisional ? 'missing_peer_reference' : location.status === 'low_accuracy' ? 'low_gps_accuracy' : 'missing_location') };
    }
    delete record.locationPoint;
    delete record.networkArea;
  }
  if (session.verificationSettings) {
    for (const key of ['locationLat', 'locationLon', 'locationAccuracy', 'locationCapturedAt', 'teacherNetworkArea']) {
      delete session.verificationSettings[key];
    }
  }
}

function schedulePeerVerificationRefresh(sessionId) {
  const pending = peerVerificationRefreshTimers.get(sessionId);
  if (pending) clearTimeout(pending);
  const timer = setTimeout(() => {
    peerVerificationRefreshTimers.delete(sessionId);
    try {
      const state = readState();
      const session = state.sessions.find(item => item.id === sessionId);
      if (!session?.active) return;
      const settings = sessionVerificationSettings(state, session);
      const previous = new Map(Object.entries(session.records || {}).map(([id, record]) => [id, JSON.stringify(record)]));
      refreshPendingLocations(session, settings);
      persistCheckin(session, previous, []);
    } catch (error) {
      console.error('تعذر تحديث مراجعة الموقع الجماعية:', error.message);
    }
  }, 2000);
  timer.unref();
  peerVerificationRefreshTimers.set(sessionId, timer);
}

function signalHash(kind, value) {
  return crypto.createHmac('sha256', pinSecret).update(`${kind}:${value}`).digest('hex');
}

function markSharedDevice(record, otherStudentName) {
  const existing = record.verification?.sharedWith;
  const names = Array.isArray(existing) ? existing : existing ? [existing] : [];
  record.verification = { ...(record.verification || {}), device: 'shared', sharedWith: [...new Set([...names, otherStudentName])] };
}

function networkScope(ipAddress) {
  const address = String(ipAddress || '').replace(/^::ffff:/i, '').toLowerCase();
  const ipv4 = address.split('.');
  if (ipv4.length === 4 && ipv4.every(part => /^\d{1,3}$/.test(part))) return ipv4.slice(0, 3).join('.');
  if (address.includes(':')) {
    const halves = address.split('::');
    const left = halves[0] ? halves[0].split(':') : [];
    const right = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
    const groups = [...left, ...Array(Math.max(0, 8 - left.length - right.length)).fill('0'), ...right];
    return groups.slice(0, 4).map(group => (parseInt(group || '0', 16) || 0).toString(16)).join(':');
  }
  return address || 'unknown';
}

function publicCheckinUrl(request, code) {
  return `${requestOrigin(request)}/?join=${encodeURIComponent(code)}`;
}

function modernQrSvg(value) {
  const qr = QRCode.create(value, { errorCorrectionLevel: 'M' });
  const size = qr.modules.size;
  const quiet = 4;
  const fullSize = size + quiet * 2;
  const parts = [`<svg xmlns="http://www.w3.org/2000/svg" width="320" height="320" viewBox="0 0 ${fullSize} ${fullSize}" role="img" aria-label="QR لتسجيل الحضور"><rect width="${fullSize}" height="${fullSize}" fill="#ffffff"/>`];
  for (let row = 0; row < size; row++) {
    for (let column = 0; column < size; column++) {
      if (qr.modules.data[row * size + column]) {
        parts.push(`<rect x="${column + quiet}" y="${row + quiet}" width="1" height="1" fill="#000000"/>`);
      }
    }
  }
  parts.push('</svg>');
  return parts.join('');
}

function credentialsConfigured() {
  return Boolean(selectCredentials.get());
}

function hasTooManyFailures(ip) {
  const entry = failedLogins.get(ip);
  if (!entry || entry.resetAt < Date.now()) {
    failedLogins.delete(ip);
    return false;
  }
  return entry.count >= 5;
}

function noteFailedLogin(ip) {
  const entry = failedLogins.get(ip);
  if (!entry || entry.resetAt < Date.now()) failedLogins.set(ip, { count: 1, resetAt: Date.now() + 10 * 60 * 1000 });
  else entry.count += 1;
}

async function handleApi(request, response, url) {
  if (!originIsLocal(request)) return sendJson(response, 403, { error: 'مصدر الطلب غير مسموح.' });
  expireSessions();


  if (url.pathname === '/api/profile' && ['GET','PUT'].includes(request.method)) {
    if (!requireInstructor(request,response)) return;
    if(request.method==='GET'){const row=database.prepare('SELECT setting_value FROM app_settings WHERE setting_key=?').get('instructor_profile');return sendJson(response,200,row?JSON.parse(row.setting_value):{});}
    const body=await readJsonBody(request),profile={};
    for(const key of ['name','academicTitle','email','university','faculty','department']){if(body[key]!=null&&typeof body[key]!=='string')return sendJson(response,400,{error:'بيانات غير صالحة.'});profile[key]=(body[key]||'').trim();if(profile[key].length>160)return sendJson(response,400,{error:'الحد الأقصى للحقل 160 حرفًا.'});}
    if(!profile.name)return sendJson(response,400,{error:'أدخل الاسم الكامل.'});
    if(profile.email&&!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(profile.email))return sendJson(response,400,{error:'أدخل بريدًا إلكترونيًا صحيحًا.'});
    database.prepare('INSERT INTO app_settings(setting_key,setting_value) VALUES(?,?) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value').run('instructor_profile',JSON.stringify(profile));
    return sendJson(response,200,profile);
  }
  if(url.pathname==='/api/change-password'&&request.method==='POST'){
    if(!requireInstructor(request,response))return;
    const ip=request.socket.remoteAddress||'local';
    if(hasTooManyFailures(ip))return sendJson(response,429,{error:'محاولات كثيرة. انتظر عشر دقائق.'});
    const body=await readJsonBody(request),credentials=selectCredentials.get();
    if(typeof body.currentPassword!=='string'||body.currentPassword.length>128||typeof body.newPassword!=='string'||body.newPassword.length<12||body.newPassword.length>128)return sendJson(response,400,{error:'أدخل الحالية وكلمة جديدة من 12 إلى 128 حرفًا.'});
    const expected=Buffer.from(credentials.password_hash,'hex'),candidate=crypto.scryptSync(body.currentPassword,Buffer.from(credentials.salt,'hex'),expected.length);
    if(!crypto.timingSafeEqual(expected,candidate)){noteFailedLogin(ip);return sendJson(response,400,{error:'كلمة المرور الحالية غير صحيحة.'});}
    const salt=crypto.randomBytes(16),hash=crypto.scryptSync(body.newPassword,salt,64);
    database.prepare('UPDATE instructor_credentials SET salt=?,password_hash=? WHERE singleton=1').run(salt.toString('hex'),hash.toString('hex'));
    failedLogins.delete(ip);const current=currentSession(request);for(const token of activeSessions.keys())if(token!==current?.token)activeSessions.delete(token);
    return sendJson(response,200,{ok:true});
  }
  if (url.pathname === '/api/auth-status' && request.method === 'GET') {
    return sendJson(response, 200, { configured: credentialsConfigured(), authenticated: Boolean(currentSession(request)) });
  }

  if (url.pathname === '/api/setup' && request.method === 'POST') {
    if (credentialsConfigured()) return sendJson(response, 409, { error: 'تم إعداد حساب الأستاذ بالفعل.' });
    const body = await readJsonBody(request);
    if (typeof body.password !== 'string' || body.password.length < 12 || body.password.length > 128) {
      return sendJson(response, 400, { error: 'استخدم كلمة مرور من 12 إلى 128 حرفًا.' });
    }
    const salt = crypto.randomBytes(16);
    const hash = crypto.scryptSync(body.password, salt, 64);
    insertCredentials.run(salt.toString('hex'), hash.toString('hex'), new Date().toISOString());
    createSession(response);
    return sendJson(response, 201, { ok: true });
  }

  if (url.pathname === '/api/login' && request.method === 'POST') {
    const ip = request.socket.remoteAddress || 'local';
    if (hasTooManyFailures(ip)) return sendJson(response, 429, { error: 'محاولات كثيرة. انتظر عشر دقائق ثم حاول مرة أخرى.' });
    const body = await readJsonBody(request);
    const credentials = selectCredentials.get();
    if (!credentials || typeof body.password !== 'string') return sendJson(response, 401, { error: 'كلمة المرور غير صحيحة.' });
    const salt = Buffer.from(credentials.salt, 'hex');
    const expected = Buffer.from(credentials.password_hash, 'hex');
    const candidate = crypto.scryptSync(body.password, salt, expected.length);
    if (!crypto.timingSafeEqual(expected, candidate)) {
      noteFailedLogin(ip);
      return sendJson(response, 401, { error: 'كلمة المرور غير صحيحة.' });
    }
    failedLogins.delete(ip);
    createSession(response);
    return sendJson(response, 200, { ok: true });
  }

  if (url.pathname === '/api/logout' && request.method === 'POST') {
    const session = currentSession(request);
    if (session) activeSessions.delete(session.token);
    clearSessionCookie(response);
    return sendJson(response, 200, { ok: true });
  }

  if (url.pathname === '/api/public-session' && request.method === 'GET') {
    const code = url.searchParams.get('code') || '';
    const state = readState();
    const session = state.sessions.find(item => item.active && item.code === code);
    if (!session) return sendJson(response, 404, { active: false, error: 'الجلسة غير متاحة.' });
    const course = state.courses.find(item => item.id === session.courseId) || {};
    const settings = sessionVerificationSettings(state, session);
    const students = state.students.filter(item => item.courseId === session.courseId).map(item => ({ id: item.id, name: item.name })).sort((left, right) => left.name.localeCompare(right.name, 'ar'));
    return sendJson(response, 200, {
      active: true,
      courseName: course.name || 'المقرر',
      sessionTitle: session.title || '',
      allowSelfEnrollment: session.allowSelfEnrollment !== false,
      locationPolicy: settings.locationPolicy,
      locationRequired: settings.locationPolicy === 'required' || ['review', 'block'].includes(settings.locationPolicy),
      locationSource: settings.locationLat == null ? 'class' : 'teacher',
      locationRadiusM: settings.locationRadiusM,
      devicePolicy: settings.devicePolicy,
      paused: session.paused === true,
      students
    });
  }

  if (url.pathname === '/api/session-display' && request.method === 'GET') {
    if (!requireInstructor(request, response)) return;
    const code = url.searchParams.get('code') || '';
    const session = readState().sessions.find(item => item.active && item.code === code);
    if (!session) return sendJson(response, 404, { error: 'الجلسة غير متاحة.' });
    const intervalSeconds = pinIntervalSeconds(session);
    const now = Date.now();
    const intervalMs = intervalSeconds * 1000;
    const autoEndAt = session.autoEndAt || null;
    return sendJson(response, 200, {
      pin: makeRotatingPin(session.code, Math.floor(now / intervalMs), intervalSeconds, Math.max(0, Number(session.pinGeneration) || 0)),
      welcomeTitle: String(session.welcomeTitle ?? 'أهلا بكم').slice(0,60),
      welcomeMessage: String(session.welcomeMessage ?? 'يرجي تسجيل الاسم الثلاثي').slice(0, 42),
      rotationSeconds: intervalSeconds,
      secondsRemaining: Math.ceil((intervalMs - (now % intervalMs)) / 1000),
      checkinUrl: publicCheckinUrl(request, session.code),
      paused: session.paused === true,
      autoEndAt,
      secondsUntilEnd: autoEndAt ? Math.max(0, Math.ceil((Date.parse(autoEndAt) - now) / 1000)) : null
    });
  }

  if (url.pathname === '/api/qr.svg' && request.method === 'GET') {
    if (!requireInstructor(request, response)) return;
    const code = url.searchParams.get('code') || '';
    const session = readState().sessions.find(item => item.active && item.code === code);
    if (!session) return sendJson(response, 404, { error: 'الجلسة غير متاحة.' });
    const svg = modernQrSvg(publicCheckinUrl(request, session.code));
    securityHeaders(response);
    response.setHeader('Content-Type', 'image/svg+xml; charset=utf-8');
    response.end(svg);
    return;
  }

  if (url.pathname === '/api/checkin' && request.method === 'POST') {
    const checkinReceivedAt = new Date().toISOString();
    const body = await readJsonBody(request);
    const code = String(body.code || '').trim();
    const pin = String(body.pin || '').trim();
    if (!/^[a-zA-Z0-9_-]{6,96}$/.test(code) || !/^\d{4}$/.test(pin) || body.agreed !== true) {
      return sendJson(response, 400, { error: 'تحقق من رمز الجلسة والرمز المتغير والإقرار.' });
    }
    const location = locationInput(body.location);
    const clientIp = requestClientIp(request);
    let context = readCheckinContext(code);
    const candidate = context?.session?.active && !context.session.paused ? context.session : null;
    const receivedAt = Date.parse(checkinReceivedAt);
    const candidateEndAt = Date.parse(candidate?.autoEndAt || '');
    const shouldLookup = candidate && (!Number.isFinite(candidateEndAt) || candidateEndAt > receivedAt)
      && pinIsValid(candidate, pin, receivedAt)
      && sessionVerificationSettings(context.state, candidate).locationPolicy !== 'off'
      && (!location || location.accuracy > Math.min(250, sessionVerificationSettings(context.state, candidate).locationRadiusM));
    const networkArea = shouldLookup ? await lookupIpArea(clientIp) : null;
    // Refresh the context after any network lookup so concurrent check-ins see committed records.
    if (shouldLookup) context = readCheckinContext(code);
    const { state, session } = context;
    if (!session || !session.active) return sendJson(response, 404, { error: 'رمز الجلسة غير صالح أو انتهت الجلسة.' });
    if (sessionsEnding.has(session.id)) return sendJson(response, 423, { error: 'جارٍ إنهاء الجلسة. أعد المحاولة بعد لحظات.' });
    if (sessionsChanging.has(session.id)) return sendJson(response, 423, { error: 'جارٍ تغيير حالة الجلسة. أعد المحاولة بعد لحظات.' });
    if (!session) return sendJson(response, 404, { error: 'رمز الجلسة غير صالح أو انتهت الجلسة.' });
    if (session.paused === true) return sendJson(response, 423, { error: 'التسجيل متوقف مؤقتًا من الأستاذ. انتظر استئناف الجلسة.' });
    const sessionEndAt = Date.parse(session.autoEndAt || '');
    if (Number.isFinite(sessionEndAt) && sessionEndAt <= receivedAt) return sendJson(response, 404, { error: 'انتهت الجلسة.' });
    if (!pinIsValid(session, pin, receivedAt)) return sendJson(response, 400, { error: 'انتهت صلاحية الرمز. اقرأ الرمز الحالي من شاشة القاعة.' });
    const courseRecord = state.courses.find(item => item.id === session.courseId) || {};
    const course = sessionVerificationSettings(state, session);
    const rawDeviceId = String(body.deviceId || '');
    const deviceKey = /^[a-zA-Z0-9-]{16,80}$/.test(rawDeviceId) ? signalHash('device', rawDeviceId) : '';
    if (course?.devicePolicy === 'block' && !deviceKey) return sendJson(response, 400, { error: 'تعذر التحقق من معرّف هذا المتصفح. فعّل التخزين المحلي أو تواصل مع الأستاذ.' });
    const networkKey = signalHash('network', networkScope(clientIp));
    const previousRecords = Object.entries(session.records).filter(([studentId, record]) => studentId !== (body.studentId || '') && record);
    const pendingDeviceEntries = deviceKey ? (pendingDeviceCheckins.get(session.id + ' : ' + deviceKey) || []).filter(entry => entry.studentId !== (body.studentId || '')) : [];
    const sameDeviceRecords = deviceKey
      ? [...previousRecords.filter(([, record]) => record.deviceKey === deviceKey), ...pendingDeviceEntries.map(entry => [entry.studentId, entry.record])]
      : [];
    const networkRecords = previousRecords.map(([, record]) => record.networkKey).filter(Boolean);
    const networkStatus = networkRecords.length
      ? networkRecords.includes(networkKey) ? 'same_network' : 'different_network'
      : 'awaiting_network';
    let student;
    let selfEnrolled = false;
    if (body.studentId) {
      student = state.studentById.get(body.studentId);
      if (student?.courseId !== session.courseId) student = null;
      if (!student) return sendJson(response, 404, { error: 'اختر اسمًا من قائمة هذا المقرر.' });
    } else {
      const name = String(body.name || '').trim().replace(/\s+/g, ' ');
      if (session.allowSelfEnrollment === false) return sendJson(response, 403, { error: 'إضافة الأسماء الجديدة غير مفعّلة لهذا المقرر.' });
      if (name.length < 2 || name.length > 100) {
        return sendJson(response, 400, { error: 'أدخل الاسم الكامل.' });
      }
      if (state.students.some(item => (item.courseId === session.courseId) && item.name.trim().toLocaleLowerCase('ar') === name.toLocaleLowerCase('ar'))) {
        return sendJson(response, 409, { error: 'هذا الاسم موجود في القائمة. اختره من قائمة الأسماء بدل إضافته مرة أخرى.' });
      }
      student = { id: crypto.randomUUID(), name, number: '', courseId: session.courseId, selfEnrolled: true, reviewStatus: 'pending', addedAt: new Date().toISOString() };
      selfEnrolled = true;
    }
    const pendingStudent = pendingStudentCheckins.get(session.id + ' : ' + student.id);
    if (pendingStudent) {
      await pendingStudent.promise;
      const record = pendingStudent.record;
      return sendJson(response, 201, { ok: true, alreadyRecorded: true, status: record.status, lateByMinutes: record.lateByMinutes || null, time: record.time, verification: record.verification, message: 'تم حفظ تسجيل حضورك بالفعل.' });
    }
    if (session.records[student.id]) {
      const record = session.records[student.id];
      return sendJson(response, 201, { ok: true, alreadyRecorded: true, status: record.status, lateByMinutes: record.lateByMinutes || null, time: record.time, verification: record.verification, message: 'تم حفظ تسجيل حضورك بالفعل.' });
    }
    const gpsRequired = course.locationPolicy === 'required' || ['review', 'block'].includes(course.locationPolicy);
    const gpsInaccurate = course.locationPolicy === 'required' && location
      && location.accuracy > Math.min(250, course.locationRadiusM);
    if (gpsRequired && (!location || gpsInaccurate)) {
      const error = !location
        ? 'تحديد موقع GPS مطلوب لتسجيل الحضور. فعّل إذن الموقع وأعد المحاولة.'
        : 'دقة GPS غير كافية للتسجيل. انتقل إلى مكان مفتوح وأعد طلب الموقع.';
      return sendJson(response, 403, { error, verification: !location ? 'location_required' : 'location_inaccurate' });
    }
    const previousAttendance = new Map(Object.entries(session.records).map(([id, record]) => [id, JSON.stringify(record)]));
    const checkinEvents = [];
    let locationCheck;
    if (course.locationPolicy === 'block') {
      const peerRecords = Object.entries(session.records || {}).filter(([studentId, record]) => studentId !== student.id && record);
      const peerLocations = peerRecords.filter(([, record]) => record.locationPoint).map(([, record]) => record.locationPoint);
      const peerNetworkAreas = peerRecords.filter(([, record]) => record.networkArea && !record.locationPoint).map(([, record]) => record.networkArea);
      locationCheck = location
          ? assessLocation(course, location, peerLocations)
          : assessNetworkArea(course, networkArea, peerNetworkAreas, peerLocations);
      if (location && course.locationLat == null && peerLocations.length === 0 && peerNetworkAreas.length) {
        locationCheck = assessNetworkArea(course, location, peerNetworkAreas);
      }
      // Preserve the existing admission decision for sessions configured to block.
      const locationAccepted = ['disabled', 'precise', 'in_range'].includes(locationCheck.status);
      if (locationCheck.policy === 'block' && !locationAccepted && !locationCheck.provisional) {
        const message = locationCheck.status === 'not_shared'
          ? 'تعذر تحديد منطقة اتصالك. حاول مرة أخرى أو اطلب من الأستاذ تسجيل حضورك.'
          : locationCheck.status === 'low_accuracy'
            ? 'إشارة الموقع غير دقيقة بما يكفي. انتقل إلى مكان مفتوح وحاول مرة أخرى.'
            : 'موقعك خارج نطاق المقارنة. إذا كنت داخل القاعة، اطلب من الأستاذ مراجعة التسجيل.';
        return sendJson(response, 403, { error: message, verification: locationCheck.status });
      }
    }
    locationCheck = assessSessionLocation(course, location, networkArea,
      eligiblePeers(session.records, student.id, deviceKey), Boolean(deviceKey));
    if (sameDeviceRecords.length && course?.devicePolicy === 'block') {
      for (const [studentId, record] of sameDeviceRecords) {
        markSharedDevice(record, student.name);
        checkinEvents.push({ id: crypto.randomUUID(), at: new Date().toISOString(), actor: 'النظام', action: 'جهاز مشترك', summary: `استُخدم متصفح طالب آخر لتسجيل ${student.name}`, after: { sessionId: session.id, studentId, deviceStatus: 'shared' } });
      }
      await Promise.all(pendingDeviceEntries.map(entry => entry.promise));
      if (sessionsChanging.has(session.id)) return sendJson(response, 423, { error: 'جارٍ تغيير حالة الجلسة. أعد المحاولة بعد لحظات.' });
      await persistCheckin(session, previousAttendance, checkinEvents);
      return sendJson(response, 409, { error: 'استُخدم هذا المتصفح لتسجيل طالب آخر في الجلسة. راجع الأستاذ إذا كنتما تستخدمان جهازًا مشتركًا.' });
    }
    for (const [, record] of previousRecords) {
      if (record.networkKey && record.verification) {
        record.verification.network = record.networkKey === networkKey ? 'same_network' : 'different_network';
      }
    }
    if (selfEnrolled) state.students.push(student);
    const deviceStatus = sameDeviceRecords.length ? 'shared' : deviceKey ? 'unique' : 'unavailable';
    const checkedAt = checkinReceivedAt;
    const timing = attendanceTiming(session, courseRecord, checkedAt);
    const sharedWith = sameDeviceRecords.map(([studentId]) => state.students.find(item => item.id === studentId)?.name).filter(Boolean);
    const verification = { location: locationCheck, network: networkStatus, device: deviceStatus, ...(sharedWith.length ? { sharedWith } : {}) };
    const attendanceRecord = { ...timing, time: checkedAt, source: 'student', verification, deviceKey, networkKey };
    if (course.locationPolicy !== 'off' && course.locationLat == null && location) attendanceRecord.locationPoint = sessionLocationPoint(location);
    if (course.locationPolicy !== 'off' && networkArea) attendanceRecord.networkArea = networkArea;
    session.records[student.id] = attendanceRecord;
    locationCheck = attendanceRecord.verification.location;
    for (const [, record] of sameDeviceRecords) markSharedDevice(record, student.name);
    const flagged = ['verify', 'low_accuracy', 'unconfigured', 'awaiting_peers', 'insufficient_accuracy', 'not_shared'].includes(locationCheck.status)
      || deviceStatus === 'shared';
    const auditAction = timing.status === 'tardy' ? (selfEnrolled ? 'تسجيل ذاتي متأخر' : 'تسجيل متأخر') : (selfEnrolled ? 'تسجيل ذاتي وحضور' : 'تسجيل حضور');
    const auditSummary = timing.status === 'tardy' ? (selfEnrolled ? `أضاف ${student.name} اسمه وسجل حضوره متأخرًا ${timing.lateByMinutes} دقيقة؛ الاسم بحاجة إلى مراجعة` : `سُجل حضور طالب متأخرًا ${timing.lateByMinutes} دقيقة عن موعد البداية`) : selfEnrolled ? `أضاف ${student.name} اسمه وسجل حضوره؛ الاسم بحاجة إلى مراجعة` : 'تم تسجيل حضور طالب في جلسة مفتوحة';
    checkinEvents.push({ id: crypto.randomUUID(), at: checkedAt, actor: 'طالب', action: auditAction, summary: auditSummary, after: { studentId: student.id, sessionId: session.id, status: attendanceRecord.status, lateByMinutes: attendanceRecord.lateByMinutes || null, selfEnrolled, verification } });
    if (sessionsChanging.has(session.id)) return sendJson(response, 423, { error: 'جارٍ تغيير حالة الجلسة. أعد المحاولة بعد لحظات.' });
    await persistCheckin(session, previousAttendance, checkinEvents, selfEnrolled ? student : null);
    if (attendanceRecord.locationPoint || attendanceRecord.networkArea) schedulePeerVerificationRefresh(session.id);
    const baseMessage = selfEnrolled ? 'تم تسجيل حضورك وإضافة اسمك إلى القائمة. سيظهر الاسم للأستاذ للمراجعة.' : timing.status === 'tardy' ? `تم تسجيل حضورك متأخرًا ${timing.lateByMinutes} دقيقة عن موعد البداية.` : 'تم تسجيل حضورك بنجاح.';
    const deviceNotice = deviceStatus === 'shared' ? ' رُصد استخدام المتصفح نفسه لأكثر من طالب.' : '';
    return sendJson(response, 201, { ok: true, flagged, status: attendanceRecord.status, lateByMinutes: attendanceRecord.lateByMinutes || null, verification, message: `${baseMessage}${flagged ? ' أُضيفت إشارة للمراجعة.' : ''}${deviceNotice}` });
  }

  if (url.pathname === '/api/session/control' && request.method === 'POST') {
    if (!requireInstructor(request, response)) return;
    const body = await readJsonBody(request);
    const sessionId = String(body.sessionId || '');
    const action = String(body.action || '');
    if (!['pause', 'resume', 'rotate', 'interval', 'duration'].includes(action)) return sendJson(response, 400, { error: 'إجراء الجلسة غير صالح.' });
    if (sessionsChanging.has(sessionId) || sessionsEnding.has(sessionId)) return sendJson(response, 423, { error: 'جارٍ تحديث الجلسة. أعد المحاولة.' });
    if (!readState().sessions.some(item => item.id === sessionId && item.active)) return sendJson(response, 404, { error: 'الجلسة غير متاحة.' });
    sessionsChanging.add(sessionId);
    try {
      await waitForSessionCheckinWrites(sessionId);
      const result = inTransaction(() => {
        const state = JSON.parse(selectCachedState.get().data);
        const session = state.sessions.find(item => item.id === sessionId && item.active);
        if (!session) throw new Error('الجلسة غير متاحة.');
        const now = Date.now();
        let label;
        if (action === 'pause') {
          if (session.paused) throw new Error('الجلسة متوقفة مؤقتًا بالفعل.');
          session.paused = true;
          session.pausedRemainingMs = session.autoEndAt ? Math.max(0, Date.parse(session.autoEndAt) - now) : null;
          session.autoEndAt = null;
          label = 'إيقاف التسجيل مؤقتًا';
        } else if (action === 'resume') {
          if (!session.paused) throw new Error('الجلسة مفتوحة بالفعل.');
          session.paused = false;
          session.autoEndAt = session.pausedRemainingMs == null ? null : new Date(now + session.pausedRemainingMs).toISOString();
          delete session.pausedRemainingMs;
          label = 'استئناف التسجيل';
        } else if (action === 'rotate') {
          session.previousPinIntervalSeconds = pinIntervalSeconds(session);
          session.previousPinGeneration = Math.max(0, Number(session.pinGeneration) || 0);
          session.pinGeneration = session.previousPinGeneration + 1;
          session.pinRotatedAt = new Date(now).toISOString();
          label = 'تجديد رمز الجلسة';
        } else if (action === 'interval') {
          const seconds = Number(body.seconds);
          if (!Number.isInteger(seconds) || seconds < 20 || seconds > 3600) throw new Error('اختر مدة بين 20 و3600 ثانية.');
          session.previousPinIntervalSeconds = pinIntervalSeconds(session);
          session.previousPinGeneration = Math.max(0, Number(session.pinGeneration) || 0);
          session.pinRotationSeconds = seconds;
          session.pinGeneration = session.previousPinGeneration + 1;
          session.pinRotatedAt = new Date(now).toISOString();
          label = 'تعديل تدوير الرمز';
        } else {
          const minutes = Number(body.minutes);
          if (!Number.isInteger(minutes) || ![0,30,60,90,120].includes(minutes)) throw new Error('مدة الجلسة غير صالحة.');
          session.autoEndMinutes = minutes;
          session.autoEndAt = session.paused || !minutes ? null : new Date(now + minutes * 60_000).toISOString();
          if (session.paused) session.pausedRemainingMs = minutes ? minutes * 60_000 : null;
          label = 'تعديل مدة الجلسة';
        }
        const auditEvent = { id: crypto.randomUUID(), at: new Date(now).toISOString(), actor: 'الأستاذ', action: label, summary: label, after: { sessionId, paused: session.paused, pinGeneration: session.pinGeneration } };
        state.auditLog = [auditEvent, ...(state.auditLog || [])].slice(0, 2000);
        updateState.run(JSON.stringify(state), new Date(now).toISOString());
        checkinBaseStateCache = null;
        return { session, auditEvent };
      });
      return sendJson(response, 200, { ok: true, session: result.session, auditEvent: result.auditEvent });
    } catch (error) {
      return sendJson(response, 400, { error: error.message || 'تعذر تحديث الجلسة.' });
    } finally {
      sessionsChanging.delete(sessionId);
    }
  }

  if (url.pathname === '/api/session/end' && request.method === 'POST') {
    if (!requireInstructor(request, response)) return;
    const body = await readJsonBody(request);
    const sessionId = String(body.sessionId || '').trim();
    if (!sessionId) return sendJson(response, 400, { error: 'معرّف الجلسة غير صالح.' });
    if (sessionsEnding.has(sessionId)) return sendJson(response, 423, { error: 'جارٍ إنهاء الجلسة.' });
    const currentState = readState();
    const currentSession = currentState.sessions.find(item => item.id === sessionId);
    if (!currentSession) return sendJson(response, 404, { error: 'الجلسة غير موجودة.' });
    if (!currentSession.active) return sendJson(response, 200, { ok: true, session: { id: currentSession.id, active: false, endedAt: currentSession.endedAt || null } });
    sessionsEnding.add(sessionId);
    try {
      await waitForSessionCheckinWrites(sessionId);
      const state = readState();
      const session = state.sessions.find(item => item.id === sessionId);
      if (!session) return sendJson(response, 404, { error: 'الجلسة غير موجودة.' });
      if (!session.active) return sendJson(response, 200, { ok: true, session: { id: session.id, active: false, endedAt: session.endedAt || null } });
      const endedAt = new Date().toISOString();
      session.active = false;
      session.paused = false;
      session.endedAt = endedAt;
      finalizeSessionLocations(state, session);
      const course = state.courses.find(item => item.id === session.courseId) || {};
      const auditEvent = { id: crypto.randomUUID(), at: endedAt, actor: 'الأستاذ', action: 'إنهاء جلسة', summary: 'انتهت جلسة ' + (course.name || 'الحضور'), after: { sessionId } };
      state.auditLog.unshift(auditEvent);
      state.auditLog = state.auditLog.slice(0, 2000);
      const savedState = writeState(state);
      const savedSession = savedState.sessions.find(item => item.id === sessionId);
      return sendJson(response, 200, { ok: true, session: { id: savedSession.id, active: savedSession.active, endedAt: savedSession.endedAt, records: savedSession.records }, auditEvent });
    } catch (error) {
      return sendJson(response, 500, { error: error.message || 'تعذر إنهاء الجلسة.' });
    } finally {
      sessionsEnding.delete(sessionId);
    }
  }
  if (url.pathname === '/api/state' && request.method === 'GET') {
    if (!requireInstructor(request, response)) return;
    return sendJson(response, 200, readState());
  }

  if (url.pathname === '/api/state' && request.method === 'PUT') {
    if (!requireInstructor(request, response)) return;
    const body = await readJsonBody(request);
    try {
      const known = new Set(readState().sessions.map(session => session.id));
      const fresh = normalizedState(body).sessions.filter(session => session.active && !known.has(session.id)
        && session.verificationSettings?.locationPolicy !== 'off' && session.verificationSettings);
      if (fresh.length) {
        const area = await lookupIpArea(requestClientIp(request));
        for (const session of fresh) {
          session.verificationSettings.teacherNetworkArea = area;
        }
      }
      if (pendingCheckinWrites.length) {
        clearTimeout(checkinWriteTimer);
        flushPendingCheckinWrites();
      }
      return sendJson(response, 200, { ok: true, state: writeState(body, true, true) });
    }
    catch (error) { return sendJson(response, 400, { error: error.message }); }
  }

  return sendJson(response, 404, { error: 'المسار غير موجود.' });
}

function serveStatic(request, response, url) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return sendJson(response, 405, { error: 'الطريقة غير مدعومة.' });
  let filePath;
  if (url.pathname === '/' || url.pathname === '/index.html') filePath = path.join(__dirname, 'index.html');
  else if (url.pathname === '/students-demo.csv') filePath = path.join(__dirname, 'students-demo.csv');
  else return sendJson(response, 404, { error: 'الصفحة غير موجودة.' });

  securityHeaders(response);
  const isCsv = url.pathname.endsWith('.csv');
  response.setHeader('Content-Type', isCsv ? 'text/csv; charset=utf-8' : 'text/html; charset=utf-8');
  if (!isCsv) response.setHeader('Vary', 'Accept-Encoding');
  const gzip = !isCsv && request.method === 'GET' && /(?:^|,)\s*gzip\s*(?:;|,|$)/i.test(request.headers['accept-encoding'] || '');
  if (gzip) response.setHeader('Content-Encoding', 'gzip');
  if (url.pathname.endsWith('.csv')) response.setHeader('Content-Disposition', 'attachment; filename="students-demo.csv"');
  const stream = fs.createReadStream(filePath);
  stream.on('error', () => {
    if (!response.headersSent) sendJson(response, 500, { error: 'تعذر فتح الملف.' });
    else response.destroy();
  });
  if (request.method === 'HEAD') { response.end(); stream.destroy(); }
  else if (gzip) {
    const compressor = zlib.createGzip();
    compressor.on('error', () => response.destroy());
    stream.pipe(compressor).pipe(response);
  } else stream.pipe(response);
}

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url, `http://${request.headers.host || `${HOST}:${PORT}`}`);
    if (url.pathname.startsWith('/api/')) return await handleApi(request, response, url);
    return serveStatic(request, response, url);
  } catch (error) {
    if (!response.headersSent) sendJson(response, 400, { error: error.message || 'تعذر إكمال الطلب.' });
    else response.destroy();
  }
});

server.listen(PORT, HOST, () => console.log(`خادم حضور المحلي: http://${HOST}:${PORT}`));
const autoEndTimer = setInterval(expireSessions, 5000);
autoEndTimer.unref();
server.on('close', () => database.close());
