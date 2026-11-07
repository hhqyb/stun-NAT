import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const MAX_LOG_BYTES = 1024 ** 3;
export const DEFAULT_LOG_FILE_BYTES = 16 * 1024 ** 2;
const logName = /^[a-zA-Z0-9_-]+\.log(?:\.\d+-[a-f0-9]+)?$/;
const truncatedMarker = Buffer.from(' …[日志过长，已截断]\n');

function positiveLimit(value, maximum, label) {
  if (!Number.isSafeInteger(value) || value < 64 || value > maximum) throw new Error(`${label} 必须是 64-${maximum} 之间的整数字节数`);
  return value;
}

function boundedRecord(text, limit) {
  const record = Buffer.from(text.endsWith('\n') ? text : `${text}\n`);
  if (record.length <= limit) return record;
  let end = limit - truncatedMarker.length;
  // Never split a UTF-8 character at the truncation boundary.
  while (end > 0 && (record[end] & 0xc0) === 0x80) end--;
  return Buffer.concat([record.subarray(0, end), truncatedMarker]);
}

// One store per data directory. Synchronous writes keep rotations and the shared budget atomic
// with respect to all RuleRunners in this process; no open handles survive a rotation.
export class RotatingLogStore {
  constructor(directory, { maxTotalBytes = MAX_LOG_BYTES, maxFileBytes = Math.min(DEFAULT_LOG_FILE_BYTES, maxTotalBytes) } = {}) {
    this.directory = directory;
    this.maxTotalBytes = positiveLimit(maxTotalBytes, MAX_LOG_BYTES, '日志总上限');
    this.maxFileBytes = positiveLimit(maxFileBytes, this.maxTotalBytes, '单个日志文件上限');
    this.files = new Map();
    this.totalBytes = 0;
    fs.mkdirSync(directory, { recursive: true });
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (!entry.isFile() || !logName.test(entry.name)) continue;
      const filename = path.join(directory, entry.name);
      const stat = fs.statSync(filename);
      const size = stat.size > this.maxTotalBytes ? this.keepTail(filename, stat) : stat.size;
      this.files.set(entry.name, { size, modified: stat.mtimeMs, archive: entry.name.includes('.log.') });
      this.totalBytes += size;
    }
    this.prune();
  }

  keepTail(filename, stat) {
    const fd = fs.openSync(filename, 'r+');
    try {
      // Bound memory even when upgrading from a legacy multi-gigabyte log. Keep existing
      // history within the shared budget; the next append rotates any oversized active file.
      let start = stat.size - this.maxTotalBytes;
      const buffer = Buffer.alloc(Math.min(64 * 1024, this.maxTotalBytes + 1));
      const peeked = fs.readSync(fd, buffer, 0, buffer.length, start - 1);
      if (buffer[0] !== 10) {
        const newline = buffer.subarray(1, peeked).indexOf(10);
        if (newline >= 0 && start + newline + 1 < stat.size) start += newline + 1;
        else {
          let offset = 1;
          while (offset < peeked && (buffer[offset] & 0xc0) === 0x80) offset++;
          start += offset - 1;
        }
      }
      let copied = 0;
      while (start + copied < stat.size) {
        const read = fs.readSync(fd, buffer, 0, Math.min(buffer.length, stat.size - start - copied), start + copied);
        if (!read) break;
        let written = 0;
        while (written < read) written += fs.writeSync(fd, buffer, written, read - written, copied + written);
        copied += read;
      }
      fs.ftruncateSync(fd, copied);
      fs.futimesSync(fd, stat.atime, stat.mtime);
      return copied;
    } finally { fs.closeSync(fd); }
  }

  prune(incoming = 0, protectedName = '') {
    if (this.totalBytes + incoming <= this.maxTotalBytes) return;
    // Prefer dropping rotated history; only then evict the oldest other active file.
    const candidates = [...this.files].filter(([name]) => name !== protectedName)
      .sort((a, b) => Number(b[1].archive) - Number(a[1].archive) || a[1].modified - b[1].modified || a[0].localeCompare(b[0]));
    for (const [name, info] of candidates) {
      fs.rmSync(path.join(this.directory, name), { force: true });
      this.files.delete(name);
      this.totalBytes -= info.size;
      if (this.totalBytes + incoming <= this.maxTotalBytes) break;
    }
  }

  append(ruleId, text) {
    if (!/^[a-zA-Z0-9_-]+$/.test(ruleId)) throw new Error('日志规则 ID 无效');
    const name = `${ruleId}.log`;
    const filename = path.join(this.directory, name);
    const record = boundedRecord(String(text), this.maxFileBytes);
    let info = this.files.get(name) || { size: 0, modified: 0, archive: false };
    if (info.size + record.length > this.maxFileBytes) {
      const archiveName = `${name}.${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;
      fs.renameSync(filename, path.join(this.directory, archiveName));
      this.files.delete(name);
      this.files.set(archiveName, { ...info, archive: true });
      info = { size: 0, modified: 0, archive: false };
    }
    this.prune(record.length, name);
    fs.appendFileSync(filename, record, { mode: 0o600 });
    this.files.set(name, { size: info.size + record.length, modified: Date.now(), archive: false });
    this.totalBytes += record.length;
  }

  listRule(ruleId) {
    if (!/^[a-zA-Z0-9_-]+$/.test(ruleId)) throw new Error('日志规则 ID 无效');
    const current = `${ruleId}.log`;
    return [...this.files].filter(([name]) => name === current || name.startsWith(`${current}.`))
      .map(([name, info]) => ({ name, size: info.size, modified: info.modified, archive: info.archive }))
      .sort((a, b) => Number(a.archive) - Number(b.archive) || b.modified - a.modified || a.name.localeCompare(b.name));
  }

  removeRule(ruleId) {
    if (!/^[a-zA-Z0-9_-]+$/.test(ruleId)) throw new Error('日志规则 ID 无效');
    const current = `${ruleId}.log`;
    let removed = 0;
    for (const [name, info] of [...this.files]) {
      if (name !== current && !name.startsWith(`${current}.`)) continue;
      fs.rmSync(path.join(this.directory, name), { force: true });
      this.files.delete(name);
      this.totalBytes -= info.size;
      removed++;
    }
    return removed;
  }
}
