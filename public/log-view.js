import { formatLogTime } from './log-time.js';

function logRecords(logs) {
  const occurrences = new Map();
  return logs.map((log) => {
    // Older servers did not provide IDs; keep their repeated messages distinct too.
    const identity = log.id || JSON.stringify([log.at, log.level, log.message]);
    const occurrence = occurrences.get(identity) || 0;
    occurrences.set(identity, occurrence + 1);
    return { key: `${identity}:${occurrence}`, text: `${formatLogTime(log.at)} ${log.level.toUpperCase()} ${log.message}` };
  });
}

export class LogViewer {
  constructor(element, latestButton) {
    this.element = element;
    this.latestButton = latestButton;
    this.rows = new Map();
    this.latest = [];
    this.signature = null;
    this.pending = false;
    this.following = true;
    latestButton.addEventListener('click', () => { this.following = true; this.flush(); });
    element.addEventListener('scroll', () => {
      if (!element.clientHeight) return;
      this.following = this.atBottom();
      if (this.following && this.pending && !this.hasSelection()) this.flush();
    });
  }

  hasSelection() {
    const selection = this.element.ownerDocument.getSelection();
    if (!selection || selection.isCollapsed || !selection.rangeCount) return false;
    return selection.getRangeAt(0).intersectsNode(this.element);
  }

  atBottom() {
    return this.element.scrollHeight - this.element.clientHeight - this.element.scrollTop <= 2;
  }

  reveal() {
    if (this.following && !this.hasSelection()) {
      if (this.pending) this.flush();
      else this.element.scrollTop = this.element.scrollHeight;
    }
  }

  update(logs) {
    this.latest = logRecords(logs);
    const signature = JSON.stringify(this.latest);
    if (signature === this.signature) {
      this.pending = false;
      this.latestButton.disabled = true;
      this.latestButton.textContent = '已显示最新日志';
      return;
    }
    if (this.element.clientHeight) this.following = this.atBottom();
    if (this.signature !== null && (!this.following || this.hasSelection())) {
      // Keep the actual text nodes while reading, even when the API's 80-line window rolls.
      // Only the newest bounded snapshot is buffered; a long pause cannot grow memory forever.
      this.pending = true;
      this.latestButton.disabled = false;
      this.latestButton.textContent = '有新日志 · 查看最新';
      return;
    }
    this.flush();
  }

  flush() {
    const keys = new Set(this.latest.map((record) => record.key));
    for (const [key, row] of this.rows) {
      if (!keys.has(key)) { row.remove(); this.rows.delete(key); }
    }
    this.element.querySelector('.log-placeholder')?.remove();
    this.latest.forEach((record, index) => {
      let row = this.rows.get(record.key);
      if (!row) {
        row = this.element.ownerDocument.createElement('span');
        row.className = 'log-entry';
        this.rows.set(record.key, row);
      }
      if (row.textContent !== record.text) row.textContent = record.text;
      if (this.element.children[index] !== row) this.element.insertBefore(row, this.element.children[index] || null);
    });
    if (!this.latest.length) {
      const placeholder = this.element.ownerDocument.createElement('span');
      placeholder.className = 'log-placeholder';
      placeholder.textContent = '暂无日志';
      this.element.append(placeholder);
    }
    this.signature = JSON.stringify(this.latest);
    this.pending = false;
    this.latestButton.disabled = true;
    this.latestButton.textContent = '已显示最新日志';
    if (this.following) this.element.scrollTop = this.element.scrollHeight;
  }
}
