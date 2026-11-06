const eastEightOffset = 8 * 60 * 60 * 1000;

// Explicit offset keeps disk logs, API values and browsers independent of the host timezone.
export function formatLogTime(value = Date.now()) {
  if (value === null || value === '') return '—';
  const milliseconds = new Date(value).getTime();
  if (!Number.isFinite(milliseconds)) return String(value);
  return new Date(milliseconds + eastEightOffset).toISOString().replace('Z', '+08:00');
}
