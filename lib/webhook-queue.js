export function createWebhookQueue({ minGapMs = 1000, now = Date.now, sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)) } = {}) {
  let tail = Promise.resolve();
  let lastStart = null;
  return (task) => {
    const run = tail.then(async () => {
      if (lastStart !== null && minGapMs > 0) {
        const wait = lastStart + minGapMs - now();
        if (wait > 0) await sleep(wait);
      }
      lastStart = now();
      return task();
    });
    tail = run.catch(() => {});
    return run;
  };
}
