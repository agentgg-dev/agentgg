/**
 * Tiny worker-pool: process `items` with up to `limit` concurrent
 * invocations of `fn`. Each worker pulls the next index off a shared
 * cursor and calls `fn`. Resolves when every item has been processed.
 *
 * The caller is responsible for catching errors inside `fn`. When `fn`
 * does throw (e.g. a fatal credential error rethrown by
 * `handleDetectorError`), the pool stops dispatching new work to the
 * remaining items, lets every already-launched call settle, then
 * re-throws the first error. That ordering matters on Windows:
 * `process.exit` while a claude-agent-sdk subprocess is still mid-shutdown
 * triggers a libuv double-close assertion. By waiting for in-flight
 * promises to drain, we avoid that race entirely.
 */
export async function runConcurrent<T>(
  items: ReadonlyArray<T>,
  limit: number,
  fn: (item: T, index: number) => Promise<void>,
): Promise<void> {
  const cap = Math.max(1, limit);
  if (items.length === 0) return;

  let cursor = 0;
  let firstError: unknown = null;
  const workerCount = Math.min(cap, items.length);
  const workers = Array.from({ length: workerCount }, async () => {
    while (true) {
      if (firstError !== null) return;
      const i = cursor++;
      if (i >= items.length) return;
      try {
        await fn(items[i], i);
      } catch (err) {
        // Capture the first error, swallow subsequent ones. Subsequent
        // throws would otherwise become unhandled rejections since
        // Promise.all rejects only once and the other worker promises
        // keep running in the background.
        if (firstError === null) firstError = err;
        return;
      }
    }
  });
  await Promise.all(workers);
  if (firstError !== null) throw firstError;
}
