/**
 * Tiny worker-pool: process `items` with up to `limit` concurrent
 * invocations of `fn`. Each worker pulls the next index off a shared
 * cursor and calls `fn`. Resolves when every item has been processed.
 *
 * The caller is responsible for catching errors inside `fn` — anything
 * thrown will reject the whole pool. The scan command wraps each
 * per-file call in its own try/catch so transient detector failures
 * don't abort a long-running scan.
 */
export async function runConcurrent<T>(
  items: ReadonlyArray<T>,
  limit: number,
  fn: (item: T, index: number) => Promise<void>,
): Promise<void> {
  const cap = Math.max(1, limit);
  if (items.length === 0) return;

  let cursor = 0;
  const workerCount = Math.min(cap, items.length);
  const workers = Array.from({ length: workerCount }, async () => {
    while (true) {
      const i = cursor++;
      if (i >= items.length) return;
      await fn(items[i], i);
    }
  });
  await Promise.all(workers);
}
