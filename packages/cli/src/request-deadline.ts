import { APICallError } from "ai";
import { logWarn } from "./log.js";

/**
 * A deadline on one LLM HTTP request, headers and body together. A host can
 * send response headers and then stall on the body, and neither fetch nor the
 * AI SDK gives up on its own. The timeout is a retryable APICallError, so
 * the SDK retries that one request instead of failing the whole call.
 */
export function createDeadlineFetch(inner: typeof fetch, timeoutMs: number): typeof fetch {
  return async (input, init) => {
    const controller = new AbortController();
    const caller = init?.signal;
    let responseHeaders: Record<string, string> | undefined;
    const onCallerAbort = () => controller.abort(caller?.reason);
    if (caller?.aborted) onCallerAbort();
    else caller?.addEventListener("abort", onCallerAbort, { once: true });

    const timer = setTimeout(() => {
      const genId = responseHeaders?.["x-generation-id"];
      const message = `request timed out after ${timeoutMs / 1000}s${genId ? ` (genId=${genId})` : " with no response"}`;
      logWarn(`[request-deadline] ${message}`);
      controller.abort(
        new APICallError({
          message,
          url: requestUrl(input),
          requestBodyValues: undefined,
          responseHeaders,
          isRetryable: true,
        }),
      );
    }, timeoutMs);
    // A body the caller never reads must not keep the CLI alive at exit.
    timer.unref?.();
    const settle = () => {
      clearTimeout(timer);
      caller?.removeEventListener("abort", onCallerAbort);
    };

    let res: Response;
    try {
      res = await inner(input, { ...init, signal: controller.signal });
    } catch (err) {
      settle();
      throw controller.signal.aborted ? controller.signal.reason : err;
    }
    responseHeaders = Object.fromEntries(res.headers.entries());
    if (!res.body) {
      settle();
      return res;
    }

    // Re-wrap the body so the deadline also covers it, and so an abort surfaces
    // as the abort reason whatever fetch itself does with the stream.
    const reader = res.body.getReader();
    const body = new ReadableStream<Uint8Array>({
      start(stream) {
        controller.signal.addEventListener(
          "abort",
          () => {
            stream.error(controller.signal.reason);
            reader.cancel(controller.signal.reason).catch(() => {});
          },
          { once: true },
        );
      },
      async pull(stream) {
        try {
          const { done, value } = await reader.read();
          if (done) {
            settle();
            stream.close();
          } else {
            stream.enqueue(value);
          }
        } catch (err) {
          settle();
          stream.error(controller.signal.aborted ? controller.signal.reason : err);
        }
      },
      cancel(reason) {
        settle();
        return reader.cancel(reason);
      },
    });
    return new Response(body, {
      status: res.status,
      statusText: res.statusText,
      headers: res.headers,
    });
  };
}

function requestUrl(input: Parameters<typeof fetch>[0]): string {
  if (typeof input === "string") return input;
  return input instanceof URL ? input.href : input.url;
}
