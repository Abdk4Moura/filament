/**
 * Filament Showcase Worker
 * ------------------------
 * Serves the static showcase (build-log page + reels/gifs) from R2 at
 *   https://filament.autumated.com/showcase/*
 *
 * Mapping: GET /showcase/<path>  ->  R2 object <path> (in the `filament-showcase`
 * bucket). `/showcase` and `/showcase/` serve `index.html`.
 *
 * This Worker is wired ONLY to the /showcase/* route; the main `filament` app
 * Worker (the SPA on `/`) is never touched.
 */

export interface Env {
  SHOWCASE: R2Bucket;
}

const ROUTE_PREFIX = "/showcase";

// Immutable media gets a long cache; html/css are revalidated more eagerly so
// re-publishes show up without a hard cache-bust.
const LONG_IMMUTABLE = "public, max-age=31536000, immutable";
const SHORT_HTML = "public, max-age=60, must-revalidate";

function contentTypeFor(key: string): string {
  const k = key.toLowerCase();
  if (k.endsWith(".mp4")) return "video/mp4";
  if (k.endsWith(".webm")) return "video/webm";
  if (k.endsWith(".gif")) return "image/gif";
  if (k.endsWith(".png")) return "image/png";
  if (k.endsWith(".jpg") || k.endsWith(".jpeg")) return "image/jpeg";
  if (k.endsWith(".svg")) return "image/svg+xml";
  if (k.endsWith(".webp")) return "image/webp";
  if (k.endsWith(".css")) return "text/css; charset=utf-8";
  if (k.endsWith(".js")) return "text/javascript; charset=utf-8";
  if (k.endsWith(".json")) return "application/json; charset=utf-8";
  if (k.endsWith(".html") || k.endsWith(".htm")) return "text/html; charset=utf-8";
  if (k.endsWith(".txt")) return "text/plain; charset=utf-8";
  return "application/octet-stream";
}

function cacheControlFor(key: string): string {
  const k = key.toLowerCase();
  if (k.endsWith(".html") || k.endsWith(".htm")) return SHORT_HTML;
  return LONG_IMMUTABLE;
}

function notFound(): Response {
  return new Response("404 — not found in showcase\n", {
    status: 404,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("Method Not Allowed", {
        status: 405,
        headers: { allow: "GET, HEAD" },
      });
    }

    let path = decodeURIComponent(url.pathname);

    // Only the /showcase/* surface is ours. (The route guarantees this, but be
    // defensive.)
    if (path !== ROUTE_PREFIX && !path.startsWith(ROUTE_PREFIX + "/")) {
      return notFound();
    }

    // Strip the route prefix -> R2 key.
    let key = path.slice(ROUTE_PREFIX.length); // "" | "/" | "/foo.mp4"
    if (key.startsWith("/")) key = key.slice(1);

    // Index for the root of the showcase, or any directory-style request.
    if (key === "" || key.endsWith("/")) {
      key = key + "index.html";
    }

    // Guard against path traversal.
    if (key.includes("..")) return notFound();

    // Parse a (single) HTTP Range into an R2Range. Anything we can't parse
    // cleanly -> serve the whole object (status 200), which is always valid.
    const rangeHeader = request.headers.get("range");
    let r2range: R2Range | undefined;
    if (rangeHeader) {
      const m = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader.trim());
      if (m && (m[1] !== "" || m[2] !== "")) {
        if (m[1] === "") {
          // bytes=-N  -> last N bytes
          r2range = { suffix: Number(m[2]) };
        } else if (m[2] === "") {
          // bytes=N-  -> from N to end
          r2range = { offset: Number(m[1]) };
        } else {
          // bytes=A-B
          const start = Number(m[1]);
          const endIncl = Number(m[2]);
          r2range = { offset: start, length: endIncl - start + 1 };
        }
      }
    }

    // Conditional GET support (If-None-Match / If-Modified-Since) without
    // mixing the Range header in.
    const onlyIf = new Headers();
    const inm = request.headers.get("if-none-match");
    const ims = request.headers.get("if-modified-since");
    if (inm) onlyIf.set("if-none-match", inm);
    if (ims) onlyIf.set("if-modified-since", ims);

    const object = await env.SHOWCASE.get(key, {
      range: r2range,
      onlyIf: onlyIf,
    });

    if (object === null) {
      // Either the key is missing, or a precondition (304) was satisfied.
      // Distinguish: a satisfied precondition only happens when the client
      // sent one. We can't tell from null alone, so re-check existence cheaply
      // via head() only when a conditional was present.
      if (inm || ims) {
        const head = await env.SHOWCASE.head(key);
        if (head !== null) {
          const h = new Headers();
          head.writeHttpMetadata(h);
          h.set("etag", head.httpEtag);
          h.set("cache-control", cacheControlFor(key));
          return new Response(null, { status: 304, headers: h });
        }
      }
      return notFound();
    }

    const headers = new Headers();
    object.writeHttpMetadata(headers);
    headers.set("etag", object.httpEtag);
    headers.set("content-type", contentTypeFor(key));
    headers.set("cache-control", cacheControlFor(key));
    headers.set("accept-ranges", "bytes");

    const body = (object as R2ObjectBody).body;
    const served = (object as R2ObjectBody).range as R2Range | undefined;

    let status = 200;
    if (r2range && served && object.size !== undefined) {
      let offset = 0;
      let length = object.size;
      if ("suffix" in served && served.suffix !== undefined) {
        length = Math.min(served.suffix, object.size);
        offset = object.size - length;
      } else {
        offset = ("offset" in served && served.offset !== undefined) ? served.offset : 0;
        length = ("length" in served && served.length !== undefined)
          ? served.length
          : object.size - offset;
      }
      const end = offset + length - 1;
      headers.set("content-range", `bytes ${offset}-${end}/${object.size}`);
      headers.set("content-length", String(length));
      status = 206;
    } else if (object.size !== undefined) {
      headers.set("content-length", String(object.size));
    }

    if (request.method === "HEAD") {
      return new Response(null, { status, headers });
    }

    return new Response(body, { status, headers });
  },
} satisfies ExportedHandler<Env>;
