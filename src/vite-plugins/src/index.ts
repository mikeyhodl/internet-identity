import { isNullish, nonNullish } from "@dfinity/utils";
import { createHash } from "crypto";
import { writeFileSync } from "fs";
import { minify } from "html-minifier-terser";
import { extname } from "path";
import type { Plugin, ViteDevServer } from "vite";
import viteCompression from "vite-plugin-compression";
import { forwardToReplica, readCanisterId } from "./utils.js";

export * from "./utils.js";

/**
 * Inject the canister ID of 'canisterName' as a <script /> tag in index.html for local development. Will process
 * at most 1 script tag.
 */
export const injectCanisterIdPlugin = ({
  canisterName,
}: {
  canisterName: string;
}): Plugin => ({
  name: "inject-canister-id",
  transformIndexHtml(html): string {
    const rgx = /<script type="module" src="(?<src>[^"]+)"><\/script>/;
    const canisterId = readCanisterId({ canisterName });
    return html.replace(rgx, (_match, src) => {
      return `<script data-canister-id="${canisterId}" type="module" src="${src}"></script>`;
    });
  },
});

/**
 * GZip generated resources e.g. index.js => index.js.gz
 */
export const compression = (): Plugin =>
  viteCompression({
    // II canister only supports one content type per resource. That is why we remove the original file.
    deleteOriginFile: true,
    filter: (file: string): boolean =>
      [".js", ".woff2"].includes(extname(file)),
  });

/**
 * Minify HTML
 */
export const minifyHTML = (): Plugin => ({
  name: "minify-html",
  async transformIndexHtml(html): Promise<string> {
    return minify(html, { collapseWhitespace: true });
  },
});

/**
 * Forwards requests to the local replica.
 * Denies access to raw URLs.
 *
 * @param replicaOrigin Replica URL to forward requests to
 * @param forwardRules List of rules (i.e. hostname to canisterId mappings)
 *                     to forward requests to a specific canister
 */
export const replicaForwardPlugin = ({
  replicaOrigin,
  forwardDomains /* note: will match exactly on <canister>.<domain> */,
  forwardRules,
}: {
  replicaOrigin: string;
  forwardDomains?: string[];
  forwardRules: Array<{ canisterName: string; hosts: string[] }>;
}) => ({
  name: "replica-forward",
  configureServer(server: ViteDevServer) {
    server.middlewares.use((req, res, next) => {
      if (
        /* Deny requests to raw URLs, e.g. <canisterId>.raw.ic0.app to make sure that II always uses certified assets
         * to verify the alternative origins. */
        req.headers["host"]?.includes(".raw.")
      ) {
        console.log(
          `Denying access to raw URL ${req.method} https://${req.headers.host}${req.url}`
        );
        res.statusCode = 400;
        res.end("Raw IC URLs are not supported");
        return;
      }

      const host_ = req.headers["host"];
      if (isNullish(host_)) {
        // default handling
        return next();
      }

      const [host, _port] = host_.split(":");

      const matchingRule = forwardRules.find((rule) =>
        rule.hosts.includes(host)
      );

      if (!isNullish(matchingRule)) {
        const canisterId = readCanisterId({
          canisterName: matchingRule.canisterName,
        });
        console.log("Host matches forward rule", host);
        return forwardToReplica({ canisterId, req, res, replicaOrigin });
      }

      // split the subdomain & domain by splitting on the first dot
      const [subdomain_, ...domain_] = host.split(".");
      const [subdomain, domain] =
        domain_.length > 0
          ? [subdomain_, domain_.join(".")]
          : [undefined, subdomain_];

      if (
        nonNullish(forwardDomains) &&
        nonNullish(subdomain) &&
        forwardDomains.includes(domain) &&
        /([a-z0-9])+(-[a-z0-9]+)+/.test(
          subdomain
        ) /* fast check for principal-ish */
      ) {
        // Assume the principal-ish thing is a canister ID
        console.log("Domain matches list to forward", domain);
        return forwardToReplica({
          canisterId: subdomain,
          req,
          res,
          replicaOrigin,
        });
      }

      // Try to read the canister ID of a potential canister called <subdomain>
      // and if found forward to that
      if (nonNullish(subdomain) && domain === "localhost") {
        try {
          const canisterId = readCanisterId({ canisterName: subdomain });
          console.log("Subdomain is a canister", subdomain, canisterId);
          return forwardToReplica({ canisterId, req, res, replicaOrigin });
        } catch {}
      }

      return next();
    });
  },
});

/** Update the HTML files to include integrity hashes for script.
 * i.e.: `<script src="foo.js">` becomes `<script integrity="<hash(./foo.js)>" src="foo.js">`.
 */
export const integrityPlugin: Plugin = {
  name: "integrity",
  apply: "build" /* only use during build, not serve */,

  // XXX We use writeBundle as opposed to transformIndexHtml because transformIndexHtml still
  // includes some variables (VITE_PRELOAD) that will be replaced later (by vite), changing
  // the effective checksum. By the time writeBundle is called, the bundle has already been
  // written so we update the files directly on the filesystem.
  writeBundle(options: any, bundle: any) {
    // Matches a script tag, grouping all the attributes (re-injected later) and extracting
    // the 'src' attribute
    const rgx =
      /<script(?<attrs>(?:\s+[^>]+)*\s+src="?(?<src>[^"]+)"?(?:\s+[^>]+)*)>/g;

    const distDir = options.dir;

    for (const filename in bundle) {
      // If this is not HTML, skip
      if (!filename.endsWith(".html")) {
        continue;
      }

      // Grab the source, match all the script tags, inject the hash, and write the updated
      // HTML to the filesystem
      const html: string = bundle[filename].source;
      const replaced = html.replace(rgx, (match, attrs, src) => {
        const subresourcePath = src.slice(1); /* drop leading slash */
        const item =
          bundle[subresourcePath]; /* grab the item from the bundle */
        const content = item.source || item.code;
        const HASH_ALGO = "sha384" as const;
        const integrityHash = createHash(HASH_ALGO)
          .update(content)
          .digest()
          .toString("base64"); /* Compute the hash */

        const integrityValue = `${HASH_ALGO}-${integrityHash}`;
        return `<script integrity="${integrityValue}"${attrs}>`;
      });

      // Write the new content to disk
      const filepath = [distDir, filename].join("/");
      writeFileSync(filepath, replaced);
    }
  },
};
