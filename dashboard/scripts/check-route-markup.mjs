// Tailwind's source scanner skips bracketed route folders (src/app/runs/[id]/...), so a utility class
// used only in a file there is silently never generated. Keep markup in src/components/ and let the
// route files be thin wrappers. This check fails the build if that rule is broken.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const root = new URL("../src/app", import.meta.url).pathname;
const offenders = [];

function walk(dir) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) walk(path);
    else if (/\.(tsx|jsx)$/.test(name) && /[\\/]\[[^\]]+\][\\/]/.test(path + "/") && /className\s*=/.test(readFileSync(path, "utf8"))) {
      offenders.push(relative(process.cwd(), path));
    }
  }
}
walk(root);

if (offenders.length) {
  console.error("These route files sit in a bracketed folder and use className (Tailwind will not see it):");
  for (const f of offenders) console.error("  - " + f);
  console.error("Move the markup into src/components/ and render it from the route file.");
  process.exit(1);
}
console.log("route markup check ok");
