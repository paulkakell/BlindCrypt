import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(new URL("..", import.meta.url).pathname);
const failures = [];
const version = (await readFile(resolve(root, "VERSION"), "utf8")).trim();
const packageJson = JSON.parse(await readFile(resolve(root, "package.json"), "utf8"));

for (const script of ["lint", "typecheck", "test", "security", "config", "build", "smoke", "perf", "validate"]) {
  if (!packageJson.scripts?.[script]) failures.push(`package.json is missing ${script} script`);
}
if (packageJson.engines?.node !== ">=22") failures.push("Node engine must be >=22");
if (!/^\d{2}\.\d{2}\.\d{2}$/u.test(version)) failures.push("Invalid release version");

const ci = await readFile(resolve(root, ".github/workflows/ci.yml"), "utf8");
for (const required of ["push:", "dev", "pull_request:", "permissions:", "contents: read", "npm audit --audit-level=high", "npm run validate"]) {
  if (!ci.includes(required)) failures.push(`CI workflow is missing ${required}`);
}
const codeql = await readFile(resolve(root, ".github/workflows/codeql.yml"), "utf8");
if (!/github\/codeql-action\/(?:init|analyze)@[a-f0-9]{40}/u.test(codeql)) {
  failures.push("CodeQL actions must be pinned to commit SHAs");
}
const pages = await readFile(resolve(root, ".github/workflows/pages.yml"), "utf8");
for (const required of ["branches: [main]", "pages: write", "id-token: write", "environment:", "github-pages"]) {
  if (!pages.includes(required)) failures.push(`Pages workflow is missing ${required}`);
}

for (const [name, workflow] of [["CI", ci], ["CodeQL", codeql], ["Pages", pages]]) {
  for (const match of workflow.matchAll(/uses:\s+([^@\s]+)@([^\s#]+)/gu)) {
    if (!/^[a-f0-9]{40}$/u.test(match[2])) {
      failures.push(`${name} workflow action ${match[1]} is not pinned to a full commit SHA`);
    }
  }
}

const dependabot = await readFile(resolve(root, ".github/dependabot.yml"), "utf8");
for (const required of ["package-ecosystem: npm", "package-ecosystem: github-actions", "timezone: America/Denver"]) {
  if (!dependabot.includes(required)) failures.push(`Dependabot configuration is missing ${required}`);
}
const codeowners = await readFile(resolve(root, ".github/CODEOWNERS"), "utf8");
if (!codeowners.includes("/assets/crypto*.js @paulkakell")) failures.push("Cryptographic code owner is missing");

const npmrc = await readFile(resolve(root, ".npmrc"), "utf8");
for (const required of ["audit=true", "ignore-scripts=true", "save-exact=true", "engine-strict=true"]) {
  if (!npmrc.includes(required)) failures.push(`.npmrc is missing ${required}`);
}

const sbom = JSON.parse(await readFile(resolve(root, "SBOM.spdx.json"), "utf8"));
if (sbom.spdxVersion !== "SPDX-2.3") failures.push("SBOM must use SPDX 2.3");
if (!Array.isArray(sbom.packages) || !sbom.packages.some((entry) => entry.name === "BlindCrypt" && entry.versionInfo === version)) {
  failures.push("SBOM does not describe the current BlindCrypt version");
}

const index = await readFile(resolve(root, "index.html"), "utf8");
if (!index.includes("value=\"strong\" selected")) failures.push("Strong must remain the default security level");
if (!index.includes("64 MiB")) failures.push("File-size safety limit is not documented in the interface");

if (failures.length) {
  console.error(failures.map((failure) => `- ${failure}`).join("\n"));
  process.exit(1);
}
console.log("Configuration validation passed.");
