/* Différentiel IPv6 / bornes IPv4 — le corpus réel est 100 % IPv4 bien formé,
   donc l'arithmétique d'adresses du portage JS n'y était validée par rien.
   Ce test compare le JS à l'oracle Python sur les cas que les vrais backups
   ne contiennent pas : IPv6 sous ses formes compressée/étendue/ULA/:: /128,
   et les bornes IPv4 où un décalage 32 bits signé en JS part en négatif. */
import { readFileSync } from "node:fs";
import { loadFabrics, resolveSubnet } from "../web/resolve.js";

const data = JSON.parse(readFileSync(new URL("./data/fabrics-ipv6.json", import.meta.url), "utf8"));
const oracle = JSON.parse(readFileSync(new URL("./reference/python-oracle-ipv6.json", import.meta.url), "utf8"));
const F = loadFabrics(data);

const norm = g => g.fabrics.map(f => ({
  id: f.id, status: f.status, summary: f.summary,
  hits: (f.hits || []).map(h => `${h.dn}|${h.role}|${h.match}|${(h.scopes||[]).join(",")}`).sort(),
  nodes: Object.keys(f.nodes).sort(),
  edges: (f.edges || []).map(e => `${e.from}>${e.to}|${e.rel}`).sort(),
}));

let ko = 0, total = 0, ecarts = 0;
for (const [q, exp] of Object.entries(oracle.subnet)) {
  total++;
  let got;
  try { got = resolveSubnet(F, q); }
  catch (e) { console.log(`KO  subnet:${q}  EXCEPTION ${e.message}`); ko++; ecarts++; continue; }
  const a = JSON.stringify(norm(exp)), b = JSON.stringify(norm(got));
  if (a === b) { console.log(`OK  subnet:${q}`); continue; }
  ko++;
  console.log(`KO  subnet:${q}`);
  const A = norm(exp), B = norm(got);
  for (let i = 0; i < A.length; i++) {
    const x = A[i], y = B[i] || { nodes: [], edges: [], hits: [] };
    const miss = x.nodes.filter(n => !y.nodes.includes(n));
    const extra = y.nodes.filter(n => !x.nodes.includes(n));
    const hm = x.hits.filter(h => !y.hits.includes(h));
    const he = y.hits.filter(h => !x.hits.includes(h));
    if (!miss.length && !extra.length && !hm.length && !he.length && x.status === y.status) continue;
    ecarts++;
    console.log(`      ${x.id}: statut ${x.status} vs ${y.status}`);
    miss.slice(0, 2).forEach(n => console.log(`        MANQUE  ${n}`));
    extra.slice(0, 2).forEach(n => console.log(`        EN TROP ${n}`));
    hm.slice(0, 2).forEach(h => console.log(`        HIT MANQUE  ${h}`));
    he.slice(0, 2).forEach(h => console.log(`        HIT EN TROP ${h}`));
  }
}
console.log("\n" + "-".repeat(70));
console.log(`  requetes OK : ${total - ko}/${total}   ecarts : ${ecarts}`);
console.log(ko ? "RESULTAT: DIVERGENT" : "RESULTAT: IDENTIQUE");
process.exit(ko ? 1 : 0);
