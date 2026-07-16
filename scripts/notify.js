#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';

const [publicAddress, publicPort, ip4p, privatePort, protocol, privateAddress] = process.argv.slice(2);
const id = process.env.STUNMAP_RULE_ID;
const directory = process.env.STUNMAP_STATE_DIR;
if (!id || !directory || !publicAddress || !publicPort || !privatePort) process.exit(2);
const target = path.join(directory, `${id}.json`);
let previous = {};
try { previous = JSON.parse(fs.readFileSync(target, 'utf8')); } catch {}
const now = new Date().toISOString(); const changed = previous.publicAddress !== publicAddress || previous.publicPort !== Number(publicPort) || previous.privatePort !== Number(privatePort);
const state = { updatedAt: now, lastVerifiedAt: now, mappingChangedAt: changed ? now : previous.mappingChangedAt, publicAddress, publicPort: Number(publicPort), ip4p, privatePort: Number(privatePort), protocol, privateAddress };
const temp = `${target}.${process.pid}.tmp`;
fs.writeFileSync(temp, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 }); fs.renameSync(temp, target);
