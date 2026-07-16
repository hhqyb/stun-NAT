import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import net from 'node:net';
import { after, before, test } from 'node:test';
import { spawn } from 'node:child_process';

const port = 17992; const token = 'probe-test-token'; let probe;
function listen(server) { return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port))); }
async function request(body) { return fetch(`http://127.0.0.1:${port}/probe`, { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ token, ...body }) }); }
before(async () => { probe=spawn(process.execPath,['probe-server.js'],{env:{...process.env,PROBE_PORT:String(port),STUNMAP_PROBE_TOKEN:token}}); await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('probe did not start')),3000); probe.stdout.on('data',()=>{clearTimeout(timer);resolve();}); probe.on('error',reject);}); });
after(() => probe.kill('SIGTERM'));

test('public probe checks TCP channel handshake without application payload', async () => {
  const server=net.createServer((socket)=>socket.destroy()); const targetPort=await listen(server); const response=await request({address:'127.0.0.1',port:targetPort,protocol:'tcp'}); assert.equal(response.status,200); assert.equal((await response.json()).reachable,true); server.close();
});
test('public probe checks UDP channel echo', async () => {
  const server=dgram.createSocket('udp4'); const targetPort=await new Promise((resolve)=>server.bind(0,'127.0.0.1',()=>resolve(server.address().port))); server.on('message',(message,remote)=>server.send(message,remote.port,remote.address)); const response=await request({address:'127.0.0.1',port:targetPort,protocol:'udp'}); assert.equal(response.status,200); assert.equal((await response.json()).reachable,true); server.close();
});
test('public probe rejects invalid token', async () => {
  const response=await fetch(`http://127.0.0.1:${port}/probe`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({token:'wrong',address:'127.0.0.1',port:1,protocol:'tcp'})}); assert.equal(response.status,403);
});
