const http = require('http');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

const PORT = 7700;
const API_KEY = process.env.OSIRIS_KEY || 'osiris-scanner-2024';

// Rate limiting
const rateLimit = new Map();
const RATE_LIMIT = 10;
const RATE_WINDOW = 60000;

function checkRate(ip) {
  const now = Date.now();
  const entry = rateLimit.get(ip) || { count: 0, reset: now + RATE_WINDOW };
  if (now > entry.reset) { entry.count = 0; entry.reset = now + RATE_WINDOW; }
  entry.count++;
  rateLimit.set(ip, entry);
  return entry.count <= RATE_LIMIT;
}

function validateTarget(target) {
  if (!target || typeof target !== 'string') return false;
  if (target.length > 253) return false;
  if (/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.|169\.254\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.)/.test(target)) return false;
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(target) || /^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(target);
}

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Content-Type', 'application/json');
}

function json(res, code, data) {
  cors(res);
  res.writeHead(code);
  res.end(JSON.stringify(data));
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') { cors(res); res.writeHead(204); res.end(); return; }

  const url = new URL(req.url, 'http://localhost');
  const clientIP = req.socket.remoteAddress;

  const authKey = url.searchParams.get('key') || req.headers['authorization']?.replace('Bearer ', '');
  if (authKey !== API_KEY) return json(res, 401, { error: 'Unauthorized' });
  if (!checkRate(clientIP)) return json(res, 429, { error: 'Rate limited' });

  const target = url.searchParams.get('target');

  try {
    if (url.pathname === '/health') {
      return json(res, 200, { status: 'ok', scanner: 'osiris-nmap', version: '1.0', uptime: process.uptime() });
    }

    if (url.pathname === '/scan/ports') {
      if (!validateTarget(target)) return json(res, 400, { error: 'Invalid target' });
      const ports = url.searchParams.get('ports') || '21,22,23,25,53,80,110,143,443,993,995,3306,3389,5432,8080,8443';
      const { stdout } = await execAsync(
        `nmap -Pn -sV --open -p ${ports} --max-retries 1 --host-timeout 30s -oX - ${target}`,
        { timeout: 45000 }
      );
      return json(res, 200, { target, scan_type: 'port_scan', ...parseNmapXML(stdout), timestamp: new Date().toISOString() });
    }

    if (url.pathname === '/scan/quick') {
      if (!validateTarget(target)) return json(res, 400, { error: 'Invalid target' });
      const { stdout } = await execAsync(
        `nmap -Pn -F --open --max-retries 1 --host-timeout 20s -oX - ${target}`,
        { timeout: 30000 }
      );
      return json(res, 200, { target, scan_type: 'quick_scan', ...parseNmapXML(stdout), timestamp: new Date().toISOString() });
    }

    if (url.pathname === '/scan/banner') {
      if (!validateTarget(target)) return json(res, 400, { error: 'Invalid target' });
      const port = url.searchParams.get('port') || '80';
      const { stdout } = await execAsync(
        `nmap -Pn -sV -p ${port} --version-intensity 5 --max-retries 1 --host-timeout 15s -oX - ${target}`,
        { timeout: 20000 }
      );
      return json(res, 200, { target, scan_type: 'banner_grab', port, ...parseNmapXML(stdout), timestamp: new Date().toISOString() });
    }

    if (url.pathname === '/scan/ssl') {
      if (!validateTarget(target)) return json(res, 400, { error: 'Invalid target' });
      const port = url.searchParams.get('port') || '443';
      const { stdout } = await execAsync(
        `nmap -Pn --script ssl-enum-ciphers,ssl-cert -p ${port} --host-timeout 15s -oX - ${target}`,
        { timeout: 20000 }
      );
      let cert = null;
      try {
        const { stdout: certOut } = await execAsync(
          `echo | openssl s_client -connect ${target}:${port} -servername ${target} 2>/dev/null | openssl x509 -noout -subject -issuer -dates -fingerprint 2>/dev/null`,
          { timeout: 10000 }
        );
        cert = parseCertOutput(certOut);
      } catch {}
      return json(res, 200, { target, scan_type: 'ssl_analysis', port, ...parseNmapXML(stdout), certificate: cert, timestamp: new Date().toISOString() });
    }

    if (url.pathname === '/scan/traceroute') {
      if (!validateTarget(target)) return json(res, 400, { error: 'Invalid target' });
      const { stdout } = await execAsync(`traceroute -m 20 -w 2 ${target} 2>&1 | head -25`, { timeout: 30000 });
      const hops = stdout.split('\n').filter(l => l.trim()).map(l => l.trim());
      return json(res, 200, { target, scan_type: 'traceroute', hops, hop_count: hops.length, timestamp: new Date().toISOString() });
    }

    if (url.pathname === '/scan/rdns') {
      if (!validateTarget(target)) return json(res, 400, { error: 'Invalid target' });
      const { stdout } = await execAsync(`nslookup ${target} 2>&1`, { timeout: 10000 });
      return json(res, 200, { target, scan_type: 'reverse_dns', result: stdout.trim(), timestamp: new Date().toISOString() });
    }

    if (url.pathname === '/scan/headers') {
      if (!validateTarget(target)) return json(res, 400, { error: 'Invalid target' });
      const { stdout } = await execAsync(
        `curl -sI -m 10 -L --max-redirs 3 https://${target} 2>&1 || curl -sI -m 10 -L --max-redirs 3 http://${target} 2>&1`,
        { timeout: 15000 }
      );
      const headers = {};
      stdout.split('\n').forEach(line => {
        const idx = line.indexOf(':');
        if (idx > 0) headers[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
      });
      return json(res, 200, { target, scan_type: 'http_headers', headers, raw: stdout.trim(), timestamp: new Date().toISOString() });
    }

    return json(res, 404, { error: 'Unknown endpoint' });
  } catch (e) {
    return json(res, 500, { error: e.message || 'Scan failed' });
  }
});

function parseNmapXML(xml) {
  const ports = [];
  const portRegex = /<port protocol="(\w+)" portid="(\d+)">.*?<state state="(\w+)".*?\/>.*?<service name="([^"]*)"(?:.*?product="([^"]*)")?(?:.*?version="([^"]*)")?/gs;
  let m;
  while ((m = portRegex.exec(xml)) !== null) {
    ports.push({ port: parseInt(m[2]), protocol: m[1], state: m[3], service: m[4], product: m[5] || '', version: m[6] || '' });
  }
  const hostMatch = xml.match(/<address addr="([^"]*)" addrtype="ipv4"/);
  const osMatch = xml.match(/<osmatch name="([^"]*)"/);
  return { ip: hostMatch?.[1] || null, os_guess: osMatch?.[1] || null, ports, open_ports: ports.filter(p => p.state === 'open').length, total_scanned: ports.length };
}

function parseCertOutput(output) {
  const result = {};
  output.split('\n').forEach(l => {
    if (l.startsWith('subject=')) result.subject = l.replace('subject=', '').trim();
    if (l.startsWith('issuer=')) result.issuer = l.replace('issuer=', '').trim();
    if (l.startsWith('notBefore=')) result.not_before = l.replace('notBefore=', '').trim();
    if (l.startsWith('notAfter=')) result.not_after = l.replace('notAfter=', '').trim();
    if (l.includes('Fingerprint=')) result.fingerprint = l.split('=').slice(1).join('=').trim();
  });
  return result;
}

server.listen(PORT, '0.0.0.0', () => {
  console.log('[OSIRIS SCANNER] Running on port ' + PORT);
  console.log('[OSIRIS SCANNER] Endpoints: /scan/ports, /scan/quick, /scan/banner, /scan/ssl, /scan/traceroute, /scan/rdns, /scan/headers');
});
