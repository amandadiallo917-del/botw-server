const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn, execSync } = require('child_process');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const KEYS_DIR = path.join(__dirname, 'keys');
const PUBLIC_DIR = path.join(__dirname, 'public');
const DB_FILE = path.join(DATA_DIR, 'db.json');

// Ensure directories exist
[DATA_DIR, KEYS_DIR, PUBLIC_DIR].forEach((dir) => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// 1. Generate or load RSA-2048 KeyPair (.pem + .der for Android APK assets)
const PRIV_KEY_PATH = path.join(KEYS_DIR, 'private.pem');
const PUB_KEY_PATH = path.join(KEYS_DIR, 'public.pem');
const DER_KEY_PATH = path.join(KEYS_DIR, 'srsaicos_update_public_key.der');

function ensureCryptoKeys() {
  if (!fs.existsSync(PRIV_KEY_PATH) || !fs.existsSync(DER_KEY_PATH)) {
    console.log('[CRYPTO] Generando par de claves RSA-2048 y archivo .der para el APK...');
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });

    const publicDer = crypto.createPublicKey(publicKey).export({
      type: 'spki',
      format: 'der'
    });

    fs.writeFileSync(PRIV_KEY_PATH, privateKey, 'utf8');
    fs.writeFileSync(PUB_KEY_PATH, publicKey, 'utf8');
    fs.writeFileSync(DER_KEY_PATH, publicDer);
    console.log('[CRYPTO] Clave publica .der generada en:', DER_KEY_PATH);
  }
}

ensureCryptoKeys();
const PRIVATE_KEY_PEM = fs.readFileSync(PRIV_KEY_PATH, 'utf8');
const PUBLIC_KEY_DER = fs.readFileSync(DER_KEY_PATH);

// Helper to get LAN IPv4 addresses (e.g., 192.168.100.210)
function getLanUrls(port) {
  const urls = [];
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name] || []) {
      if (iface.family === 'IPv4' && !iface.internal && !iface.address.startsWith('169.254.')) {
        urls.push(`http://${iface.address}:${port}`);
      }
    }
  }
  return urls;
}

let publicTunnelUrl = null;
let activeSshProc = null;

function startPublicTunnel(port) {
  try {
    const sshProc = spawn(
      'ssh',
      [
        '-T',
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'ServerAliveInterval=30',
        '-R', `80:127.0.0.1:${port}`,
        'nokey@localhost.run'
      ],
      { stdio: ['pipe', 'pipe', 'pipe'] }
    );
    activeSshProc = sshProc;

    sshProc.stdout.on('data', (chunk) => {
      const text = chunk.toString();
      const match = text.match(/https:\/\/[a-zA-Z0-9.-]+\.lhr\.life/);
      if (match && match[0] !== publicTunnelUrl) {
        publicTunnelUrl = match[0];
        console.log('==============================================================');
        console.log(` [TUNEL INTERNET ACTIVO] URL Publica para la App Android:`);
        console.log(` >>> ${publicTunnelUrl} <<<`);
        console.log(' (Funciona con Datos Moviles 4G/5G y Wi-Fi sin bloqueo de Firewall)');
        console.log('==============================================================');
      }
    });

    sshProc.on('error', () => {});
    sshProc.on('exit', () => {
      publicTunnelUrl = null;
      setTimeout(() => startPublicTunnel(port), 3000);
    });
  } catch (_) {}
}

// 2. Database Initialization & Helpers
function loadDb() {
  if (!fs.existsSync(DB_FILE)) {
    const now = Date.now();
    const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;
    const initialDb = {
      admin: {
        username: 'admin',
        passwordHash: hashPassword('admin123'),
        tokenSecret: crypto.randomBytes(32).toString('hex')
      },
      branding: {
        schema: 1,
        distribution_id: 'bd_' + crypto.randomBytes(18).toString('base64url'),
        app_id: 'botw5.189.0',
        flow_key: 'srsaicos',
        validator_profile_key: 'srsaicos',
        security_ui: 'classic'
      },
      billingConfig: {
        whatsappNumber: '18092355519',
        bankAccounts: 'Banreservas: 9608414920 | Banco Popular: 821386158',
        currency: 'RD$',
        plans: [
          { id: 'plan_7d', name: 'Plan Semanal', days: 7, price: 500 },
          { id: 'plan_15d', name: 'Plan Quincenal', days: 15, price: 900 },
          { id: 'plan_30d', name: 'Plan Mensual VIP', days: 30, price: 1500 }
        ]
      },
      rechargePins: [
        {
          id: 'pin_demo_7d',
          code: 'PIN-7D-DEMO-2026',
          days: 7,
          status: 'unused',
          notes: 'PIN de prueba de 7 dias',
          createdAt: new Date(now).toISOString(),
          usedAt: null,
          usedByHwid: null,
          usedByUser: null
        }
      ],
      licenses: [],
      securityEvents: []
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(initialDb, null, 2), 'utf8');
    return initialDb;
  }
  const existingDb = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  let migrated = false;
  if (!existingDb.billingConfig) {
    existingDb.billingConfig = {
      whatsappNumber: '18092355519',
      bankAccounts: 'Banreservas: 9608414920 | Banco Popular: 821386158',
      currency: 'RD$',
      plans: [
        { id: 'plan_7d', name: 'Plan Semanal', days: 7, price: 500 },
        { id: 'plan_15d', name: 'Plan Quincenal', days: 15, price: 900 },
        { id: 'plan_30d', name: 'Plan Mensual VIP', days: 30, price: 1500 }
      ]
    };
    migrated = true;
  }
  if (!Array.isArray(existingDb.rechargePins)) {
    existingDb.rechargePins = [
      {
        id: 'pin_demo_7d',
        code: 'PIN-7D-DEMO-2026',
        days: 7,
        status: 'unused',
        notes: 'PIN de prueba de 7 dias',
        createdAt: new Date().toISOString(),
        usedAt: null,
        usedByHwid: null,
        usedByUser: null
      }
    ];
    migrated = true;
  }
  if (migrated) {
    fs.writeFileSync(DB_FILE, JSON.stringify(existingDb, null, 2), 'utf8');
  }
  return existingDb;
}

function saveDb(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf8');
}

function hashPassword(plain) {
  return crypto.createHash('sha256').update(String(plain) + '_srsaicos_salt').digest('hex');
}

function signPayloadRSA(payloadObj) {
  const payloadJson = JSON.stringify(payloadObj);
  const payloadBase64 = Buffer.from(payloadJson, 'utf8').toString('base64');
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(payloadBase64);
  signer.end();
  const signatureBase64 = signer.sign(PRIVATE_KEY_PEM, 'base64');
  return {
    payload: payloadBase64,
    signature: signatureBase64,
    data: payloadObj
  };
}

function createAdminToken(db) {
  const hmac = crypto.createHmac('sha256', db.admin.tokenSecret);
  hmac.update(db.admin.username + ':' + db.admin.passwordHash);
  return hmac.digest('hex');
}

function isAdminAuthenticated(req, db) {
  const authHeader = req.headers['authorization'] || '';
  if (authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7).trim();
    return token === createAdminToken(db);
  }
  return false;
}

function parseBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk.toString();
      if (body.length > 1e6) req.socket.destroy();
    });
    req.on('end', () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (e) {
        resolve({});
      }
    });
  });
}

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS'
  });
  res.end(JSON.stringify(data, null, 2));
}

// 3. HTTP Server & Router
const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS'
    });
    return res.end();
  }

  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  // Soportar tanto raiz (https://willmyphone.com o https://botw.willmyphone.com) como subcarpeta (https://willmyphone.com/botw)
  const pathname = parsedUrl.pathname.replace(/^\/botw(?=\/|$)/, '') || '/';
  const db = loadDb();

  // Serve Admin Panel UI on / or /admin
  if (req.method === 'GET' && (pathname === '/' || pathname === '/admin')) {
    const htmlPath = path.join(PUBLIC_DIR, 'index.html');
    if (fs.existsSync(htmlPath)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(fs.readFileSync(htmlPath, 'utf8'));
    }
  }

  // Health/ping endpoint for quick app connectivity test
  if (req.method === 'GET' && pathname === '/api/v1/ping') {
    return sendJson(res, 200, {
      ok: true,
      app_id: db.branding.app_id,
      serverTime: new Date().toISOString()
    });
  }

  // Download DER public key for Android APK assets
  if (req.method === 'GET' && pathname === '/api/v1/config/srsaicos_update_public_key.der') {
    res.writeHead(200, {
      'Content-Type': 'application/octet-stream',
      'Content-Disposition': 'attachment; filename="srsaicos_update_public_key.der"'
    });
    return res.end(PUBLIC_KEY_DER);
  }

  // Branding metadata endpoint
  if (req.method === 'GET' && pathname === '/api/v1/config/branding') {
    return sendJson(res, 200, db.branding);
  }

  // =========================================================================
  // ANDROID CLIENT ENDPOINTS (LOGIN, HEARTBEAT, SECURITY TELEMETRY)
  // =========================================================================

  if (req.method === 'POST' && pathname === '/api/v1/auth/login') {
    const body = await parseBody(req);
    const { username, password, licenseKey, hwid, deviceModel } = body;

    console.log(`[LOGIN] Solicitud recibida -> usuario/key: "${username || licenseKey}" | HWID: "${hwid}" | Modelo: "${deviceModel}"`);

    if (!hwid || String(hwid).trim().length < 4) {
      return sendJson(res, 400, {
        ok: false,
        code: 'INVALID_HWID',
        message: 'No se recibio un identificador de dispositivo (HWID) valido.'
      });
    }

    const license = db.licenses.find((lic) => {
      if (licenseKey && lic.licenseKey.toUpperCase() === String(licenseKey).trim().toUpperCase()) {
        return true;
      }
      if (username && lic.licenseKey.toUpperCase() === String(username).trim().toUpperCase()) {
        return true;
      }
      if (username && password) {
        return (
          lic.username.toLowerCase() === String(username).trim().toLowerCase() &&
          lic.passwordHash === hashPassword(password)
        );
      }
      return false;
    });

    if (!license) {
      db.securityEvents.unshift({
        id: 'evt_' + Date.now(),
        type: 'LOGIN_FAILED',
        hwid,
        deviceModel: deviceModel || 'Unknown',
        detail: `Credenciales invalidas (${username || licenseKey || 'vacio'})`,
        timestamp: new Date().toISOString()
      });
      saveDb(db);
      return sendJson(res, 401, {
        ok: false,
        code: 'INVALID_CREDENTIALS',
        message: 'Usuario, contrasena o clave de licencia incorrectos.'
      });
    }

    if (license.status !== 'active') {
      return sendJson(res, 403, {
        ok: false,
        code: 'ACCOUNT_SUSPENDED',
        message: 'Esta licencia ha sido suspendida por el administrador.'
      });
    }

    const now = Date.now();
    const expTime = new Date(license.expiresAt).getTime();
    if (now > expTime) {
      license.status = 'expired';
      saveDb(db);
      return sendJson(res, 403, {
        ok: false,
        code: 'LICENSE_EXPIRED',
        message: `Tu suscripcion vencio el ${new Date(license.expiresAt).toLocaleDateString()}.`
      });
    }

    const normalizedHwid = String(hwid).trim();
    if (!license.hwid) {
      license.hwid = normalizedHwid;
      license.deviceModel = deviceModel || 'Android Device';
    } else if (license.hwid !== normalizedHwid) {
      db.securityEvents.unshift({
        id: 'evt_' + Date.now(),
        type: 'HWID_MISMATCH',
        username: license.username,
        expectedHwid: license.hwid,
        receivedHwid: normalizedHwid,
        deviceModel: deviceModel || 'Unknown',
        detail: `Intento de uso en otro dispositivo (${deviceModel || 'Unknown'})`,
        timestamp: new Date().toISOString()
      });
      saveDb(db);
      return sendJson(res, 403, {
        ok: false,
        code: 'HWID_MISMATCH',
        message: 'Esta licencia ya esta vinculada a otro dispositivo. Solicita un Reset de HWID en el Panel Admin.'
      });
    }

    license.lastLoginAt = new Date(now).toISOString();
    if (deviceModel) license.deviceModel = deviceModel;
    saveDb(db);

    const sessionPayload = {
      ok: true,
      licenseId: license.id,
      username: license.username,
      licenseKey: license.licenseKey,
      hwid: license.hwid,
      expiresAt: license.expiresAt,
      remainingDays: Math.max(0, Math.ceil((expTime - now) / (1000 * 60 * 60 * 24))),
      issuedAt: new Date(now).toISOString(),
      flowKey: db.branding.flow_key,
      config: license.config
    };

    const signed = signPayloadRSA(sessionPayload);
    console.log(`[LOGIN OK] Acceso concedido a "${license.username}" (${license.hwid})`);
    return sendJson(res, 200, {
      ok: true,
      code: 'AUTH_SUCCESS',
      message: 'Licencia verificada correctamente.',
      ...signed
    });
  }

  // Heartbeat check
  if (req.method === 'POST' && pathname === '/api/v1/auth/heartbeat') {
    const body = await parseBody(req);
    const { licenseKey, username, hwid } = body;

    const license = db.licenses.find(
      (lic) =>
        (licenseKey && lic.licenseKey === licenseKey) ||
        (username && lic.username.toLowerCase() === String(username).toLowerCase())
    );

    if (!license || license.status !== 'active') {
      return sendJson(res, 403, {
        ok: false,
        code: 'SESSION_REVOKED',
        message: 'Licencia revocada o inactiva.'
      });
    }

    if (license.hwid && license.hwid !== String(hwid).trim()) {
      return sendJson(res, 403, {
        ok: false,
        code: 'HWID_MISMATCH',
        message: 'Dispositivo no autorizado.'
      });
    }

    if (Date.now() > new Date(license.expiresAt).getTime()) {
      license.status = 'expired';
      saveDb(db);
      return sendJson(res, 403, {
        ok: false,
        code: 'LICENSE_EXPIRED',
        message: 'Suscripcion expirada.'
      });
    }

    license.lastLoginAt = new Date().toISOString();
    saveDb(db);

    const heartbeatPayload = {
      ok: true,
      licenseId: license.id,
      hwid: license.hwid,
      expiresAt: license.expiresAt,
      issuedAt: new Date().toISOString(),
      config: license.config
    };

    return sendJson(res, 200, {
      ok: true,
      ...signPayloadRSA(heartbeatPayload)
    });
  }

  // Public Billing Info & Live Status by HWID (Opción 1 + Opción 2)
  if (req.method === 'GET' && pathname === '/api/v1/billing/info') {
    const hwid = String(parsedUrl.searchParams.get('hwid') || '').trim();
    const licenseKey = String(parsedUrl.searchParams.get('licenseKey') || '').trim();
    const deviceModel = String(parsedUrl.searchParams.get('model') || 'Android Device').trim();
    let lic = db.licenses.find(
      (l) =>
        (hwid && l.hwid === hwid) ||
        (licenseKey && l.licenseKey.toUpperCase() === licenseKey.toUpperCase())
    );

    // Si es un dispositivo nuevo con HWID valido que aun no esta registrado, registrarlo con 0 dias (SIN ACTIVAR)
    // para que aparezca de inmediato en el Panel Admin listo para darle +7d / +15d / +30d
    if (!lic && hwid && hwid.startsWith('AND-')) {
      const shortHwid = hwid.replace(/[^a-zA-Z0-9]/g, '').slice(-6).toUpperCase();
      const now = Date.now();
      lic = {
        id: 'lic_' + crypto.randomBytes(6).toString('hex'),
        username: `chofer_${shortHwid.toLowerCase()}`,
        passwordHash: hashPassword('123456'),
        licenseKey: `BOTW-${shortHwid}`,
        status: 'expired',
        hwid,
        deviceModel,
        expiresAt: new Date(now - 24 * 60 * 60 * 1000).toISOString(),
        createdAt: new Date(now).toISOString(),
        lastLoginAt: new Date(now).toISOString(),
        notes: 'Dispositivo nuevo (0 dias - Pendiente de pago)',
        config: {
          minFare: 15.0,
          maxPickupKm: 3.0,
          maxTripKm: 15.0,
          minPricePerKm: 1.5,
          autoAccept: true,
          clickDelayMs: 350,
          targetPackages: ['sinet.startup.inDriver']
        }
      };
      db.licenses.unshift(lic);
      saveDb(db);
    }

    let licenseStatus = null;
    if (lic) {
      const now = Date.now();
      const expTime = new Date(lic.expiresAt).getTime();
      const remDays = Math.max(0, Math.ceil((expTime - now) / (1000 * 60 * 60 * 24)));
      if (remDays <= 0 && lic.status === 'active') {
        lic.status = 'expired';
        saveDb(db);
      }
      licenseStatus = {
        username: lic.username,
        licenseKey: lic.licenseKey,
        status: lic.status,
        expiresAt: lic.expiresAt,
        remainingDays: lic.status === 'active' ? remDays : 0
      };
    }

    return sendJson(res, 200, {
      ok: true,
      billingConfig: db.billingConfig,
      licenseStatus
    });
  }

  // Redeem Prepaid PIN / Recharge Code (Opción 3)
  if (req.method === 'POST' && pathname === '/api/v1/auth/redeem-pin') {
    const body = await parseBody(req);
    const pinCode = String(body.pinCode || '').trim().toUpperCase();
    const hwid = String(body.hwid || '').trim();
    const deviceModel = String(body.deviceModel || 'Android Device').trim();
    const usernameHint = String(body.username || '').trim();

    if (!pinCode) {
      return sendJson(res, 400, {
        ok: false,
        code: 'PIN_EMPTY',
        message: 'Ingresa un codigo PIN de recarga valido.'
      });
    }

    if (!hwid || hwid.length < 4) {
      return sendJson(res, 400, {
        ok: false,
        code: 'INVALID_HWID',
        message: 'No se detecto un HWID de dispositivo valido.'
      });
    }

    const pinObj = (db.rechargePins || []).find(
      (p) => p.code.toUpperCase() === pinCode
    );

    if (!pinObj) {
      return sendJson(res, 404, {
        ok: false,
        code: 'PIN_NOT_FOUND',
        message: 'El codigo PIN ingresado no existe. Verifica que este bien escrito.'
      });
    }

    if (pinObj.status !== 'unused') {
      return sendJson(res, 409, {
        ok: false,
        code: 'PIN_ALREADY_USED',
        message: `Este PIN ya fue canjeado anteriormente (${pinObj.usedAt ? new Date(pinObj.usedAt).toLocaleDateString() : 'usado'}).`
      });
    }

    const now = Date.now();
    const addMs = (Number(pinObj.days) || 7) * 24 * 60 * 60 * 1000;

    // Buscar licencia por HWID primero, luego por username/key si no tiene otro HWID
    let license = db.licenses.find((l) => l.hwid === hwid);
    if (!license && usernameHint) {
      license = db.licenses.find(
        (l) =>
          (!l.hwid || l.hwid === hwid) &&
          (l.username.toLowerCase() === usernameHint.toLowerCase() ||
            l.licenseKey.toUpperCase() === usernameHint.toUpperCase())
      );
    }

    if (!license) {
      const shortHwid = hwid.replace(/[^a-zA-Z0-9]/g, '').slice(-6).toUpperCase();
      const autoUser = `chofer_${shortHwid.toLowerCase()}`;
      const autoKey = `BOTW-${shortHwid}-${new Date().getFullYear()}`;
      license = {
        id: 'lic_' + crypto.randomBytes(6).toString('hex'),
        username: autoUser,
        passwordHash: hashPassword('123456'),
        licenseKey: autoKey,
        status: 'active',
        hwid,
        deviceModel,
        expiresAt: new Date(now + addMs).toISOString(),
        createdAt: new Date(now).toISOString(),
        lastLoginAt: new Date(now).toISOString(),
        notes: `Activado con PIN ${pinObj.code} (+${pinObj.days}d)`,
        config: {
          minFare: 15.0,
          maxPickupKm: 3.0,
          maxTripKm: 15.0,
          minPricePerKm: 1.5,
          autoAccept: true,
          clickDelayMs: 350,
          targetPackages: ['sinet.startup.inDriver']
        }
      };
      db.licenses.unshift(license);
    } else {
      const currentExp = new Date(license.expiresAt).getTime();
      const baseTime = Math.max(now, isNaN(currentExp) ? now : currentExp);
      license.expiresAt = new Date(baseTime + addMs).toISOString();
      license.status = 'active';
      license.hwid = hwid;
      license.deviceModel = deviceModel;
      license.lastLoginAt = new Date(now).toISOString();
      license.notes = `${license.notes ? license.notes + ' | ' : ''}Recarga ${pinObj.code} (+${pinObj.days}d)`;
    }

    pinObj.status = 'used';
    pinObj.usedAt = new Date(now).toISOString();
    pinObj.usedByHwid = hwid;
    pinObj.usedByUser = license.username;

    saveDb(db);

    const newExpTime = new Date(license.expiresAt).getTime();
    const remDays = Math.max(0, Math.ceil((newExpTime - now) / (1000 * 60 * 60 * 24)));

    const sessionPayload = {
      ok: true,
      licenseId: license.id,
      username: license.username,
      licenseKey: license.licenseKey,
      hwid: license.hwid,
      expiresAt: license.expiresAt,
      remainingDays: remDays,
      addedDays: pinObj.days,
      issuedAt: new Date(now).toISOString(),
      flowKey: db.branding.flow_key,
      config: license.config
    };

    const signed = signPayloadRSA(sessionPayload);
    console.log(`[PIN CANJEADO] ${pinObj.code} (+${pinObj.days}d) -> "${license.username}" (${hwid})`);
    return sendJson(res, 200, {
      ok: true,
      code: 'PIN_REDEEM_SUCCESS',
      message: `¡PIN canjeado con exito! Se sumaron +${pinObj.days} dias. Total activo: ${remDays} dias.`,
      ...signed
    });
  }

  // Security Telemetry Endpoint
  if (req.method === 'POST' && pathname === '/api/v1/security/event') {
    const body = await parseBody(req);
    db.securityEvents.unshift({
      id: 'evt_' + Date.now(),
      type: body.type || 'CLIENT_SECURITY_ALERT',
      hwid: body.hwid || 'unknown',
      deviceModel: body.deviceModel || 'unknown',
      detail: body.detail || JSON.stringify(body),
      timestamp: new Date().toISOString()
    });
    if (db.securityEvents.length > 200) db.securityEvents.length = 200;
    saveDb(db);
    return sendJson(res, 200, { ok: true });
  }

  // =========================================================================
  // ADMIN PANEL API ENDPOINTS
  // =========================================================================

  if (req.method === 'POST' && pathname === '/api/v1/admin/login') {
    const body = await parseBody(req);
    const { username, password } = body;
    if (
      username === db.admin.username &&
      hashPassword(password) === db.admin.passwordHash
    ) {
      return sendJson(res, 200, {
        ok: true,
        token: createAdminToken(db),
        username: db.admin.username
      });
    }
    return sendJson(res, 401, { ok: false, message: 'Credenciales de administrador invalidas.' });
  }

  if (pathname.startsWith('/api/v1/admin/')) {
    if (!isAdminAuthenticated(req, db)) {
      return sendJson(res, 401, { ok: false, message: 'No autorizado.' });
    }

    if (req.method === 'GET' && pathname === '/api/v1/admin/overview') {
      return sendJson(res, 200, {
        ok: true,
        branding: db.branding,
        billingConfig: db.billingConfig,
        rechargePins: db.rechargePins || [],
        connectionUrls: {
          lanUrls: getLanUrls(PORT),
          publicTunnelUrl: publicTunnelUrl || 'https://botw-server.onrender.com  (y  https://botw.willmyphone.com)',
          emulatorUrl: `http://10.0.2.2:${PORT}`
        },
        licenses: db.licenses.map(({ passwordHash, ...rest }) => rest),
        securityEvents: db.securityEvents.slice(0, 50)
      });
    }

    if (req.method === 'POST' && pathname === '/api/v1/admin/billing-config') {
      const body = await parseBody(req);
      db.billingConfig = {
        whatsappNumber:
          body.whatsappNumber !== undefined
            ? String(body.whatsappNumber).replace(/[^0-9]/g, '')
            : db.billingConfig.whatsappNumber,
        bankAccounts:
          body.bankAccounts !== undefined
            ? String(body.bankAccounts).trim()
            : db.billingConfig.bankAccounts,
        currency: String(body.currency || 'RD$').trim(),
        plans: [
          {
            id: 'plan_7d',
            name: 'Plan Semanal',
            days: 7,
            price: Number(body.price7d) || 500
          },
          {
            id: 'plan_15d',
            name: 'Plan Quincenal',
            days: 15,
            price: Number(body.price15d) || 900
          },
          {
            id: 'plan_30d',
            name: 'Plan Mensual VIP',
            days: 30,
            price: Number(body.price30d) || 1500
          }
        ]
      };
      saveDb(db);
      return sendJson(res, 200, { ok: true, billingConfig: db.billingConfig });
    }

    if (req.method === 'POST' && pathname === '/api/v1/admin/pins/generate') {
      const body = await parseBody(req);
      const days = Math.max(1, Number(body.days) || 7);
      const count = Math.min(50, Math.max(1, Number(body.count) || 1));
      const notes = String(body.notes || `Lote ${days}d`).trim();
      const createdPins = [];

      if (!Array.isArray(db.rechargePins)) db.rechargePins = [];

      for (let i = 0; i < count; i++) {
        const randA = crypto.randomBytes(2).toString('hex').toUpperCase();
        const randB = crypto.randomBytes(2).toString('hex').toUpperCase();
        const pinObj = {
          id: 'pin_' + crypto.randomBytes(6).toString('hex'),
          code: `PIN-${days}D-${randA}-${randB}`,
          days,
          status: 'unused',
          notes,
          createdAt: new Date().toISOString(),
          usedAt: null,
          usedByHwid: null,
          usedByUser: null
        };
        db.rechargePins.unshift(pinObj);
        createdPins.push(pinObj);
      }

      saveDb(db);
      return sendJson(res, 201, { ok: true, createdPins });
    }

    if (req.method === 'POST' && pathname === '/api/v1/admin/pins/delete') {
      const body = await parseBody(req);
      const { id } = body;
      if (Array.isArray(db.rechargePins)) {
        db.rechargePins = db.rechargePins.filter((p) => p.id !== id);
        saveDb(db);
      }
      return sendJson(res, 200, { ok: true });
    }

    if (req.method === 'POST' && pathname === '/api/v1/admin/licenses') {
      const body = await parseBody(req);
      const username = String(body.username || '').trim();
      const password = String(body.password || '123456').trim();
      const days = Number(body.days) || 30;
      const customKey = String(body.licenseKey || '').trim().toUpperCase();
      const licenseKey =
        customKey ||
        'BOTW-' + crypto.randomBytes(3).toString('hex').toUpperCase() + '-' + new Date().getFullYear();

      if (!username) {
        return sendJson(res, 400, { ok: false, message: 'El nombre de usuario es obligatorio.' });
      }

      if (db.licenses.some((l) => l.username.toLowerCase() === username.toLowerCase())) {
        return sendJson(res, 400, { ok: false, message: 'Ese nombre de usuario ya existe.' });
      }

      const now = Date.now();
      const newLic = {
        id: 'lic_' + crypto.randomBytes(6).toString('hex'),
        username,
        passwordHash: hashPassword(password),
        licenseKey,
        status: 'active',
        hwid: null,
        deviceModel: null,
        expiresAt: new Date(now + days * 24 * 60 * 60 * 1000).toISOString(),
        createdAt: new Date(now).toISOString(),
        lastLoginAt: null,
        notes: body.notes || `Creada por ${days} dias`,
        config: {
          minFare: Number(body.minFare) || 15.0,
          maxPickupKm: Number(body.maxPickupKm) || 3.0,
          maxTripKm: Number(body.maxTripKm) || 15.0,
          minPricePerKm: Number(body.minPricePerKm) || 1.5,
          autoAccept: body.autoAccept !== false,
          clickDelayMs: Number(body.clickDelayMs) || 350,
          targetPackages: ['sinet.startup.inDriver']
        }
      };

      db.licenses.unshift(newLic);
      saveDb(db);
      const { passwordHash, ...safeLic } = newLic;
      return sendJson(res, 201, { ok: true, license: safeLic });
    }

    if (req.method === 'POST' && pathname === '/api/v1/admin/licenses/action') {
      const body = await parseBody(req);
      const { id, action, days, password, config } = body;
      const idx = db.licenses.findIndex((l) => l.id === id);
      if (idx === -1) {
        return sendJson(res, 404, { ok: false, message: 'Licencia no encontrada.' });
      }

      const lic = db.licenses[idx];
      if (action === 'reset-hwid') {
        lic.hwid = null;
        lic.deviceModel = null;
      } else if (action === 'toggle-status') {
        lic.status = lic.status === 'active' ? 'suspended' : 'active';
      } else if (action === 'add-days') {
        const extraMs = (Number(days) || 30) * 24 * 60 * 60 * 1000;
        const baseTime = Math.max(Date.now(), new Date(lic.expiresAt).getTime());
        lic.expiresAt = new Date(baseTime + extraMs).toISOString();
        if (lic.status === 'expired' || lic.status === 'suspended') lic.status = 'active';
      } else if (action === 'expire-now') {
        lic.expiresAt = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        lic.status = 'expired';
      } else if (action === 'change-password' && password) {
        lic.passwordHash = hashPassword(password);
      } else if (action === 'update-config' && config) {
        lic.config = { ...lic.config, ...config };
      } else if (action === 'delete') {
        db.licenses.splice(idx, 1);
      }

      saveDb(db);
      return sendJson(res, 200, { ok: true });
    }
  }

  sendJson(res, 404, { ok: false, message: 'Ruta no encontrada: ' + pathname });
});

function startServerWithAutoRecovery() {
  // Modo Hosting Namecheap cPanel (Linux / Phusion Passenger)
  if (process.platform !== 'win32') {
    server.listen(PORT, () => {
      console.log(`[BOTW NAMECHEAP] Servidor activo en willmyphone.com (Puerto/Socket: ${PORT})`);
    });
    return;
  }

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.log(`[AVISO] El puerto ${PORT} estaba ocupado por una instancia anterior. Liberando puerto automaticamente...`);
      try {
        if (process.platform === 'win32') {
          execSync(
            `powershell -NoProfile -Command "$c = Get-NetTCPConnection -LocalPort ${PORT} -State Listen -ErrorAction SilentlyContinue; if ($c) { Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue }"`
          );
        }
      } catch (_) {}
      setTimeout(() => {
        server.close();
        server.listen(PORT, '0.0.0.0');
      }, 600);
    } else {
      console.error('[ERROR SERVIDOR]:', err);
    }
  });

  server.listen(PORT, '0.0.0.0', () => {
    const lanUrls = getLanUrls(PORT);
    console.log('==============================================================');
    console.log(` BOTW - Servidor de Login y Licencias ACTIVO`);
    console.log(` Dominio Oficial Namecheap:  https://willmyphone.com/botw`);
    console.log(` Panel Admin en tu PC:       http://localhost:${PORT}/admin`);
    if (lanUrls.length > 0) {
      console.log(` URL para Telefono (Wi-Fi):  ${lanUrls.join('  o  ')}`);
    }
    console.log(` URL para Emulador Android:  http://10.0.2.2:${PORT}`);
    console.log('==============================================================');
    startPublicTunnel(PORT);
  });
}

if (require.main === module || process.platform !== 'win32') {
  startServerWithAutoRecovery();
}

module.exports = { server, ensureCryptoKeys, DER_KEY_PATH };
