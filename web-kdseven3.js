// web-kdseven.js
// Servidor WEB para o sistema KDSEVEN usando a mesma estrutura do BOT do Whats.
// Agora com login via TOKEN, controle de IP e painel protegido.

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const chalk = require('chalk');
const fs = require('fs');
const path = require('path');
const CryptoJS = require('crypto-js');
const dns = require('dns').promises;
const dnsModule = require('dns');
const EfiPay = require('sdk-node-apis-efi');
const Database = require('better-sqlite3');
const crypto = require('crypto');

// DNS confiável (igual ao bot)
dnsModule.setServers(['1.1.1.1', '1.0.0.1']);

// ================== VARIÁVEIS DE AMBIENTE ==================
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const EFI_PIX_KEY = process.env.EFI_PIX_KEY;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

if (!CLIENT_ID || !CLIENT_SECRET || !EFI_PIX_KEY || !ENCRYPTION_KEY) {
    console.error(chalk.red('❌ ERRO CRÍTICO: Faltam variáveis de ambiente no arquivo .env.'));
    process.exit(1);
}

const CERTIFICATE_PATH = path.join(__dirname, 'certificate.p12');
if (!fs.existsSync(CERTIFICATE_PATH)) {
    console.error(chalk.red('❌ Certificado não encontrado:'), CERTIFICATE_PATH);
    process.exit(1);
}

// ================== CONFIG EFI PAY ==================
const efiOptions = {
    sandbox: false,
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    certificate: CERTIFICATE_PATH
};
const efipay = new EfiPay(efiOptions);

// ================== CONFIG GERAL ==================
const NETWORK_CONFIG = {
    API_TIMEOUT: 30000,
    MAX_RETRIES: 3,
    RETRY_DELAY: 2000,
    CHECK_INTERNET: true
};

const pendingPayments = new Map();

const CONFIG = {
    ADMIN_PHONES: ['559292201697'],
    CREDITS_DIR: './IDS',
    DATA_DIR: './data',
    BACKUP_DIR: './backups',
    MAX_RECHARGE_AMOUNT: 10000,
    MONITORING_COST: 10,
    MAX_LINES: {
        NORMAL: 50,
        SIMPLES: 1000,
        INTERMEDIARIO: 4000,
        MASTER: 6000,
        AVANCADO: 20000,
        ADMINISTRATIVA: 0 // 0 = todas as linhas
    },
    ANDROID_MAX_LINES: {
        NORMAL: 80,
        INTERMEDIARIO: 400,
        AVANCADO: 20000
    },
    PLANO_PRECOS: {
        NORMAL: 1,
        SIMPLES: 10,
        INTERMEDIARIO: 30,
        MASTER: 40,
        AVANCADO: 80,
        ADMINISTRATIVA: 250
    },
    ANDROID_PLANO_PRECOS: {
        NORMAL: 1,
        INTERMEDIARIO: 3,
        AVANCADO: 100
    },
    ALUGUEL: {
        DIARIO: { creditos: 50, limite: 2000, dias: 1 },
        '7_DIAS': { creditos: 200, limite: 5000, dias: 7 },
        '15_DIAS': { creditos: 300, limite: 10000, dias: 15 },
        '30_DIAS': { creditos: 400, limite: 20000, dias: 30 }
    },
    ENCRYPTION_KEY: ENCRYPTION_KEY,
    ADMIN_2FA: false,
    MAX_CONCURRENT_SEARCHES: 20
};

const JSON_FILES = {
    AFFILIATE: './afiliados.json',
    GIFT: './giftcards.json',
    GAINS: './ganhos.json',
    TRANSACTIONS: './transacoes.json',
    RESELLERS: './resellers.json',
    USERS: './users.json',
    MONITORED: './monitored.json',
    PROMOTION: './promotion.json',
    RENTALS: './alugueis.json',
    TOKENS: './tokens.json' // novo arquivo de tokens
};

// Cria diretórios e arquivos JSON se não existirem
Object.values(CONFIG).forEach(value => {
    if (typeof value === 'string' && value.includes('/') && !fs.existsSync(value)) {
        fs.mkdirSync(value, { recursive: true });
    }
});
Object.values(JSON_FILES).forEach(file => {
    if (!fs.existsSync(file)) {
        if (file === JSON_FILES.PROMOTION) {
            fs.writeFileSync(file, JSON.stringify({ isActive: false, minValue: 0 }, null, 2));
        } else {
            fs.writeFileSync(file, '{}');
        }
    }
});

// ================== FUNÇÕES AUXILIARES JSON/CRIPTO ==================
function encryptData(data) {
    return CryptoJS.AES.encrypt(JSON.stringify(data), CONFIG.ENCRYPTION_KEY).toString();
}
function decryptData(ciphertext) {
    try {
        const bytes = CryptoJS.AES.decrypt(ciphertext, CONFIG.ENCRYPTION_KEY);
        return JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
    } catch (e) {
        console.error(chalk.red('Erro de descriptografia:'), e);
        return null;
    }
}
function loadJson(file) {
    try {
        const data = fs.readFileSync(file, 'utf-8');
        return file.endsWith('_encrypted.json') ? decryptData(data) : JSON.parse(data);
    } catch (e) {
        console.error(chalk.red(`Erro ao carregar ${file}:`), e);
        return {};
    }
}
function saveJson(file, data) {
    const content = file.endsWith('_encrypted.json')
        ? encryptData(data)
        : JSON.stringify(data, null, 2);
    fs.writeFileSync(file, content);
}

// ================== TOKENS ==================
function getTokens() {
    return loadJson(JSON_FILES.TOKENS);
}
function saveTokens(tokens) {
    saveJson(JSON_FILES.TOKENS, tokens);
}
function generateTokenString() {
    return crypto.randomBytes(24).toString('hex');
}
function findTokenByPhone(phone) {
    const tokens = getTokens();
    for (const [token, data] of Object.entries(tokens)) {
        if (data.phone === phone) {
            return { token, data };
        }
    }
    return null;
}
function ensureTokenForPhone(phone) {
    const existing = findTokenByPhone(phone);
    if (existing) return existing.token;

    const tokens = getTokens();
    let token;
    do {
        token = generateTokenString();
    } while (tokens[token]);

    const now = new Date().toISOString();
    tokens[token] = {
        phone,
        createdAt: now,
        blockedUntil: null,
        activeIp: null,
        lastSeen: null,
        disabled: false
    };
    saveTokens(tokens);
    console.log(chalk.green(`🔑 Novo token gerado para ${phone}: ${token}`));
    return token;
}
function getTokenData(token) {
    const tokens = getTokens();
    return tokens[token] || null;
}
function updateTokenData(token, updates) {
    const tokens = getTokens();
    if (!tokens[token]) return null;
    tokens[token] = { ...tokens[token], ...updates };
    saveTokens(tokens);
    return tokens[token];
}
function getClientIp(req) {
    const fwd = req.headers['x-forwarded-for'];
    if (fwd) return fwd.split(',')[0].trim();
    return req.ip || req.connection.remoteAddress || '';
}

// Middleware de autenticação por token + controle de IP
function authTokenMiddleware(req, res, next) {
    const token = req.headers['x-auth-token'] || req.body.token || req.query.token;
    if (!token) {
        return res.status(401).json({ ok: false, error: 'Token de acesso obrigatório.' });
    }
    const data = getTokenData(token);
    if (!data) {
        return res.status(401).json({ ok: false, error: 'Token inválido.' });
    }

    if (data.disabled) {
        return res.status(401).json({ ok: false, error: 'Token expirado. Gere um novo token.' });
    }

    const now = Date.now();
    if (data.blockedUntil && now < new Date(data.blockedUntil).getTime()) {
        const seconds = Math.ceil((new Date(data.blockedUntil).getTime() - now) / 1000);
        return res.status(403).json({
            ok: false,
            error: `Token bloqueado por uso simultâneo. Aguarde ${seconds}s.`,
            blockedUntil: data.blockedUntil
        });
    }

    const ip = getClientIp(req);
    const lastSeenTime = data.lastSeen ? new Date(data.lastSeen).getTime() : 0;
    const SIMULTANEOUS_WINDOW_MS = 60 * 1000; // 1 minuto: se 2 IPs mexerem no token nesse intervalo, bloqueia

    if (
        data.activeIp &&
        data.activeIp !== ip &&
        lastSeenTime &&
        (now - lastSeenTime) < SIMULTANEOUS_WINDOW_MS
    ) {
        const blockedUntil = new Date(now + 60 * 1000).toISOString();
        updateTokenData(token, {
            blockedUntil,
            activeIp: null,
            lastSeen: null
        });
        console.log(chalk.red(`⛔ Token ${token} bloqueado por uso simultâneo (IPs: ${data.activeIp} e ${ip}).`));
        return res.status(403).json({
            ok: false,
            error: 'Token bloqueado por uso simultâneo (2 IPs). Aguarde 60s.',
            blockedUntil
        });
    }

    updateTokenData(token, {
        activeIp: ip,
        lastSeen: new Date(now).toISOString()
    });

    req.authToken = token;
    req.phone = data.phone;
    next();
}

// ================== RENTALS (ALUGUEL) ==================
function getRentals() { return loadJson(JSON_FILES.RENTALS); }
function saveRentals(data) { saveJson(JSON_FILES.RENTALS, data); }

function activateRental(phone, plan) {
    const rentals = getRentals();
    const rentalConfig = CONFIG.ALUGUEL[plan];
    const now = new Date();
    const expires = new Date(now.getTime() + rentalConfig.dias * 24 * 60 * 60 * 1000);

    rentals[phone] = {
        plan,
        expires: expires.toISOString(),
        dailyLimit: rentalConfig.limite,
        usedToday: 0,
        lastReset: now.toISOString(),
        activatedAt: now.toISOString()
    };

    saveRentals(rentals);
    return rentals[phone];
}

function checkRental(phone) {
    const rentals = getRentals();
    const rental = rentals[phone];
    if (!rental) return null;

    const now = new Date();
    const lastReset = new Date(rental.lastReset);
    const expires = new Date(rental.expires);

    if (now > expires) {
        // Ao expirar o aluguel diário, desativa o token vinculado a esse phone
        const tokenInfo = findTokenByPhone(phone);
        if (tokenInfo) {
            updateTokenData(tokenInfo.token, { disabled: true });
            console.log(chalk.yellow(`🔒 Token ${tokenInfo.token} desativado pois aluguel de ${phone} expirou.`));
        }
        delete rentals[phone];
        saveRentals(rentals);
        return null;
    }

    if (now.toDateString() !== lastReset.toDateString()) {
        rental.usedToday = 0;
        rental.lastReset = now.toISOString();
        saveRentals(rentals);
    }

    return rental;
}

function getRentalUsage(phone) {
    const rental = checkRental(phone);
    if (!rental) return null;

    return {
        plan: rental.plan,
        usedToday: rental.usedToday,
        dailyLimit: rental.dailyLimit,
        expires: new Date(rental.expires),
        remaining: rental.dailyLimit - rental.usedToday
    };
}

function incrementRentalUsage(phone) {
    const rentals = getRentals();
    if (rentals[phone]) {
        rentals[phone].usedToday += 1;
        saveRentals(rentals);
        return rentals[phone].usedToday;
    }
    return 0;
}

// ================== DB POOL ==================
class DatabasePool {
    constructor() {
        this.pool = new Map();
        this.activeConnections = 0;
        this.corruptedDbs = new Set();
    }

    getDatabase(dbNameOrLetter) {
        const dbName = /^[a-zA-Z]$/.test(dbNameOrLetter) ? `${dbNameOrLetter}.db` : dbNameOrLetter;
        const dbPath = path.join(CONFIG.DATA_DIR, dbName);
        if (this.corruptedDbs.has(dbPath)) {
            console.log(chalk.yellow(`⚠️ Banco marcado como corrompido: ${path.basename(dbPath)}`));
            return null;
        }
        if (!fs.existsSync(dbPath)) {
            return null;
        }
        if (!this.pool.has(dbPath)) {
            try {
                const db = new Database(dbPath, { readonly: false });
                db.pragma('journal_mode = WAL');
                db.pragma('synchronous = NORMAL');
                db.exec(`
                    CREATE TABLE IF NOT EXISTS data (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        line TEXT UNIQUE NOT NULL,
                        sold INTEGER DEFAULT 0
                    );
                    CREATE INDEX IF NOT EXISTS idx_sold ON data (sold);
                `);
                this.pool.set(dbPath, db);
                db._dbPath = dbPath;
                console.log(chalk.green(`✅ Conectado ao banco: ${path.basename(dbPath)}`));
            } catch (error) {
                console.error(chalk.red(`❌ Erro ao conectar ao banco ${path.basename(dbPath)}:`), error);
                return null;
            }
        }
        return this.pool.get(dbPath);
    }

    getAllDbFiles() {
        if (!fs.existsSync(CONFIG.DATA_DIR)) return [];
        return fs.readdirSync(CONFIG.DATA_DIR).filter(f => f.endsWith('.db'));
    }

    incrementConnection() {
        this.activeConnections++;
    }

    decrementConnection() {
        this.activeConnections--;
    }

    canAcceptNewConnection() {
        return this.activeConnections < CONFIG.MAX_CONCURRENT_SEARCHES;
    }
}
const dbPool = new DatabasePool();

// ================== FUNÇÕES DE USUÁRIO/CRÉDITO ==================
function initializeCredits(phone) {
    const userFile = path.join(CONFIG.CREDITS_DIR, `${phone}.txt`);
    if (!fs.existsSync(userFile)) {
        fs.writeFileSync(userFile, '0');
        return 0;
    }
    return parseInt(fs.readFileSync(userFile, 'utf-8').trim()) || 0;
}
function updateCredits(phone, amount) {
    const userFile = path.join(CONFIG.CREDITS_DIR, `${phone}.txt`);
    const currentCredits = initializeCredits(phone);
    const newCredits = Math.max(0, currentCredits + amount);
    fs.writeFileSync(userFile, newCredits.toString());
    return newCredits;
}
function isAdmin(phone) {
    return CONFIG.ADMIN_PHONES.includes(phone);
}

// ================== BUSCA / LIMPEZA RESULTADOS ==================
function cleanAndDeduplicateResults(lines) {
    const filteredLines = lines.filter(line => !/unknown/i.test(line));
    const uniqueLines = [...new Set(filteredLines)];
    return uniqueLines;
}

function hasFTSMigration(db) {
    try {
        const result = db.prepare(
            "SELECT count(*) as count FROM sqlite_master WHERE type='table' AND name='data_fts'"
        ).get();
        return result.count > 0;
    } catch (error) {
        console.error(chalk.red('Erro ao verificar FTS5:'), error);
        return false;
    }
}

// ================== INTERNET / PIX ==================
async function checkInternetConnection() {
    try {
        await Promise.any([
            dns.resolve('api-pix.gerencianet.com.br'),
            dns.resolve('api-pix.efi.com.br')
        ]);
        return true;
    } catch (error) {
        console.error(chalk.red('Aviso: Erro na verificação de DNS:'), error);
        return false;
    }
}

async function apiCallWithRetry(apiFunction, params, retries = NETWORK_CONFIG.MAX_RETRIES, delay = NETWORK_CONFIG.RETRY_DELAY) {
    for (let i = 0; i < retries; i++) {
        try {
            const result = await Promise.race([
                apiFunction(params),
                new Promise((_, reject) =>
                    setTimeout(() => reject(new Error('Timeout da API')), NETWORK_CONFIG.API_TIMEOUT)
                )
            ]);
            return result;
        } catch (error) {
            if (error instanceof TypeError && error.message.includes("Cannot read properties of undefined")) {
                console.warn(chalk.yellow(`⚠️ Erro de SDK da Efí detectado (provavelmente PIX não encontrado/expirado).`));
                throw new Error('PIX_NOT_FOUND');
            }
            const isLastAttempt = i === retries - 1;
            const statusCode = error.response?.status;
            const nonRetryableError = statusCode && statusCode >= 400 && statusCode < 500;
            if (nonRetryableError) {
                console.error(chalk.red(`❌ Erro de cliente na API (${statusCode})`));
                throw error;
            }
            if (isLastAttempt) {
                console.error(chalk.red(`❌ Falha na chamada da API após ${retries} tentativas:`), error.message);
                throw error;
            }
            console.warn(chalk.yellow(`⚠️ Erro na API (tentativa ${i + 1}/${retries}), retry em ${delay / 1000}s...`));
            await new Promise(resolve => setTimeout(resolve, delay));
            delay *= 2;
        }
    }
}

function generateTxid(phone) {
    const digits = String(phone || '').replace(/\D/g, '').slice(-6);
    const base = `KDS${Date.now()}${digits}`;
    const needed = 26 - base.length;
    if (needed > 0) {
        const randomChars = crypto.randomBytes(Math.ceil(needed / 2)).toString('hex').toUpperCase();
        return (base + randomChars).slice(0, 35);
    }
    return base.slice(0, 35);
}

async function createPixPayment(phone, amount) {
    try {
        if (NETWORK_CONFIG.CHECK_INTERNET) {
            if (!await checkInternetConnection()) {
                console.warn(chalk.yellow('⚠️ Aviso: Verificação de internet falhou. Tentando prosseguir...'));
            }
        }
        const txid = generateTxid(phone);
        const body = {
            calendario: { expiracao: 3600 },
            valor: { original: amount.toFixed(2) },
            chave: EFI_PIX_KEY,
            solicitacaoPagador: `Recarga de ${amount} créditos - ${phone}`
        };
        console.log(chalk.blue(`⏳ Gerando cobrança PIX para ${phone} no valor de R$${amount.toFixed(2)}...`));
        const charge = await apiCallWithRetry(
            (params) => efipay.pixCreateCharge(params, body),
            { txid }
        );
        const locId = charge.loc?.id;
        if (!locId) {
            throw new Error('Loc ID não encontrado.');
        }
        const qrcode = await apiCallWithRetry(
            (params) => efipay.pixGenerateQRCode(params),
            { id: locId }
        );
        console.log(chalk.green(`✅ Cobrança PIX com TXID ${txid} gerada com sucesso!`));
        return {
            txid,
            calendario: charge.calendario,
            qrcode: qrcode.qrcode,
            imagemQrcode: qrcode.imagemQrcode
        };
    } catch (error) {
        console.error(chalk.red(`❌ Falha final ao criar PIX para ${phone}.`), error.message);
        return null;
    }
}

async function checkPixPayment(txid) {
    try {
        const details = await apiCallWithRetry(
            (params) => efipay.pixDetailCharge(params),
            { txid }
        );
        return details;
    } catch (error) {
        if (error.message === 'PIX_NOT_FOUND') {
            return { status: 'REMOVIDA_PELO_PSP' };
        }
        console.error(chalk.red(`❌ Falha ao verificar PIX com TXID ${txid}.`), error.message);
        return null;
    }
}

// ================== LÓGICA DE BUSCA (ADAPTADA PARA WEB) ==================
async function searchAndSaveHTTP({ phone, keyword, plano, searchType = 'NORMAL', format = 'full', isRental = false }) {
    const startTime = Date.now();

    // Verificar aluguel existente / ativar aluguel diário (50 créditos) se marcado
    let rental = checkRental(phone);
    let usandoAluguel = false;

    if (isRental) {
        if (!rental) {
            const rentalConfig = CONFIG.ALUGUEL.DIARIO;
            const custoAluguel = rentalConfig.creditos || 50;
            const creditsAtual = initializeCredits(phone);

            if (creditsAtual < custoAluguel) {
                return {
                    ok: false,
                    error: `Saldo insuficiente! Você precisa de ${custoAluguel} créditos para ativar o aluguel diário.`,
                    credits: creditsAtual
                };
            }

            const creditsDepois = updateCredits(phone, -custoAluguel);
            rental = activateRental(phone, 'DIARIO');
            console.log(chalk.blue(`🎫 Aluguel diário ativado para ${phone}. Custo: ${custoAluguel}. Saldo: ${creditsDepois}`));
        }
        usandoAluguel = !!rental;
    } else if (rental) {
        // Se já tem aluguel diário ativo, usa ele automaticamente
        usandoAluguel = true;
    }

    if (usandoAluguel && rental) {
        if (rental.usedToday >= rental.dailyLimit) {
            return {
                ok: false,
                error: `Você atingiu o limite de buscas diárias do seu aluguel (${rental.dailyLimit}).`
            };
        }
    }

    let limite, custo;

    if (searchType === 'ANDROID') {
        custo = usandoAluguel ? 0 : CONFIG.ANDROID_PLANO_PRECOS[plano.toUpperCase()];
        limite = CONFIG.ANDROID_MAX_LINES[plano.toUpperCase()];
    } else {
        custo = usandoAluguel ? 0 : CONFIG.PLANO_PRECOS[plano.toUpperCase()];
        limite = CONFIG.MAX_LINES[plano.toUpperCase()];

        if (plano.toUpperCase() === 'ADMINISTRATIVA') {
            limite = Infinity;
        }

        if (usandoAluguel && searchType !== 'ANDROID' && plano.toUpperCase() !== 'ADMINISTRATIVA') {
            limite = 200;
            console.log(chalk.blue(`📦 Limite de aluguel aplicado: ${limite} linhas para ${phone}`));
        }
    }

    const ftsKeyword = keyword.toLowerCase().trim();
    let dbIdentifier = searchType === 'ANDROID' ? 'a' : (ftsKeyword[0] || 'outros');
    if (!/^[a-zA-Z]$/.test(dbIdentifier)) {
        dbIdentifier = 'outros';
    }

    if (!dbPool.canAcceptNewConnection()) {
        return { ok: false, error: 'Muitas buscas em paralelo. Tente novamente em alguns segundos.' };
    }

    dbPool.incrementConnection();
    let db;
    try {
        db = dbPool.getDatabase(dbIdentifier);
        if (!db) {
            return { ok: false, error: 'Nenhum banco de dados encontrado para essa busca.' };
        }

        if (!hasFTSMigration(db)) {
            return { ok: false, error: `Banco de dados da letra '${dbIdentifier}' não está otimizado com FTS5.` };
        }

        if (!usandoAluguel) {
            const credits = initializeCredits(phone);
            if (credits < custo) {
                return {
                    ok: false,
                    error: `Saldo insuficiente! Você precisa de ${custo} créditos para o plano ${plano}.`,
                    credits
                };
            }
        }

        const ftsQuery = db.prepare(`SELECT rowid FROM data_fts WHERE data_fts MATCH ?`);
        const searchTerm = `"${ftsKeyword}"*`;
        const matchingRowIds = ftsQuery.all(searchTerm).map(r => r.rowid);

        let rows = [];

        if (matchingRowIds.length > 0) {
            let idsToFetch = matchingRowIds;

            if (plano.toUpperCase() !== 'ADMINISTRATIVA') {
                const shuffledIds = matchingRowIds.sort(() => 0.5 - Math.random());
                idsToFetch = shuffledIds.slice(0, limite * 2);
            }

            const batchSize = 500;
            let batchResults = [];

            for (let i = 0; i < idsToFetch.length; i += batchSize) {
                const batchIds = idsToFetch.slice(i, i + batchSize);
                const placeholders = batchIds.map(() => '?').join(',');
                const remainingLimit = Math.max(0, limite - batchResults.length);
                if (remainingLimit === 0 && plano.toUpperCase() !== 'ADMINISTRATIVA') break;

                let sql = `
                    SELECT id, line FROM data
                    WHERE id IN (${placeholders}) AND sold = 0
                `;

                if (plano.toUpperCase() !== 'ADMINISTRATIVA') {
                    sql += ` LIMIT ?`;
                }

                const searchQuery = db.prepare(sql);
                const batchRows = plano.toUpperCase() !== 'ADMINISTRATIVA'
                    ? searchQuery.all(...batchIds, remainingLimit)
                    : searchQuery.all(...batchIds);

                batchResults = batchResults.concat(batchRows);

                if (plano.toUpperCase() !== 'ADMINISTRATIVA' && batchResults.length >= limite) {
                    batchResults = batchResults.slice(0, limite);
                    break;
                }
            }

            rows = batchResults;
        }

        if (rows.length === 0) {
            return {
                ok: true,
                results: [],
                stats: {
                    keyword,
                    plano,
                    usandoAluguel,
                    linhas: 0,
                    tempoSegundos: ((Date.now() - startTime) / 1000).toFixed(2)
                },
                msg: 'Nenhum resultado disponível encontrado para sua busca.'
            };
        }

        const idsToMarkAsSold = [];
        let results = [];

        for (const row of rows) {
            let formattedLine = row.line;
            if (format === 'user') {
                const parts = row.line.split(/[:|;\s]/);
                if (parts.length >= 2) {
                    const user = parts[parts.length - 2];
                    const pass = parts[parts.length - 1];
                    if (user && pass) {
                        formattedLine = `${user}:${pass}`;
                    }
                }
            }
            results.push(formattedLine);
            idsToMarkAsSold.push(row.id);
        }

        results = cleanAndDeduplicateResults(results);

        if (usandoAluguel && searchType !== 'ANDROID' && results.length > 200) {
            results = results.slice(0, 200);
            idsToMarkAsSold.splice(200);
        }

        if (idsToMarkAsSold.length > 0) {
            const updateQuery = db.prepare(`UPDATE data SET sold = 1 WHERE id = ?`);
            const batchUpdateSize = 500;

            for (let i = 0; i < idsToMarkAsSold.length; i += batchUpdateSize) {
                const batchIds = idsToMarkAsSold.slice(i, i + batchUpdateSize);
                const transaction = db.transaction((ids) => {
                    for (const id of ids) {
                        updateQuery.run(id);
                    }
                });
                transaction(batchIds);
            }
        }

        if (usandoAluguel) {
            incrementRentalUsage(phone);
        } else {
            updateCredits(phone, -custo);
        }

        const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
        const credits = initializeCredits(phone);

        return {
            ok: true,
            results,
            stats: {
                keyword,
                plano: plano.toUpperCase(),
                usandoAluguel,
                linhas: results.length,
                tempoSegundos: elapsed,
                custo: usandoAluguel ? 0 : custo,
                credits
            }
        };

    } catch (error) {
        console.error(chalk.red('Erro na busca (SQLite/WEB):'), error);
        return { ok: false, error: 'Erro interno durante a busca.' };
    } finally {
        dbPool.decrementConnection();
    }
}

// ================== BUSCA PREMIUM (TODOS OS DBs) ==================
async function searchAllDatabasesHTTP({ phone, keyword }) {
    const startTime = Date.now();
    const custo = 50;
    let allResults = [];
    const allIdsToMarkAsSold = {};

    const credits = initializeCredits(phone);
    if (credits < custo) {
        return {
            ok: false,
            error: `Saldo insuficiente! Você precisa de ${custo} créditos para a Busca Premium.`,
            credits
        };
    }

    try {
        const dbFiles = dbPool.getAllDbFiles();
        if (dbFiles.length === 0) {
            return { ok: false, error: 'Nenhum banco de dados disponível para a busca.' };
        }

        const lowerKeyword = keyword.toLowerCase().trim();

        for (const dbFile of dbFiles) {
            const db = dbPool.getDatabase(dbFile);
            if (!db || !hasFTSMigration(db)) continue;

            const ftsQuery = db.prepare(`SELECT rowid FROM data_fts WHERE data_fts MATCH ?`);
            const searchTerm = `"${lowerKeyword}"*`;
            const matchingRowIds = ftsQuery.all(searchTerm).map(r => r.rowid);

            if (matchingRowIds.length > 0) {
                const batchSize = 500;
                let batchRows = [];

                for (let i = 0; i < matchingRowIds.length; i += batchSize) {
                    const batchIds = matchingRowIds.slice(i, i + batchSize);
                    const placeholders = batchIds.map(() => '?').join(',');
                    const sql = `SELECT id, line FROM data WHERE id IN (${placeholders}) AND sold = 0`;

                    const batchResult = db.prepare(sql).all(...batchIds);
                    batchRows = batchRows.concat(batchResult);
                }

                batchRows.forEach(row => {
                    allResults.push(row.line);
                    if (!allIdsToMarkAsSold[dbFile]) {
                        allIdsToMarkAsSold[dbFile] = [];
                    }
                    allIdsToMarkAsSold[dbFile].push(row.id);
                });
            }
        }

        allResults = cleanAndDeduplicateResults(allResults);

        if (allResults.length === 0) {
            return { ok: true, results: [], msg: 'Nenhum resultado encontrado em todas as bases.' };
        }

        for (const dbName in allIdsToMarkAsSold) {
            const db = dbPool.getDatabase(dbName);
            const ids = allIdsToMarkAsSold[dbName];
            if (db && ids.length > 0) {
                const updateQuery = db.prepare(`UPDATE data SET sold = 1 WHERE id = ?`);
                const batchSize = 500;
                for (let i = 0; i < ids.length; i += batchSize) {
                    const batchIds = ids.slice(i, i + batchSize);
                    const transaction = db.transaction((idList) => {
                        for (const id of idList) {
                            updateQuery.run(id);
                        }
                    });
                    transaction(batchIds);
                }
            }
        }

        updateCredits(phone, -custo);
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
        const creditsNow = initializeCredits(phone);

        return {
            ok: true,
            results: allResults,
            stats: {
                keyword,
                linhas: allResults.length,
                custo,
                tempoSegundos: elapsed,
                credits: creditsNow
            }
        };
    } catch (error) {
        console.error(chalk.red('Erro na busca premium HTTP:'), error);
        return { ok: false, error: 'Erro interno na busca premium.' };
    }
}

// ================== MIX ALEATÓRIO 20k ==================
async function searchRandomLinesHTTP({ phone }) {
    const startTime = Date.now();
    const custo = 50;
    const totalLinesToFetch = 20000;
    let allResults = [];
    const allIdsToMarkAsSold = {};

    const credits = initializeCredits(phone);
    if (credits < custo) {
        return {
            ok: false,
            error: `Saldo insuficiente! Você precisa de ${custo} créditos para o Mix Aleatório 20k.`,
            credits
        };
    }

    try {
        const dbFiles = dbPool.getAllDbFiles();
        if (dbFiles.length === 0) {
            return { ok: false, error: 'Nenhum banco de dados disponível.' };
        }

        const linesPerDb = Math.ceil(totalLinesToFetch / dbFiles.length);

        for (const dbFile of dbFiles) {
            const db = dbPool.getDatabase(dbFile);
            if (!db) continue;

            const query = db.prepare(`SELECT id, line FROM data WHERE sold = 0 LIMIT ?`);
            const rows = query.all(linesPerDb);

            rows.forEach(row => {
                allResults.push(row.line);
                if (!allIdsToMarkAsSold[dbFile]) {
                    allIdsToMarkAsSold[dbFile] = [];
                }
                allIdsToMarkAsSold[dbFile].push(row.id);
            });
        }

        allResults = cleanAndDeduplicateResults(allResults);

        if (allResults.length === 0) {
            return { ok: true, results: [], msg: 'Nenhum resultado disponível encontrado.' };
        }

        for (const dbName in allIdsToMarkAsSold) {
            const db = dbPool.getDatabase(dbName);
            const ids = allIdsToMarkAsSold[dbName];
            if (db && ids.length > 0) {
                const updateQuery = db.prepare(`UPDATE data SET sold = 1 WHERE id = ?`);
                const transaction = db.transaction((idList) => {
                    idList.forEach(id => updateQuery.run(id));
                });
                transaction(ids);
            }
        }

        updateCredits(phone, -custo);
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
        const creditsNow = initializeCredits(phone);

        return {
            ok: true,
            results: allResults,
            stats: {
                linhas: allResults.length,
                custo,
                tempoSegundos: elapsed,
                credits: creditsNow
            }
        };
    } catch (error) {
        console.error(chalk.red('Erro no Mix Aleatório HTTP:'), error);
        return { ok: false, error: 'Erro interno na busca aleatória.' };
    }
}

// ================== EXPRESS APP (API WEB) ==================
const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

// Página simples de teste
app.get('/', (req, res) => {
    res.send(`
        <h1>KDSEVEN CLOUD WEB</h1>
        <p>API online.</p>
        <ul>
          <li>POST /api/token/login</li>
          <li>GET  /api/saldo</li>
          <li>POST /api/search</li>
          <li>POST /api/search/premium</li>
          <li>POST /api/search/mix</li>
          <li>POST /api/pix/create</li>
          <li>GET  /api/pix/status/:txid</li>
        </ul>
    `);
});

// Saldo + aluguel (legado por phone)
app.get('/api/saldo/:phone', (req, res) => {
    const phone = req.params.phone;
    const credits = initializeCredits(phone);
    const rentalInfo = getRentalUsage(phone);
    res.json({ ok: true, phone, credits, rental: rentalInfo });
});

// Saldo via token (para o painel web)
app.get('/api/saldo', authTokenMiddleware, (req, res) => {
    const phone = req.phone;
    const credits = initializeCredits(phone);
    const rentalInfo = getRentalUsage(phone);
    res.json({ ok: true, phone, credits, rental: rentalInfo });
});

// Login via token (painel web)
app.post('/api/token/login', authTokenMiddleware, (req, res) => {
    const phone = req.phone;
    const credits = initializeCredits(phone);
    const rentalInfo = getRentalUsage(phone);
    res.json({ ok: true, phone, credits, rental: rentalInfo });
});

// Ativar aluguel (uso externo, já cobrando créditos)
app.post('/api/aluguel/ativar', (req, res) => {
    const { phone, plano } = req.body;
    if (!phone || !plano || !CONFIG.ALUGUEL[plano]) {
        return res.status(400).json({ ok: false, error: 'Parâmetros inválidos ou plano inexistente.' });
    }
    const cfg = CONFIG.ALUGUEL[plano];
    const custoAluguel = cfg.creditos || 0;
    const creditsAtual = initializeCredits(phone);
    if (creditsAtual < custoAluguel) {
        return res.status(400).json({
            ok: false,
            error: `Saldo insuficiente! São necessários ${custoAluguel} créditos para ativar este aluguel.`,
            credits: creditsAtual
        });
    }
    const creditsDepois = updateCredits(phone, -custoAluguel);
    const rental = activateRental(phone, plano);
    res.json({ ok: true, rental, credits: creditsDepois });
});

// Busca padrão (autenticada por token)
app.post('/api/search', authTokenMiddleware, async (req, res) => {
    const { keyword, plano = 'NORMAL', searchType = 'NORMAL', format = 'full', isRental = false } = req.body;
    const phone = req.phone;
    if (!keyword || !plano) {
        return res.status(400).json({ ok: false, error: 'Campos obrigatórios: keyword, plano.' });
    }
    const resp = await searchAndSaveHTTP({ phone, keyword, plano, searchType, format, isRental });
    res.json(resp);
});

// Busca Premium Total (token)
app.post('/api/search/premium', authTokenMiddleware, async (req, res) => {
    const { keyword } = req.body;
    const phone = req.phone;
    if (!keyword) {
        return res.status(400).json({ ok: false, error: 'Campo obrigatório: keyword.' });
    }
    const resp = await searchAllDatabasesHTTP({ phone, keyword });
    res.json(resp);
});

// Mix Aleatório 20k (token)
app.post('/api/search/mix', authTokenMiddleware, async (req, res) => {
    const phone = req.phone;
    const resp = await searchRandomLinesHTTP({ phone });
    res.json(resp);
});

// Criar cobrança PIX
app.post('/api/pix/create', async (req, res) => {
    const { phone, amount } = req.body;
    if (!phone || !amount) {
        return res.status(400).json({ ok: false, error: 'Campos obrigatórios: phone, amount.' });
    }
    const value = parseFloat(String(amount).replace(',', '.'));
    if (isNaN(value) || value < 20 || value > CONFIG.MAX_RECHARGE_AMOUNT) {
        return res.status(400).json({
            ok: false,
            error: `Valor inválido! Mínimo R$ 20,00 e máximo R$ ${CONFIG.MAX_RECHARGE_AMOUNT.toFixed(2)}.`
        });
    }

    const pixData = await createPixPayment(phone, value);
    if (!pixData) {
        return res.json({ ok: false, error: 'Erro ao gerar cobrança PIX.' });
    }

    const transactions = loadJson(JSON_FILES.TRANSACTIONS);
    transactions[pixData.txid] = {
        phone,
        amount: value,
        created: new Date().toISOString(),
        status: 'PENDING'
    };
    saveJson(JSON_FILES.TRANSACTIONS, transactions);

    pendingPayments.set(pixData.txid, {
        phone,
        amount: value,
        lastCheck: Date.now(),
        notified: false,
        created: Date.now()
    });

    res.json({
        ok: true,
        txid: pixData.txid,
        qrcode: pixData.qrcode,
        imagemQrcode: pixData.imagemQrcode
    });
});

// Checar status do PIX (gera token e créditos imediatamente)
app.get('/api/pix/status/:txid', async (req, res) => {
    const txid = req.params.txid;
    const details = await checkPixPayment(txid);
    if (!details) {
        return res.json({ ok: false, error: 'Não foi possível obter o status do PIX.' });
    }

    const transactions = loadJson(JSON_FILES.TRANSACTIONS);
    const tx = transactions[txid];
    let token = null;

    if (tx) {
        const status = details.status;
        const now = new Date().toISOString();

        if (status === 'CONCLUIDA') {
            // Evitar créditos em duplicidade
            if (tx.status !== 'PAID') {
                const promoConfig = loadJson(JSON_FILES.PROMOTION);
                let creditsToAdd = tx.amount;
                if (promoConfig.isActive && tx.amount >= promoConfig.minValue) {
                    creditsToAdd = tx.amount * 2;
                }
                const newCredits = updateCredits(tx.phone, creditsToAdd);

                tx.status = 'PAID';
                tx.paid = now;
                tx.creditsAdded = creditsToAdd;
                tx.saldoApos = newCredits;
                transactions[txid] = tx;
                saveJson(JSON_FILES.TRANSACTIONS, transactions);

                console.log(chalk.green(`✅ Pagamento ${txid} confirmado (via painel) para ${tx.phone}. Créditos: ${creditsToAdd}`));
            }

            token = ensureTokenForPhone(tx.phone);
            pendingPayments.delete(txid);
        } else if (status === 'REMOVIDA_PELO_USUARIO_RECEBEDOR' || status === 'REMOVIDA_PELO_PSP') {
            if (tx.status !== 'EXPIRED') {
                tx.status = 'EXPIRED';
                tx.expiredAt = now;
                transactions[txid] = tx;
                saveJson(JSON_FILES.TRANSACTIONS, transactions);
                console.log(chalk.yellow(`⌛ Pagamento ${txid} expirado/cancelado (via painel).`));
            }
            pendingPayments.delete(txid);
        }
    }

    res.json({
        ok: true,
        status: details.status,
        detalhes: details,
        registroLocal: tx || null,
        token
    });
});

// ================== LOOP OPCIONAL PARA PROCESSAR PENDENTES (CRÉDITOS AUTOMÁTICOS) ==================
async function processPendingPaymentsLoop() {
    const now = Date.now();
    const txids = Array.from(pendingPayments.keys());
    for (const txid of txids) {
        const payment = pendingPayments.get(txid);
        if (!payment) continue;

        if (now - payment.lastCheck < 30000) continue;
        payment.lastCheck = now;

        const paymentStatus = await checkPixPayment(txid);
        if (!paymentStatus) continue;

        const transactions = loadJson(JSON_FILES.TRANSACTIONS);
        const txInfo = transactions[txid];

        // Se já foi marcado como PAID/EXPIRED por outra via (ex: painel web), não processa de novo
        if (txInfo && (txInfo.status === 'PAID' || txInfo.status === 'EXPIRED')) {
            pendingPayments.delete(txid);
            continue;
        }

        const expiredStatuses = ['REMOVIDA_PELO_USUARIO_RECEBEDOR', 'REMOVIDA_PELO_PSP'];
        const isExpired = expiredStatuses.includes(paymentStatus.status) || (now - payment.created > 3600 * 1000);

        if (paymentStatus.status === 'CONCLUIDA') {
            console.log(chalk.green(`✅ Pagamento ${txid} para ${payment.phone} confirmado! (loop automático)`));

            const promoConfig = loadJson(JSON_FILES.PROMOTION);
            let creditsToAdd = payment.amount;
            if (promoConfig.isActive && payment.amount >= promoConfig.minValue) {
                creditsToAdd = payment.amount * 2;
            }
            const newCredits = updateCredits(payment.phone, creditsToAdd);

            if (transactions[txid]) {
                transactions[txid].status = 'PAID';
                transactions[txid].paid = new Date().toISOString();
                transactions[txid].creditsAdded = creditsToAdd;
                transactions[txid].saldoApos = newCredits;
                saveJson(JSON_FILES.TRANSACTIONS, transactions);
            }
            console.log(chalk.blue(`💎 Créditos liberados automaticamente para ${payment.phone}: ${creditsToAdd}. Saldo: ${newCredits}`));
            pendingPayments.delete(txid);
        } else if (isExpired) {
            console.log(chalk.yellow(`⌛ Pagamento ${txid} expirado/cancelado.`));
            if (transactions[txid]) {
                transactions[txid].status = 'EXPIRED';
                transactions[txid].expiredAt = new Date().toISOString();
                saveJson(JSON_FILES.TRANSACTIONS, transactions);
            }
            pendingPayments.delete(txid);
        }
    }
}
setInterval(processPendingPaymentsLoop, 20000);

// ================== SUBIR SERVIDOR ==================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(chalk.green(`🚀 KDSEVEN WEB rodando na porta ${PORT}`));
});
