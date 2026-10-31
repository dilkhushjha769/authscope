// Synthetic JavaScript vulnerable source fixture for SourceAnalyzer unit tests

const express = require('express');
const jwt = require('jsonwebtoken');
const https = require('https');
const router = express.Router();

// 1. Hardcoded secret (Sensitive Data Exposure)
const jwtSecret = "super_hardcoded_jwt_signing_secret_key_2026";

// 2. SQL Injection via template literal interpolation
router.get('/api/products/search', async (req, res) => {
    const category = req.query.category;
    const rows = await db.query(`SELECT * FROM Products WHERE category = '${category}' AND deleted = 0`);
    res.json(rows);
});

// 3. Cross-Site Scripting (DOM XSS and Reflected Express HTML send)
function renderUserComment(container, userComment) {
    container.innerHTML = `<div class="comment">${userComment}</div>`;
    document.write("<p>" + userComment + "</p>");
}

router.get('/api/greet', (req, res) => {
    res.send(`<html><body><h1>Hello ${req.query.name}</h1></body></html>`);
});

// 4. Broken Access Control (Admin route without auth middleware)
router.get('/api/admin/configuration', async (req, res) => {
    const cfg = await ConfigModel.findAll();
    res.json(cfg);
});

// 5. Broken Access Control (Client-supplied role & unverified jwt.decode)
router.post('/api/profile/upgrade', (req, res) => {
    const decoded = jwt.decode(req.headers.authorization);
    if (req.body.isAdmin) {
        return res.json({ upgraded: true, user: decoded });
    }
    return res.status(400).json({ upgraded: false });
});

// 6. IDOR / BOLA (Direct lookup by req.params.id without owner check)
router.get('/rest/basket/:id', async (req, res) => {
    const basket = await BasketModel.findByPk(req.params.id);
    res.json(basket);
});

// 7. Security Misconfiguration (TLS rejectUnauthorized: false & eval)
const insecureAgent = new https.Agent({ rejectUnauthorized: false });
function runDynamicCalc(expr) {
    return eval(expr);
}

module.exports = { router, renderUserComment, insecureAgent, runDynamicCalc };
