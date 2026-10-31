// Synthetic safe JavaScript / TypeScript fixture for false-positive prevention

import express, { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import DOMPurify from 'dompurify';

const router = express.Router();
const jwtSecret = process.env.JWT_SECRET || '';

function requireAuth(req: Request, res: Response, next: NextFunction) {
    const token = req.headers.authorization || '';
    req.user = jwt.verify(token, jwtSecret);
    next();
}

function requireAdmin(req: Request, res: Response, next: NextFunction) {
    if (req.user?.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden' });
    }
    next();
}

// Safe parameterized SQL query
router.get('/api/products/search', requireAuth, async (req: Request, res: Response) => {
    const category = req.query.category;
    const rows = await db.query('SELECT * FROM Products WHERE category = ? AND deleted = 0', [category]);
    res.json(rows);
});

// Safe DOM rendering using textContent and DOMPurify
export function renderSafeComment(container: HTMLElement, userComment: string) {
    container.textContent = userComment;
    container.innerHTML = DOMPurify.sanitize(userComment);
}

// Safe Admin route with middleware
router.get('/api/admin/configuration', requireAuth, requireAdmin, async (req: Request, res: Response) => {
    const cfg = await ConfigModel.findAll();
    res.json(cfg);
});

// Safe IDOR-protected route checking req.user.id ownership
router.get('/rest/basket/:id', requireAuth, async (req: Request, res: Response) => {
    const basket = await BasketModel.findOne({
        where: { id: req.params.id, userId: req.user.id }
    });
    if (!basket) {
        return res.status(403).json({ error: 'Access denied' });
    }
    res.json(basket);
});

