// Synthetic TypeScript vulnerable source fixture for SourceAnalyzer unit tests

import express, { Request, Response } from 'express';
import cors from 'cors';

const app = express();

// 1. Security Misconfiguration: Wildcard CORS with credentials
app.use(cors({ origin: '*', credentials: true }));

// 2. Sensitive Data Exposure: Hardcoded API key
const apiKey: string = "sk_live_typescript_secret_key_9988776655";

// 3. SQL Injection in TypeScript service
export async function findUserByEmailUnsafe(prisma: any, email: string): Promise<any> {
    const sqlQuery: string = `SELECT id, email, password FROM Users WHERE email = '${email}'`;
    return await prisma.$queryRawUnsafe(sqlQuery);
}

// 4. IDOR / BOLA in TypeScript Express handler
app.get('/api/Cards/:id', async (req: Request, res: Response) => {
    const cardRecord = await CardRepository.findUnique({ where: { id: req.params.id } });
    res.status(200).json(cardRecord);
});

// 5. Broken Access Control: Unprotected admin user list endpoint
app.get('/api/Users', async (req: Request, res: Response) => {
    const allUsers = await UserRepository.findMany();
    res.json({ data: allUsers });
});

// 6. Cross-Site Scripting in TSX/React prop helper
export function getUnsafeMarkup(rawHtmlInput: string) {
    const element = { dangerouslySetInnerHTML: { __html: rawHtmlInput } };
    return element;
}

