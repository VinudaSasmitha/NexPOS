// ===============================
// IMPORTS
// ===============================
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const Joi = require('joi');
require('dotenv').config();

// Enterprise POS Backend v3.0 - COMPLETE PRODUCTION BUILD
// Applied: ⚠️3 Payment_Methods FK, ⚠️4 Stock Movement Reference_ID,
//          ⚠️5 Audit Table_Name+Record_ID, ⚠️6 Cost_Price_At_Sale snapshot

const app = express();
app.use(cors());
app.use(express.json());

// ===============================
// RATE LIMITING (Fix #8 — Security)
// ===============================
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10,
    message: { message: '⛔ Too many login attempts. Try again in 15 minutes.' }
});

// ===============================
// DB CONNECTION (POOL)
// ===============================
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'dbpos_',
    connectionLimit: 15
});

const SECRET = process.env.JWT_SECRET || "supersecret_change_in_production";

// ===============================
// PROMISE WRAPPER FOR POOL + TRANSACTIONS
// ===============================
function query(sql, params = []) {
    return new Promise((resolve, reject) => {
        pool.query(sql, params, (err, result) => {
            if (err) return reject(err);
            resolve(result);
        });
    });
}

function queryConn(conn, sql, params = []) {
    return new Promise((resolve, reject) => {
        conn.query(sql, params, (err, result) => {
            if (err) return reject(err);
            resolve(result);
        });
    });
}

// ===============================
// AUDIT LOG HELPER (⚠️5 — Table_Name + Record_ID + IP)
// ===============================
async function auditLog(userId, action, tableName = null, recordId = null, ip = null) {
    try {
        await query(
            "INSERT INTO Audit_Log (User_ID, Action, Table_Name, Record_ID, IP_Address) VALUES (?, ?, ?, ?, ?)",
            [userId, action, tableName, recordId, ip]
        );
    } catch (e) {
        console.error('Audit log failed:', e.message);
    }
}

function getIp(req) {
    return req.headers['x-forwarded-for']?.split(',')[0] || req.socket?.remoteAddress || null;
}

// ===============================
// AUTH MIDDLEWARE (Fix #8 — Bearer Token)
// ===============================
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Expect: "Bearer TOKEN"
    if (!token) return res.status(401).json({ message: 'No token provided' });

    jwt.verify(token, SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid or expired token' });
        req.user = user;
        next();
    });
}

// ===============================
// ROLE-BASED ACCESS (Fix #5 — DB-driven roles)
// ===============================
function authorizeRoles(...allowedRoles) {
    return (req, res, next) => {
        if (!allowedRoles.includes(req.user.roleName)) {
            return res.status(403).json({ message: 'Forbidden: Insufficient permissions' });
        }
        next();
    };
}

// ===============================
// INPUT VALIDATION SCHEMAS (Fix #8 — Joi)
// ===============================
const schemas = {
    register: Joi.object({
        Name: Joi.string().min(2).max(100).required(),
        Email: Joi.string().email().required(),
        Phone_Number: Joi.string().max(20).optional().allow(''),
        Password: Joi.string().min(6).required(),
        Role_ID: Joi.number().integer().required(),
        Branch_ID: Joi.number().integer().optional().allow(null)
    }),
    login: Joi.object({
        Email: Joi.string().email().required(),
        Password: Joi.string().required()
    }),
    product: Joi.object({
        Name: Joi.string().max(150).required(),
        Category_ID: Joi.number().integer().required(),
        Brand: Joi.string().max(100).optional().allow(''),
        Description: Joi.string().optional().allow(''),
        Barcode: Joi.string().max(100).required(),
        Unit: Joi.string().max(50).required()
    }),
    price: Joi.object({
        Product_ID: Joi.number().integer().required(),
        Cost_Price: Joi.number().positive().required(),
        Sell_Price: Joi.number().positive().required(),
        Wholesale_Price: Joi.number().positive().required(),
        Tax_Percentage: Joi.number().min(0).default(0)
    }),
    inventory: Joi.object({
        Product_ID: Joi.number().integer().required(),
        Warehouse_ID: Joi.number().integer().optional().allow(null),
        Branch_ID: Joi.number().integer().optional().allow(null),
        Quantity: Joi.number().integer().min(1).required(),
        Batch_Number: Joi.string().optional().allow(''),
        Expire_Date: Joi.date().optional(),
        Supplier_ID: Joi.number().integer().optional().allow(null)
    }),
    customer: Joi.object({
        Name: Joi.string().max(100).required(),
        Phone_Number: Joi.string().max(20).optional().allow(''),
        Email: Joi.string().email().optional().allow(''),
        Address: Joi.string().optional().allow('')
    }),
    bill: Joi.object({
        Customer_ID: Joi.number().integer().optional().allow(null),
        Branch_ID: Joi.number().integer().required(),
        items: Joi.array().items(Joi.object({
            Product_ID: Joi.number().integer().required(),
            Quantity: Joi.number().integer().min(1).required(),
            Unit_Price: Joi.number().positive().required(),
            Total_Price: Joi.number().positive().required()
        })).min(1).required(),
        Total_Amount: Joi.number().positive().required(),
        Tax_Amount: Joi.number().min(0).default(0),
        Discount_Amount: Joi.number().min(0).default(0)
    }),
    payment: Joi.object({
        Bill_ID: Joi.number().integer().required(),
        Method: Joi.string().valid('Cash', 'Card', 'Online', 'Credit').required(),
        Amount: Joi.number().positive().required(),
        Loan_Name: Joi.string().optional().allow(''),
        Loan_Phone_Number: Joi.string().optional().allow('')
    }),
    returns: Joi.object({
        Bill_ID: Joi.number().integer().required(),
        Product_ID: Joi.number().integer().required(),
        Quantity: Joi.number().integer().min(1).required(),
        Reason: Joi.string().optional().allow(''),
        Refund_Amount: Joi.number().positive().required(),
        Branch_ID: Joi.number().integer().required(),
        Payment_Method: Joi.string().valid('Cash', 'Card', 'Online').required()
    }),
    supplier: Joi.object({
        Name: Joi.string().max(100).required(),
        Phone_Number: Joi.string().max(20).required(),
        Email: Joi.string().email().optional().allow(''),
        Company: Joi.string().max(150).optional().allow('')
    }),
    transferInventory: Joi.object({
        Product_ID: Joi.number().integer().required(),
        From_Warehouse_ID: Joi.number().integer().required(),
        To_Branch_ID: Joi.number().integer().required(),
        Quantity: Joi.number().integer().min(1).required()
    }),
    quickStockAdjust: Joi.object({
        Barcode: Joi.string().max(100).required(),
        Qty: Joi.number().integer().min(1).required(),
        Type: Joi.string().valid('ADD', 'REMOVE').required()
    }),
    masterReceive: Joi.object({
        Category_ID: Joi.number().integer().required(),
        Barcode: Joi.string().max(100).required(),
        Product_Name: Joi.string().max(150).required(),
        Brand_Name: Joi.string().max(100).optional().allow(''),
        Unit_Type: Joi.string().max(50).required(),
        Size_Weight: Joi.string().max(255).optional().allow(''),
        Stock_Quantity: Joi.number().integer().min(1).required(),
        Expire_Date: Joi.date().optional().allow(null),
        Batch_Number: Joi.string().max(100).optional().allow('', null),
        Buying_Price: Joi.number().positive().required(),
        Retail_Price: Joi.number().positive().required(),
        Wholesale_Price: Joi.number().min(0).default(0),
        Total_Bill: Joi.number().min(0).required(),
        Amount_Paid: Joi.number().min(0).required(),
        Remaining_Due: Joi.number().min(0).required(),
        Is_New_Supplier: Joi.boolean().required(),
        Supplier_ID: Joi.number().integer().optional().allow(null),
        Supplier_Name: Joi.string().max(100).when('Is_New_Supplier', {
            is: true,
            then: Joi.required(),
            otherwise: Joi.optional().allow('', null)
        }),
        Supplier_Phone: Joi.string().max(20).when('Is_New_Supplier', {
            is: true,
            then: Joi.required(),
            otherwise: Joi.optional().allow('', null)
        }),
        Supplier_Notes: Joi.string().max(500).optional().allow('', null)
    })
};

function validate(schema) {
    return (req, res, next) => {
        const { error } = schema.validate(req.body, { abortEarly: false });
        if (error) {
            return res.status(400).json({
                message: 'Validation error',
                details: error.details.map(d => d.message)
            });
        }
        next();
    };
}

// ===============================
// ROOT
// ===============================
app.get('/', (req, res) => {
    res.json({ message: '🚀 Enterprise POS Backend Running', version: '3.0.0' });
});

// ===============================
// 🔐 REGISTER (Admin Only)
// ===============================
app.post(
    '/api/register',
    authenticateToken,
    authorizeRoles('Admin'),
    validate(schemas.register),
    async (req, res) => {
        try {
            const { Name, Email, Phone_Number, Password, Role_ID, Branch_ID } = req.body;
            const hashedPassword = await bcrypt.hash(Password, 12);

            await query(
                "INSERT INTO Members (Name, Email, Phone_Number, Password, Role_ID, Branch_ID) VALUES (?, ?, ?, ?, ?, ?)",
                [Name, Email, Phone_Number || null, hashedPassword, Role_ID, Branch_ID || null]
            );

            await auditLog(req.user.id, `Registered new user: ${Email} with Role_ID: ${Role_ID}`);
            res.status(201).json({ message: '✅ User Registered Successfully!' });
        } catch (err) {
            if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ message: 'Email already exists' });
            res.status(500).json({ message: 'Server error', error: err.message });
        }
    }
);

// ===============================
// 🔐 LOGIN (Fix #8 — Rate limited)
// ===============================
app.post('/api/login', loginLimiter, validate(schemas.login), async (req, res) => {
    try {
        const { Email, Password } = req.body;

        const result = await query(
            `SELECT m.*, r.Role_Name 
             FROM Members m 
             JOIN Roles r ON m.Role_ID = r.Role_ID 
             WHERE m.Email = ? AND m.Is_Deleted = FALSE`,
            [Email]
        );
        if (result.length === 0) return res.status(401).json({ message: 'Invalid credentials' });

        const user = result[0];

        if (user.Failed_Login_Attempts >= 5) {
            return res.status(403).json({ message: '🔒 Account locked. Contact admin.' });
        }

        const match = await bcrypt.compare(Password, user.Password);

        if (!match) {
            await query(
                "UPDATE Members SET Failed_Login_Attempts = Failed_Login_Attempts + 1 WHERE Member_ID = ?",
                [user.Member_ID]
            );
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        await query(
            "UPDATE Members SET Failed_Login_Attempts = 0, Last_Login = NOW() WHERE Member_ID = ?",
            [user.Member_ID]
        );

        const token = jwt.sign(
            { id: user.Member_ID, roleId: user.Role_ID, roleName: user.Role_Name, branchId: user.Branch_ID || null },
            SECRET,
            { expiresIn: '8h' }
        );

        await auditLog(user.Member_ID, `Login successful`);

        res.json({
            token,
            user: {
                id: user.Member_ID,
                Name: user.Name,
                Email: user.Email,
                role: user.Role_Name,
                branchId: user.Branch_ID
            }
        });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// ===============================
// 👤 CUSTOMERS
// ===============================
app.post(
    '/api/customers',
    authenticateToken,
    authorizeRoles('Admin', 'Sales Manager', 'Cashier'),
    validate(schemas.customer),
    async (req, res) => {
        try {
            const { Name, Phone_Number, Email, Address } = req.body;
            const result = await query(
                "INSERT INTO Customers (Name, Phone_Number, Email, Address) VALUES (?, ?, ?, ?)",
                [Name, Phone_Number, Email, Address]
            );
            await auditLog(req.user.id, `Added customer: ${Name}`);
            res.status(201).json({ id: result.insertId, message: 'Customer created' });
        } catch (err) {
            res.status(500).json({ message: 'Server error', error: err.message });
        }
    }
);

app.get(
    '/api/customers',
    authenticateToken,
    authorizeRoles('Admin', 'Sales Manager', 'Branch Manager'),
    async (req, res) => {
        try {
            const result = await query(
                "SELECT * FROM Customers WHERE Is_Deleted = FALSE ORDER BY Name"
            );
            res.json(result);
        } catch (err) {
            res.status(500).json({ message: 'Server error', error: err.message });
        }
    }
);

app.delete(
    '/api/customers/:id',
    authenticateToken,
    authorizeRoles('Admin'),
    async (req, res) => {
        try {
            await query("UPDATE Customers SET Is_Deleted = TRUE WHERE Customer_ID = ?", [req.params.id]);
            await auditLog(req.user.id, `Soft-deleted customer ID: ${req.params.id}`);
            res.json({ message: 'Customer removed' });
        } catch (err) {
            res.status(500).json({ message: 'Server error', error: err.message });
        }
    }
);

// ===============================
// 📦 PRODUCTS
// ===============================
app.post(
    '/api/products',
    authenticateToken,
    authorizeRoles('Admin', 'Inventory Manager'),
    validate(schemas.product),
    async (req, res) => {
        try {
            const { Name, Category_ID, Brand, Description, Barcode, Unit } = req.body;
            const result = await query(
                "INSERT INTO Products (Name, Category_ID, Brand, Description, Barcode, Unit) VALUES (?, ?, ?, ?, ?, ?)",
                [Name, Category_ID, Brand, Description, Barcode, Unit]
            );
            await auditLog(req.user.id, `Added product: ${Name} (Barcode: ${Barcode})`);
            res.status(201).json({ id: result.insertId });
        } catch (err) {
            if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ message: 'Barcode already exists' });
            res.status(500).json({ message: 'Server error', error: err.message });
        }
    }
);

app.get(
    '/api/products',
    authenticateToken,
    authorizeRoles('Admin', 'Sales Manager', 'Cashier', 'Inventory Manager', 'Branch Manager', 'Warehouse Manager'),
    async (req, res) => {
        try {
            const branchId = req.user.branchId;
            let sql = `
                SELECT 
                    p.Product_ID, p.Name, p.Category_ID, p.Brand, p.Description, p.Barcode, p.Unit,
                    pp.Sell_Price, pp.Cost_Price, pp.Wholesale_Price, pp.Tax_Percentage,
                    COALESCE(SUM(i.Quantity), 0) AS Quantity,
                    MAX(i.Branch_ID) AS Branch_ID,
                    MAX(i.Batch_Number) AS Batch_Number,
                    MIN(i.Expire_Date) AS Expire_Date,
                    CASE WHEN MIN(i.Expire_Date) < CURDATE() THEN TRUE ELSE FALSE END AS Is_Expired
                FROM Products p
                LEFT JOIN Product_Prices pp ON pp.Price_ID = (
                    SELECT Price_ID FROM Product_Prices
                    WHERE Product_ID = p.Product_ID
                    ORDER BY Effective_Date DESC LIMIT 1
                )
                LEFT JOIN Inventory i ON p.Product_ID = i.Product_ID
                WHERE p.Is_Deleted = FALSE
            `;
            const params = [];
            if (branchId) {
                sql += " AND i.Branch_ID = ?";
                params.push(branchId);
            }
            sql += " GROUP BY p.Product_ID, p.Name, p.Category_ID, p.Brand, p.Description, p.Barcode, p.Unit, pp.Sell_Price, pp.Cost_Price, pp.Wholesale_Price, pp.Tax_Percentage";
            const result = await query(sql, params);
            res.json(result);
        } catch (err) {
            res.status(500).json({ message: 'Server error', error: err.message });
        }
    }
);

app.get(
    '/api/products/barcode/:barcode',
    authenticateToken,
    authorizeRoles('Admin', 'Cashier', 'Sales Manager', 'Branch Manager', 'Inventory Manager'),
    async (req, res) => {
        try {
            const params = [req.params.barcode];
            let sql = `SELECT p.*, pp.Sell_Price, pp.Cost_Price, pp.Wholesale_Price, pp.Tax_Percentage, COALESCE(SUM(i.Quantity), 0) AS Quantity
                 FROM Products p
                 LEFT JOIN Product_Prices pp ON pp.Price_ID = (
                     SELECT Price_ID FROM Product_Prices
                     WHERE Product_ID = p.Product_ID
                     ORDER BY Effective_Date DESC LIMIT 1
                 )
                 LEFT JOIN Inventory i ON p.Product_ID = i.Product_ID
                 WHERE p.Barcode = ? AND p.Is_Deleted = FALSE`;
            if (req.user.branchId) {
                sql += " AND i.Branch_ID = ?";
                params.push(req.user.branchId);
            }
            sql += " GROUP BY p.Product_ID, pp.Sell_Price, pp.Cost_Price, pp.Wholesale_Price, pp.Tax_Percentage";
            const result = await query(sql, params);
            if (result.length === 0) return res.status(404).json({ message: 'Product not found' });
            res.json(result[0]);
        } catch (err) {
            res.status(500).json({ message: 'Server error', error: err.message });
        }
    }
);

app.get(
    '/api/products/search/:name',
    authenticateToken,
    authorizeRoles('Admin', 'Cashier', 'Sales Manager', 'Branch Manager', 'Inventory Manager'),
    async (req, res) => {
        try {
            const branchId = req.user.branchId;
            let sql = `
                SELECT p.Product_ID, p.Name, p.Brand, p.Barcode, p.Unit,
                       pp.Sell_Price, pp.Tax_Percentage,
                       COALESCE(SUM(i.Quantity), 0) AS Quantity
                FROM Products p
                LEFT JOIN Product_Prices pp ON pp.Price_ID = (
                    SELECT Price_ID FROM Product_Prices
                    WHERE Product_ID = p.Product_ID
                    ORDER BY Effective_Date DESC LIMIT 1
                )
                LEFT JOIN Inventory i ON p.Product_ID = i.Product_ID
                WHERE p.Name LIKE ? AND p.Is_Deleted = FALSE
            `;
            const params = [`%${req.params.name}%`];
            if (branchId) {
                sql += " AND i.Branch_ID = ?";
                params.push(branchId);
            }
            sql += " GROUP BY p.Product_ID, p.Name, p.Brand, p.Barcode, p.Unit, pp.Sell_Price, pp.Tax_Percentage";
            sql += " LIMIT 20";
            const result = await query(sql, params);
            res.json(result);
        } catch (err) {
            res.status(500).json({ message: 'Server error', error: err.message });
        }
    }
);

app.delete(
    '/api/products/:id',
    authenticateToken,
    authorizeRoles('Admin', 'Inventory Manager'),
    async (req, res) => {
        try {
            await query("UPDATE Products SET Is_Deleted = TRUE WHERE Product_ID = ?", [req.params.id]);
            await auditLog(req.user.id, `Soft-deleted product ID: ${req.params.id}`);
            res.json({ message: 'Product removed' });
        } catch (err) {
            res.status(500).json({ message: 'Server error', error: err.message });
        }
    }
);

// ===============================
// 💰 PRICES
// ===============================
app.post(
    '/api/prices',
    authenticateToken,
    authorizeRoles('Admin', 'Inventory Manager'),
    validate(schemas.price),
    async (req, res) => {
        try {
            const { Product_ID, Cost_Price, Sell_Price, Wholesale_Price, Tax_Percentage = 0 } = req.body;
            await query(
                "INSERT INTO Product_Prices (Product_ID, Cost_Price, Sell_Price, Wholesale_Price, Tax_Percentage, Effective_Date) VALUES (?, ?, ?, ?, ?, CURDATE())",
                [Product_ID, Cost_Price, Sell_Price, Wholesale_Price, Tax_Percentage]
            );
            await auditLog(req.user.id, `Updated price for Product_ID: ${Product_ID} — Sell: ${Sell_Price}`);
            res.status(201).json({ message: '💰 Price Added' });
        } catch (err) {
            res.status(500).json({ message: 'Server error', error: err.message });
        }
    }
);

app.get(
    '/api/prices/:productId',
    authenticateToken,
    authorizeRoles('Admin', 'Inventory Manager'),
    async (req, res) => {
        try {
            const result = await query(
                "SELECT * FROM Product_Prices WHERE Product_ID = ? ORDER BY Effective_Date DESC",
                [req.params.productId]
            );
            res.json(result);
        } catch (err) {
            res.status(500).json({ message: 'Server error', error: err.message });
        }
    }
);

// ===============================
// 📦 OLD INVENTORY (For general use)
// ===============================
app.post(
    '/api/inventory',
    authenticateToken,
    authorizeRoles('Admin', 'Inventory Manager', 'Warehouse Manager'),
    validate(schemas.inventory),
    async (req, res) => {
        try {
            const { Product_ID, Warehouse_ID, Branch_ID, Quantity, Batch_Number, Expire_Date, Supplier_ID } = req.body;

            const sql = `
                INSERT INTO Inventory (Product_ID, Warehouse_ID, Branch_ID, Quantity, Batch_Number, Expire_Date, Supplier_ID)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE 
                    Quantity = Quantity + VALUES(Quantity),
                    Batch_Number = VALUES(Batch_Number),
                    Expire_Date = VALUES(Expire_Date)
            `;
            await query(sql, [Product_ID, Warehouse_ID || null, Branch_ID || null, Quantity, Batch_Number || null, Expire_Date || null, Supplier_ID || null]);

            await query(
                "INSERT INTO Stock_Movements (Product_ID, Warehouse_ID, Branch_ID, Quantity_In, Reason) VALUES (?, ?, ?, ?, 'STOCK_IN')",
                [Product_ID, Warehouse_ID || null, Branch_ID || null, Quantity]
            );

            await auditLog(req.user.id, `Stock updated — Product: ${Product_ID}, Qty: +${Quantity}`);
            res.status(201).json({ message: '📦 Stock Updated' });
        } catch (err) {
            res.status(500).json({ message: 'Server error', error: err.message });
        }
    }
);

app.post(
    '/api/inventory/transfer',
    authenticateToken,
    authorizeRoles('Admin', 'Warehouse Manager', 'Inventory Manager'),
    validate(schemas.transferInventory),
    async (req, res) => {
        const { Product_ID, From_Warehouse_ID, To_Branch_ID, Quantity } = req.body;

        pool.getConnection(async (err, conn) => {
            if (err) return res.status(500).json({ message: 'Connection error' });
            try {
                await queryConn(conn, 'START TRANSACTION');

                const stock = await queryConn(conn,
                    "SELECT Quantity FROM Inventory WHERE Product_ID=? AND Warehouse_ID=? FOR UPDATE",
                    [Product_ID, From_Warehouse_ID]
                );
                if (!stock.length || stock[0].Quantity < Quantity) throw { message: 'Insufficient warehouse stock' };

                await queryConn(conn,
                    "UPDATE Inventory SET Quantity=Quantity-? WHERE Product_ID=? AND Warehouse_ID=?",
                    [Quantity, Product_ID, From_Warehouse_ID]
                );

                await queryConn(conn,
                    `INSERT INTO Inventory (Product_ID, Branch_ID, Quantity)
                     VALUES (?, ?, ?)
                     ON DUPLICATE KEY UPDATE Quantity=Quantity+VALUES(Quantity)`,
                    [Product_ID, To_Branch_ID, Quantity]
                );

                await queryConn(conn,
                    "INSERT INTO Stock_Movements (Product_ID, Warehouse_ID, Branch_ID, Quantity_Out, Reason) VALUES (?,?,?,?,'TRANSFER_OUT')",
                    [Product_ID, From_Warehouse_ID, To_Branch_ID, Quantity]
                );

                await queryConn(conn, 'COMMIT');
                await auditLog(req.user.id, `Transfer: Product ${Product_ID} x${Quantity} from WH ${From_Warehouse_ID} → Branch ${To_Branch_ID}`);
                res.json({ message: '🔁 Transfer Complete' });
            } catch (error) {
                await queryConn(conn, 'ROLLBACK');
                res.status(400).json({ message: error.message || 'Transfer failed' });
            } finally {
                conn.release();
            }
        });
    }
);

// ===============================
// 🧾 BILLING
// ===============================
app.post(
    '/api/bill',
    authenticateToken,
    authorizeRoles('Admin', 'Cashier', 'Sales Manager'),
    validate(schemas.bill),
    async (req, res) => {
        const { Customer_ID, Branch_ID, items, Total_Amount, Tax_Amount = 0, Discount_Amount = 0 } = req.body;
        const Cashier_ID = req.user.id;

        for (const item of items) {
            const inv = await query(
                "SELECT Quantity, Expire_Date FROM Inventory WHERE Product_ID=? AND Branch_ID=?",
                [item.Product_ID, Branch_ID]
            );
            if (inv.length > 0 && inv[0].Expire_Date && new Date(inv[0].Expire_Date) < new Date()) {
                return res.status(400).json({ message: `⛔ Product ID ${item.Product_ID} is expired.` });
            }
        }

        pool.getConnection(async (err, conn) => {
            if (err) return res.status(500).json({ message: 'Connection error' });
            try {
                await queryConn(conn, 'START TRANSACTION');

                const billResult = await queryConn(conn,
                    "INSERT INTO Bills (Customer_ID, Cashier_ID, Branch_ID, Total_Amount, Tax_Amount, Discount_Amount) VALUES (?,?,?,?,?,?)",
                    [Customer_ID || null, Cashier_ID, Branch_ID, Total_Amount, Tax_Amount, Discount_Amount]
                );
                const billId = billResult.insertId;

                for (const item of items) {
                    const stockResult = await queryConn(conn,
                        "SELECT Quantity FROM Inventory WHERE Product_ID=? AND Branch_ID=? FOR UPDATE",
                        [item.Product_ID, Branch_ID]
                    );
                    if (!stockResult.length || stockResult[0].Quantity < item.Quantity) throw { message: `Stock issues for ID: ${item.Product_ID}` };

                    const priceSnap = await queryConn(conn,
                        `SELECT Cost_Price FROM Product_Prices WHERE Product_ID = ? ORDER BY Effective_Date DESC LIMIT 1`,
                        [item.Product_ID]
                    );
                    const costAtSale = priceSnap.length ? priceSnap[0].Cost_Price : null;

                    await queryConn(conn,
                        "INSERT INTO Bill_Items (Bill_ID, Product_ID, Quantity, Unit_Price, Cost_Price_At_Sale, Total_Price) VALUES (?,?,?,?,?,?)",
                        [billId, item.Product_ID, item.Quantity, item.Unit_Price, costAtSale, item.Total_Price]
                    );

                    await queryConn(conn,
                        "UPDATE Inventory SET Quantity=Quantity-? WHERE Product_ID=? AND Branch_ID=?",
                        [item.Quantity, item.Product_ID, Branch_ID]
                    );

                    await queryConn(conn,
                        "INSERT INTO Stock_Movements (Product_ID, Branch_ID, Quantity_Out, Reason, Reference_Type, Reference_ID) VALUES (?,?,?,'SALE','BILL',?)",
                        [item.Product_ID, Branch_ID, item.Quantity, billId]
                    );
                }

                if (Customer_ID) {
                    await queryConn(conn, "UPDATE Customers SET Loyalty_Points = Loyalty_Points + ? WHERE Customer_ID = ?", [Math.floor(Total_Amount / 100), Customer_ID]);
                }

                await queryConn(conn, 'COMMIT');
                await auditLog(Cashier_ID, `Bill #${billId} created`, 'Bills', billId, getIp(req));
                res.status(201).json({ message: '🧾 Bill Completed', billId });
            } catch (error) {
                await queryConn(conn, 'ROLLBACK');
                res.status(400).json({ message: error.message || 'Billing failed' });
            } finally {
                conn.release();
            }
        });
    }
);

app.get(
    '/api/bill/:id',
    authenticateToken,
    async (req, res) => {
        try {
            const bill = await query(
                `SELECT b.*, c.Name AS Customer_Name, m.Name AS Cashier_Name, br.Name AS Branch_Name
                 FROM Bills b
                 LEFT JOIN Customers c ON b.Customer_ID = c.Customer_ID
                 JOIN Members m ON b.Cashier_ID = m.Member_ID
                 JOIN Branches br ON b.Branch_ID = br.Branch_ID
                 WHERE b.Bill_ID = ?`, [req.params.id]
            );
            if (!bill.length) return res.status(404).json({ message: 'Bill not found' });
            const items = await query(
                `SELECT bi.*, p.Name, p.Barcode, p.Unit
                 FROM Bill_Items bi
                 JOIN Products p ON bi.Product_ID = p.Product_ID
                 WHERE bi.Bill_ID = ?`, [req.params.id]
            );
            const payments = await query("SELECT * FROM Payments WHERE Bill_ID = ?", [req.params.id]);
            res.json({ bill: bill[0], items, payments });
        } catch (err) { res.status(500).json({ message: 'Server error' }); }
    }
);

// ===============================
// 💳 PAYMENTS & 🔁 RETURNS
// ===============================
app.post('/api/payments', authenticateToken, authorizeRoles('Admin', 'Cashier', 'Sales Manager'), validate(schemas.payment), async (req, res) => {
    try {
        const { Bill_ID, Method, Amount, Loan_Name, Loan_Phone_Number } = req.body;
        const bill = await query("SELECT Bill_ID FROM Bills WHERE Bill_ID = ?", [Bill_ID]);
        if (!bill.length) {
            return res.status(404).json({ message: 'Bill not found' });
        }
        await query(
            "INSERT INTO Payments (Bill_ID, Method, Amount, Loan_Name, Loan_Phone_Number, Cashier_ID) VALUES (?,?,?,?,?,?)",
            [Bill_ID, Method, Amount, Loan_Name || null, Loan_Phone_Number || null, req.user.id]
        );
        await auditLog(req.user.id, `Payment recorded — Bill: ${Bill_ID}, Method: ${Method}`);
        res.status(201).json({ message: '💳 Payment Saved' });
    } catch (err) { res.status(500).json({ message: 'Server error' }); }
});

// ==========================================
// 📦 PRO MASTER RECEIVE (GRN / STOCK IN) - SMART BATCHING
// ==========================================



// ===============================
// 📊 DASHBOARD & REPORTS
// ===============================
app.post(
    '/api/returns',
    authenticateToken,
    authorizeRoles('Admin', 'Cashier', 'Sales Manager'),
    validate(schemas.returns),
    async (req, res) => {
        const { Bill_ID, Product_ID, Quantity, Reason, Refund_Amount, Branch_ID, Payment_Method } = req.body;

        pool.getConnection(async (err, conn) => {
            if (err) return res.status(500).json({ message: 'Connection error' });

            try {
                await queryConn(conn, 'START TRANSACTION');

                const billItem = await queryConn(
                    conn,
                    "SELECT Quantity FROM Bill_Items WHERE Bill_ID = ? AND Product_ID = ?",
                    [Bill_ID, Product_ID]
                );
                if (!billItem.length) throw new Error('Bill item not found');
                if (Quantity > billItem[0].Quantity) throw new Error('Return quantity exceeds sold quantity');

                const paymentResult = await queryConn(
                    conn,
                    "INSERT INTO Payments (Bill_ID, Method, Amount, Cashier_ID) VALUES (?, ?, ?, ?)",
                    [Bill_ID, Payment_Method, Refund_Amount, req.user.id]
                );

                const returnResult = await queryConn(
                    conn,
                    "INSERT INTO Returns (Bill_ID, Product_ID, Quantity, Reason, Refund_Amount, Payment_ID, Cashier_ID, Branch_ID) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    [Bill_ID, Product_ID, Quantity, Reason || null, Refund_Amount, paymentResult.insertId, req.user.id, Branch_ID]
                );

                await queryConn(
                    conn,
                    `INSERT INTO Inventory (Product_ID, Branch_ID, Quantity)
                     VALUES (?, ?, ?)
                     ON DUPLICATE KEY UPDATE Quantity = Quantity + VALUES(Quantity)`,
                    [Product_ID, Branch_ID, Quantity]
                );

                await queryConn(
                    conn,
                    "INSERT INTO Stock_Movements (Product_ID, Branch_ID, Quantity_In, Reason, Reference_Type, Reference_ID) VALUES (?,?,?,'RETURN','RETURN',?)",
                    [Product_ID, Branch_ID, Quantity, returnResult.insertId]
                );

                await queryConn(conn, 'COMMIT');
                await auditLog(req.user.id, `Return processed for bill ${Bill_ID}`, 'Returns', returnResult.insertId, getIp(req));
                res.status(201).json({ message: 'Return processed' });
            } catch (error) {
                await queryConn(conn, 'ROLLBACK');
                res.status(400).json({ message: error.message || 'Return failed' });
            } finally {
                conn.release();
            }
        });
    }
);

app.get('/api/dashboard/sales', authenticateToken, async (req, res) => {
    try {
        let sql = `SELECT b.Branch_ID, br.Name AS Branch_Name, SUM(b.Total_Amount) AS Total_Sales, SUM(b.Tax_Amount) AS Total_Tax, COUNT(*) AS Total_Bills, DATE(b.Created_At) AS Sale_Date FROM Bills b JOIN Branches br ON b.Branch_ID = br.Branch_ID`;
        const params = [];
        if (req.user.branchId) {
            sql += ` WHERE b.Branch_ID = ?`;
            params.push(req.user.branchId);
        }
        sql += ` GROUP BY b.Branch_ID, DATE(b.Created_At) ORDER BY Sale_Date DESC`;
        const result = await query(sql, params);
        res.json(result);
    } catch (err) { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/dashboard/lowstock', authenticateToken, async (req, res) => {
    try {
        let sql = `SELECT p.Name, p.Barcode, i.Quantity, br.Name AS Branch_Name FROM Inventory i JOIN Products p ON i.Product_ID = p.Product_ID JOIN Branches br ON i.Branch_ID = br.Branch_ID WHERE i.Quantity <= 5 AND p.Is_Deleted = FALSE`;
        const params = [];
        if (req.user.branchId) {
            sql += ` AND i.Branch_ID = ?`;
            params.push(req.user.branchId);
        }
        const result = await query(sql, params);
        res.json(result);
    } catch (err) { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/dashboard/expiry', authenticateToken, async (req, res) => {
    try {
        const result = await query(`SELECT p.Name, i.Quantity, i.Expire_Date, br.Name AS Branch_Name FROM Inventory i JOIN Products p ON i.Product_ID = p.Product_ID JOIN Branches br ON i.Branch_ID = br.Branch_ID WHERE i.Expire_Date <= DATE_ADD(CURDATE(), INTERVAL 30 DAY) AND p.Is_Deleted = FALSE ORDER BY i.Expire_Date ASC`);
        res.json(result);
    } catch (err) { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/dashboard/topselling', authenticateToken, async (req, res) => {
    try {
        const result = await query(`SELECT p.Name, SUM(bi.Quantity) AS Total_Sold, SUM(bi.Total_Price) AS Total_Revenue FROM Bill_Items bi JOIN Products p ON bi.Product_ID = p.Product_ID GROUP BY p.Product_ID ORDER BY Total_Sold DESC LIMIT 20`);
        res.json(result);
    } catch (err) { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/dashboard/profit', authenticateToken, authorizeRoles('Admin', 'Branch Manager'), async (req, res) => {
    try {
        const result = await query(`SELECT p.Name, SUM(bi.Total_Price) AS Revenue, SUM(bi.Quantity * bi.Cost_Price_At_Sale) AS Cost, (SUM(bi.Total_Price) - SUM(bi.Quantity * bi.Cost_Price_At_Sale)) AS Profit FROM Bill_Items bi JOIN Products p ON bi.Product_ID = p.Product_ID GROUP BY p.Product_ID ORDER BY Profit DESC`);
        res.json(result);
    } catch (err) { res.status(500).json({ message: 'Server error' }); }
});

// ===============================
// 👥 MEMBERS & 🏢 ADMIN
// ===============================
app.get('/api/members', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
    try {
        const result = await query(`SELECT m.Member_ID, m.Name, m.Email, m.Last_Login, r.Role_Name, b.Name AS Branch_Name FROM Members m JOIN Roles r ON m.Role_ID = r.Role_ID LEFT JOIN Branches b ON m.Branch_ID = b.Branch_ID WHERE m.Is_Deleted = FALSE`);
        res.json(result);
    } catch (err) { res.status(500).json({ message: 'Server error' }); }
});

app.patch('/api/members/:id/unlock', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
    try {
        await query("UPDATE Members SET Failed_Login_Attempts = 0 WHERE Member_ID = ?", [req.params.id]);
        await auditLog(req.user.id, `Unlocked account for ID: ${req.params.id}`);
        res.json({ message: 'Account unlocked' });
    } catch (err) { res.status(500).json({ message: 'Server error' }); }
});

app.delete('/api/members/:id', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
    try {
        await query("UPDATE Members SET Is_Deleted = TRUE WHERE Member_ID = ?", [req.params.id]);
        await auditLog(req.user.id, `Soft-deleted Member ID: ${req.params.id}`);
        res.json({ message: 'Member removed' });
    } catch (err) { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/audit', authenticateToken, authorizeRoles('Admin'), async (req, res) => {
    try {
        const result = await query(`SELECT al.*, m.Name AS User_Name FROM Audit_Log al LEFT JOIN Members m ON al.User_ID = m.Member_ID ORDER BY al.Timestamp DESC LIMIT 500`);
        res.json(result);
    } catch (err) { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/branches', authenticateToken, async (req, res) => {
    try {
        const result = await query("SELECT * FROM Branches WHERE Is_Deleted = FALSE");
        res.json(result);
    } catch (err) { res.status(500).json({ message: 'Server error' }); }
});


// ==========================================
// 🏭 SUPPLIERS (NEW)
// ==========================================
app.post('/api/suppliers', authenticateToken, authorizeRoles('Admin', 'Inventory Manager', 'Warehouse Manager'), validate(schemas.supplier), async (req, res) => {
    try {
        const { Name, Phone_Number, Email, Company } = req.body;
        const result = await query(
            "INSERT INTO Suppliers (Name, Phone_Number, Email, Company) VALUES (?, ?, ?, ?)",
            [Name, Phone_Number, Email || null, Company || null]
        );
        res.status(201).json({ id: result.insertId, message: '✅ Supplier Added Successfully' });
    } catch (err) { res.status(500).json({ message: 'Server error', error: err.message }); }
});

app.get('/api/suppliers', authenticateToken, authorizeRoles('Admin', 'Inventory Manager', 'Warehouse Manager', 'Branch Manager'), async (req, res) => {
    try {
        const result = await query("SELECT * FROM Suppliers WHERE Is_Deleted = FALSE ORDER BY Name");
        res.json(result);
    } catch (err) { res.status(500).json({ message: 'Server error' }); }
});

// ==========================================
// 📦 PRO MASTER RECEIVE (GRN / STOCK IN) 
// ==========================================
app.post('/api/master-receive',
    authenticateToken,
    authorizeRoles('Admin', 'Inventory Manager', 'Branch Manager'),
    validate(schemas.masterReceive),
    async (req, res) => {
    const {
        Category_ID, Barcode, Product_Name, Brand_Name, Unit_Type, Size_Weight,
        Stock_Quantity, Expire_Date, Batch_Number,
        Buying_Price, Retail_Price, Wholesale_Price,
        Total_Bill, Amount_Paid, Remaining_Due,
        Is_New_Supplier, Supplier_ID, Supplier_Name, Supplier_Phone, Supplier_Notes
    } = req.body;

    const branchId = req.user.branchId || 1;
    const userId = req.user.id;

    // Use queryConn wrapper to maintain compatibility with existing pool setup
    pool.getConnection(async (err, conn) => {
        if (err) return res.status(500).json({ message: 'Database connection error' });

        try {
            await queryConn(conn, 'START TRANSACTION');

            // 1. HANDLE SUPPLIER
            let finalSupplierId = Supplier_ID;
            if (Is_New_Supplier) {
                const supResult = await queryConn(conn,
                    "INSERT INTO Suppliers (Name, Phone_Number) VALUES (?, ?)",
                    [Supplier_Name, Supplier_Phone]
                );
                finalSupplierId = supResult.insertId;
            }

            if (!finalSupplierId) {
                throw new Error('Supplier is required');
            }

            // 🔥 2. SECURE BACKEND BARCODE CHECK
            const existingProduct = await queryConn(conn, "SELECT Product_ID FROM Products WHERE Barcode = ? FOR UPDATE", [Barcode]);
            let finalProductId;
            let isExisting = existingProduct.length > 0;

            if (isExisting) {
                // ✅ EXISTING PRODUCT -> UPDATE DETAILS
                finalProductId = existingProduct[0].Product_ID;

                await queryConn(conn,
                    "UPDATE Products SET Name=?, Brand=?, Unit=?, Description=?, Category_ID=? WHERE Product_ID=?",
                    [Product_Name, Brand_Name, Unit_Type, Size_Weight, Category_ID, finalProductId]
                );

                // Update Inventory
                await queryConn(conn, `
                    INSERT INTO Inventory (Product_ID, Branch_ID, Quantity, Expire_Date, Supplier_ID, Batch_Number) 
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON DUPLICATE KEY UPDATE 
                        Quantity = Quantity + VALUES(Quantity), 
                        Expire_Date = VALUES(Expire_Date),
                        Supplier_ID = VALUES(Supplier_ID),
                        Batch_Number = VALUES(Batch_Number)
                `, [finalProductId, branchId, Stock_Quantity, Expire_Date || null, finalSupplierId, Batch_Number]);
            } else {
                // ✅ NEW PRODUCT -> INSERT
                const prodResult = await queryConn(conn,
                    "INSERT INTO Products (Category_ID, Barcode, Name, Brand, Unit, Description) VALUES (?, ?, ?, ?, ?, ?)",
                    [Category_ID, Barcode, Product_Name, Brand_Name, Unit_Type, Size_Weight]
                );
                finalProductId = prodResult.insertId;

                // Insert Inventory
                await queryConn(conn,
                    "INSERT INTO Inventory (Product_ID, Branch_ID, Quantity, Expire_Date, Supplier_ID, Batch_Number) VALUES (?, ?, ?, ?, ?, ?)",
                    [finalProductId, branchId, Stock_Quantity, Expire_Date || null, finalSupplierId, Batch_Number]
                );
            }

            // 3. PRICING HISTORY
            await queryConn(conn,
                "INSERT INTO Product_Prices (Product_ID, Cost_Price, Sell_Price, Wholesale_Price, Effective_Date) VALUES (?, ?, ?, ?, CURDATE())",
                [finalProductId, Buying_Price, Retail_Price, Wholesale_Price || 0]
            );

            // 4. PURCHASES (Save to accounting table)
            try {
                const purchaseResult = await queryConn(conn,
                    "INSERT INTO Purchases (Supplier_ID, Total_Bill, Amount_Paid, Remaining_Due, Branch_ID) VALUES (?, ?, ?, ?, ?)",
                    [finalSupplierId, Total_Bill, Amount_Paid, Remaining_Due, branchId]
                );

                // 5. STOCK MOVEMENTS WITH REFERENCE
                await queryConn(conn,
                    "INSERT INTO Stock_Movements (Product_ID, Branch_ID, Quantity_In, Reason, Reference_Type, Reference_ID) VALUES (?, ?, ?, 'STOCK_IN', 'PURCHASE', ?)",
                    [finalProductId, branchId, Stock_Quantity, purchaseResult.insertId]
                );
            } catch (e) {
                // Fallback in case Purchases table doesn't exist, just save movement
                await queryConn(conn,
                    "INSERT INTO Stock_Movements (Product_ID, Branch_ID, Quantity_In, Reason, Reference_Type) VALUES (?, ?, ?, 'STOCK_IN', 'PURCHASE')",
                    [finalProductId, branchId, Stock_Quantity]
                );
            }

            // 6. SUPPLIER LIFETIME PURCHASE
            try {
                await queryConn(conn,
                    "UPDATE Suppliers SET Lifetime_Total_Purchase = Lifetime_Total_Purchase + ? WHERE Supplier_ID = ?",
                    [Total_Bill, finalSupplierId]
                );
            } catch (supplierUpdateError) {
                if (supplierUpdateError.code !== 'ER_BAD_FIELD_ERROR') {
                    throw supplierUpdateError;
                }
            }

            await queryConn(conn, 'COMMIT');
            await auditLog(userId, `${isExisting ? 'Updated' : 'Added'} product ${Product_Name} via GRN`, 'Inventory', null, getIp(req));

            res.status(201).json({
                message: isExisting ? '⚡ Stock Updated Successfully!' : '✅ New Product Added Successfully!',
                batch: Batch_Number
            });

        } catch (error) {
            await queryConn(conn, 'ROLLBACK');
            res.status(400).json({ message: 'Failed to save data', error: error.message });
        } finally {
            conn.release();
        }
    });
});

// ==========================================
// GET INVENTORY LIST (NEW)
// ==========================================
app.get('/api/recent-inventory', authenticateToken, async (req, res) => {
    try {
        const branchId = req.user.branchId;
        const sql = `
            SELECT p.Barcode, p.Name AS Product, pp.Cost_Price AS Cost, pp.Sell_Price AS Price, i.Quantity AS Stock, i.Batch_Number 
            FROM Products p
            JOIN Inventory i ON p.Product_ID = i.Product_ID
            LEFT JOIN Product_Prices pp ON pp.Price_ID = (
                SELECT Price_ID FROM Product_Prices WHERE Product_ID = p.Product_ID ORDER BY Effective_Date DESC LIMIT 1
            )
            ${branchId ? 'WHERE i.Branch_ID = ?' : ''}
            ORDER BY p.Product_ID DESC LIMIT 10
        `;
        const result = await query(sql, branchId ? [branchId] : []);
        res.json(result);
    } catch (err) { res.status(500).json({ message: 'Server error' }); }
});

// ==========================================
// 📦 PRO STOCK MANAGEMENT API (FOR STOCK.HTML)
// ==========================================
app.get('/api/stock-management', authenticateToken, async (req, res) => {
    try {
        const branchId = req.user.branchId;
        if (!branchId) {
            return res.status(400).json({ message: 'Branch assignment required' });
        }
        // Products, Inventory, Categories, Suppliers, Prices ඔක්කොම එකතු කරලා ගන්නවා
        const sql = `
            SELECT 
                i.Inventory_ID, i.Batch_Number, i.Expire_Date, i.Quantity AS Stock,
                p.Product_ID, p.Barcode, p.Name AS Product_Name, p.Brand, p.Description AS Size,
                c.Category_Name,
                s.Supplier_ID, s.Name AS Supplier_Name,
                pp.Cost_Price, pp.Sell_Price
            FROM Inventory i
            JOIN Products p ON i.Product_ID = p.Product_ID
            LEFT JOIN Categories c ON p.Category_ID = c.Category_ID
            LEFT JOIN Suppliers s ON i.Supplier_ID = s.Supplier_ID
            LEFT JOIN Product_Prices pp ON pp.Price_ID = (
                SELECT Price_ID FROM Product_Prices WHERE Product_ID = p.Product_ID ORDER BY Effective_Date DESC LIMIT 1
            )
            WHERE i.Branch_ID = ? AND p.Is_Deleted = FALSE
            ORDER BY i.Expire_Date ASC, p.Name ASC
        `;
        const result = await query(sql, [branchId]);
        res.json(result);
    } catch (err) {
        console.error("Stock API Error:", err);
        res.status(500).json({ message: 'Server error' });
    }
});

// ⚡ QUICK STOCK ADJUST API (For the Quick Stock Bar)
app.post('/api/stock/quick-adjust', authenticateToken, authorizeRoles('Admin', 'Inventory Manager', 'Branch Manager', 'Warehouse Manager'), validate(schemas.quickStockAdjust), async (req, res) => {
    const { Barcode, Qty, Type } = req.body; // Type = 'ADD' or 'REMOVE'
    const branchId = req.user.branchId;

    if (!branchId) {
        return res.status(400).json({ message: 'Branch assignment required' });
    }

    pool.getConnection(async (err, conn) => {
        if (err) return res.status(500).json({ message: 'Database connection error' });

        try {
            await queryConn(conn, 'START TRANSACTION');

            const prod = await queryConn(conn, "SELECT Product_ID FROM Products WHERE Barcode = ?", [Barcode]);
            if (prod.length === 0) throw new Error("Product not found in system.");
            const productId = prod[0].Product_ID;

            // Get the specific inventory record (first available batch)
            const inv = await queryConn(conn,
                "SELECT Inventory_ID, Quantity FROM Inventory WHERE Product_ID = ? AND Branch_ID = ? ORDER BY Expire_Date ASC LIMIT 1 FOR UPDATE",
                [productId, branchId]
            );

            if (inv.length === 0) throw new Error("No inventory record found.");
            const inventoryId = inv[0].Inventory_ID;

            let newQty;
            if (Type === 'ADD') {
                newQty = inv[0].Quantity + Number(Qty);
                await queryConn(conn, "INSERT INTO Stock_Movements (Product_ID, Branch_ID, Quantity_In, Reason) VALUES (?, ?, ?, 'QUICK_ADD')", [productId, branchId, Qty]);
            } else {
                if (inv[0].Quantity < Number(Qty)) throw new Error("Insufficient stock to remove.");
                newQty = inv[0].Quantity - Number(Qty);
                await queryConn(conn, "INSERT INTO Stock_Movements (Product_ID, Branch_ID, Quantity_Out, Reason) VALUES (?, ?, ?, 'QUICK_REMOVE')", [productId, branchId, Qty]);
            }

            await queryConn(conn, "UPDATE Inventory SET Quantity = ? WHERE Inventory_ID = ?", [newQty, inventoryId]);

            await queryConn(conn, 'COMMIT');
            res.json({ message: `Stock ${Type === 'ADD' ? 'Added' : 'Removed'} Successfully! ✅` });
        } catch (err) {
            await queryConn(conn, 'ROLLBACK');
            res.status(400).json({ message: err.message });
        } finally {
            conn.release();
        }
    });
});

// ===============================
// SERVER
// ===============================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Enterprise POS running on port ${PORT}`));
