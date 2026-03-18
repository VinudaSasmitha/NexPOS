// ===============================
// IMPORTS
// ===============================
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// ===============================
// DB CONNECTION (POOL)
// ===============================
const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'pos_system',
    connectionLimit: 10
});

const SECRET = process.env.JWT_SECRET || "supersecret";

// ===============================
// AUTH MIDDLEWARE
// ===============================
function authenticateToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// ===============================
// ROOT
// ===============================
app.get('/', (req, res) => {
    res.send('🚀 PRODUCTION POS BACKEND RUNNING');
});


// ===============================
// 🔐 REGISTER
// ===============================
app.post('/api/register', async (req, res) => {
    try {
        const { Name, Email, Password, Role_ID } = req.body;

        const hashedPassword = await bcrypt.hash(Password, 10);

        db.query(
            "INSERT INTO Members (Name, Email, Password, Role_ID) VALUES (?, ?, ?, ?)",
            [Name, Email, hashedPassword, Role_ID],
            (err) => {
                if (err) return res.status(500).json(err);
                res.json({ message: "✅ User Registered" });
            }
        );
    } catch (err) {
        res.status(500).json(err);
    }
});


// ===============================
// 🔐 LOGIN
// ===============================
app.post('/api/login', (req, res) => {
    const { Email, Password } = req.body;

    db.query(
        "SELECT * FROM Members WHERE Email=?",
        [Email],
        async (err, result) => {
            if (err) return res.status(500).json(err);
            if (result.length === 0)
                return res.status(401).json({ message: "Invalid login" });

            const user = result[0];
            const match = await bcrypt.compare(Password, user.Password);

            if (!match)
                return res.status(401).json({ message: "Invalid login" });

            const token = jwt.sign(
                { id: user.Member_ID, role: user.Role_ID },
                SECRET,
                { expiresIn: "8h" }
            );

            res.json({ token, user });
        }
    );
});


// ===============================
// 👤 CUSTOMERS
// ===============================
app.post('/api/customers', authenticateToken, (req, res) => {
    const { Name, Phone_Number, Email, Address } = req.body;

    db.query(
        "INSERT INTO Customers (Name, Phone_Number, Email, Address) VALUES (?, ?, ?, ?)",
        [Name, Phone_Number, Email, Address],
        (err, result) => {
            if (err) return res.status(500).json(err);
            res.json({ id: result.insertId });
        }
    );
});

app.get('/api/customers', authenticateToken, (req, res) => {
    db.query("SELECT * FROM Customers", (err, result) => {
        if (err) return res.status(500).json(err);
        res.json(result);
    });
});


// ===============================
// 📦 PRODUCTS
// ===============================
app.post('/api/products', authenticateToken, (req, res) => {
    const { Name, Category_ID, Brand, Description, Barcode, Unit } = req.body;

    db.query(
        "INSERT INTO Products (Name, Category_ID, Brand, Description, Barcode, Unit) VALUES (?, ?, ?, ?, ?, ?)",
        [Name, Category_ID, Brand, Description, Barcode, Unit],
        (err, result) => {
            if (err) return res.status(500).json(err);
            res.json({ id: result.insertId });
        }
    );
});


// ===============================
// 💰 PRICE
// ===============================
app.post('/api/prices', authenticateToken, (req, res) => {
    const { Product_ID, Cost_Price, Sell_Price, Wholesale_Price } = req.body;

    db.query(
        "INSERT INTO Product_Prices (Product_ID, Cost_Price, Sell_Price, Wholesale_Price, Effective_Date) VALUES (?, ?, ?, ?, CURDATE())",
        [Product_ID, Cost_Price, Sell_Price, Wholesale_Price],
        (err) => {
            if (err) return res.status(500).json(err);
            res.json({ message: "💰 Price Added" });
        }
    );
});


// ===============================
// 📦 INVENTORY (UPSERT)
// ===============================
app.post('/api/inventory', authenticateToken, (req, res) => {
    const { Product_ID, Warehouse_ID, Branch_ID, Quantity } = req.body;

    const sql = `
        INSERT INTO Inventory (Product_ID, Warehouse_ID, Branch_ID, Quantity)
        VALUES (?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE Quantity = Quantity + VALUES(Quantity)
    `;

    db.query(sql, [Product_ID, Warehouse_ID, Branch_ID, Quantity], (err) => {
        if (err) return res.status(500).json(err);
        res.json({ message: "📦 Stock Updated" });
    });
});


// ===============================
// 🧾 BILLING (TRANSACTION SAFE)
// ===============================
app.post('/api/bill', authenticateToken, (req, res) => {
    const { Customer_ID, Cashier_ID, Branch_ID, items, Total_Amount } = req.body;

    db.getConnection((err, conn) => {
        if (err) return res.status(500).json(err);

        conn.beginTransaction(err => {
            if (err) return res.status(500).json(err);

            conn.query(
                "INSERT INTO Bills (Customer_ID, Cashier_ID, Branch_ID, Total_Amount) VALUES (?, ?, ?, ?)",
                [Customer_ID, Cashier_ID, Branch_ID, Total_Amount],
                (err, result) => {
                    if (err) return conn.rollback(() => res.status(500).json(err));

                    const billId = result.insertId;

                    for (let item of items) {
                        // CHECK STOCK
                        conn.query(
                            "SELECT Quantity FROM Inventory WHERE Product_ID=? AND Branch_ID=?",
                            [item.Product_ID, Branch_ID],
                            (err, stockResult) => {
                                if (err || stockResult.length === 0)
                                    return conn.rollback(() => res.status(400).json({ message: "Stock not found" }));

                                if (stockResult[0].Quantity < item.Quantity)
                                    return conn.rollback(() => res.status(400).json({ message: "Insufficient stock" }));

                                // INSERT ITEM
                                conn.query(
                                    "INSERT INTO Bill_Items (Bill_ID, Product_ID, Quantity, Unit_Price, Total_Price) VALUES (?, ?, ?, ?, ?)",
                                    [billId, item.Product_ID, item.Quantity, item.Unit_Price, item.Total_Price]
                                );

                                // UPDATE STOCK
                                conn.query(
                                    "UPDATE Inventory SET Quantity = Quantity - ? WHERE Product_ID=? AND Branch_ID=?",
                                    [item.Quantity, item.Product_ID, Branch_ID]
                                );

                                // STOCK MOVEMENT
                                conn.query(
                                    "INSERT INTO Stock_Movements (Product_ID, Branch_ID, Quantity_Out, Reason) VALUES (?, ?, ?, 'SALE')",
                                    [item.Product_ID, Branch_ID, item.Quantity]
                                );
                            }
                        );
                    }

                    conn.commit(err => {
                        if (err) return conn.rollback(() => res.status(500).json(err));
                        res.json({ message: "🧾 Bill Completed" });
                    });
                }
            );
        });
    });
});


// ===============================
// 💳 PAYMENTS
// ===============================
app.post('/api/payments', authenticateToken, (req, res) => {
    const { Bill_ID, Method, Amount } = req.body;

    db.query(
        "INSERT INTO Payments (Bill_ID, Method, Amount) VALUES (?, ?, ?)",
        [Bill_ID, Method, Amount],
        (err) => {
            if (err) return res.status(500).json(err);
            res.json({ message: "💳 Payment Saved" });
        }
    );
});


// ===============================
// 🔁 RETURNS
// ===============================
app.post('/api/returns', authenticateToken, (req, res) => {
    const { Bill_ID, Product_ID, Quantity, Refund_Amount, Branch_ID } = req.body;

    db.query(
        "INSERT INTO Returns (Bill_ID, Product_ID, Quantity, Refund_Amount) VALUES (?, ?, ?, ?)",
        [Bill_ID, Product_ID, Quantity, Refund_Amount],
        (err) => {
            if (err) return res.status(500).json(err);

            // ADD STOCK BACK
            db.query(
                "UPDATE Inventory SET Quantity = Quantity + ? WHERE Product_ID=? AND Branch_ID=?",
                [Quantity, Product_ID, Branch_ID]
            );

            // LOG
            db.query(
                "INSERT INTO Stock_Movements (Product_ID, Branch_ID, Quantity_In, Reason) VALUES (?, ?, ?, 'RETURN')",
                [Product_ID, Branch_ID, Quantity]
            );

            res.json({ message: "↩️ Return Processed" });
        }
    );
});


// ===============================
// SERVER
// ===============================
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`🚀 POS running on ${PORT}`);
});
