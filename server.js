const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
require('dotenv').config();

const app = express();

// --- 1. Middleware Setup ---
app.use(cors()); // Allows the frontend to communicate with this backend
app.use(express.json()); // Enables the server to read JSON data from requests

// --- 2. MySQL Database Connection (Using Connection Pool) ---
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Check if the Database connection is successful
db.getConnection((err, connection) => {
    if (err) {
        console.error('❌ Database Connection Failed:', err.message);
    } else {
        console.log('✅ Successfully connected to MySQL Database (pos_db)!');
        connection.release(); // Release the connection back to the pool
    }
});

// --- 3. API Routes (Endpoints) ---

// Root Route: To verify if the server is up and running
app.get('/', (req, res) => {
    res.send('NexPOS Backend is Running Perfectly!');
});

// CREATE: Add a new product to the database
app.post('/api/products', (req, res) => {
    const { Name, Category, Brand, Description, Barcode, Unit, Image_URL } = req.body;
    const sql = `INSERT INTO Products (Name, Category, Brand, Description, Barcode, Unit, Image_URL) 
                 VALUES (?, ?, ?, ?, ?, ?, ?)`;

    db.query(sql, [Name, Category, Brand, Description, Barcode, Unit, Image_URL], (err, result) => {
        if (err) {
            console.error('Error inserting product:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.status(201).json({ message: '✅ Product added successfully!', productId: result.insertId });
    });
});

// READ: Fetch all products from the database
app.get('/api/products', (req, res) => {
    const sql = "SELECT * FROM Products";
    db.query(sql, (err, results) => {
        if (err) {
            console.error('Error fetching products:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.status(200).json(results);
    });
});

// UPDATE: Modify details of an existing product by ID
app.put('/api/products/:id', (req, res) => {
    const { id } = req.params;
    const { Name, Category, Brand, Description, Barcode, Unit, Image_URL } = req.body;
    const sql = `UPDATE Products SET Name=?, Category=?, Brand=?, Description=?, Barcode=?, Unit=?, Image_URL=? 
                 WHERE Product_ID=?`;

    db.query(sql, [Name, Category, Brand, Description, Barcode, Unit, Image_URL, id], (err, result) => {
        if (err) {
            console.error('Error updating product:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.json({ message: '✅ Product updated successfully!' });
    });
});

// DELETE: Remove a product from the database by ID
app.delete('/api/products/:id', (req, res) => {
    const { id } = req.params;
    const sql = "DELETE FROM Products WHERE Product_ID = ?";

    db.query(sql, [id], (err, result) => {
        if (err) {
            console.error('Error deleting product:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.json({ message: '🗑️ Product deleted successfully!' });
    });
});

// --- 4. Server Initialization ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 NexPOS Server is running on port ${PORT}`);
});