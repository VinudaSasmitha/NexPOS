# NexPOS - Advanced Inventory & Billing System

A comprehensive, full-stack Point of Sale (POS) and Inventory Management solution designed for retail businesses. The system uniquely supports an **Offline-First** architecture, allowing seamless billing without internet connectivity, and automatically syncs data to a secure Cloud MySQL database once back online.

## 🚀 Core Features
* **Offline-First Billing:** Uninterrupted sales using Local Database (SQLite/Local DB).
* **Cloud Synchronization:** Real-time data syncing to the master cloud database (MySQL).
* **Role-Based Access Control (RBAC):** Distinct access levels for Admin, Branch Manager, Cashier, and Inventory Manager.
* **Master Inventory Management:** Centralized product catalog, stock movements, and low-stock alerts.
* **Comprehensive Analytics:** Track sales, cash flow, and employee performance.

## 💻 Tech Stack
* **Backend:** Node.js, Express.js, RESTful APIs
* **Database:** MySQL (Cloud/Master), SQLite (Local/Offline)
* **Frontend/Desktop UI:** React.js, Electron.js (Upcoming)
