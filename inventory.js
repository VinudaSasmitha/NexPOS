const token = localStorage.getItem('pos_token');
if (!token) window.location.href = 'login.html';

// ================= ELEMENTS =================
const el = (id) => document.getElementById(id);

const barcode = el('barcode');
const prodName = el('prodName');
const brandName = el('brandName');
const unitType = el('unitType');
const sizeWeight = el('sizeWeight');
const qty = el('qty');
const expireDate = el('expireDate');

const buyPrice = el('buyPrice');
const retailPrice = el('retailPrice');
const wholePrice = el('wholePrice');

const totalBill = el('totalBill');
const amountPaid = el('amountPaid');

const supplierSelect = el('supplierSelect');
const supName = el('supName');
const supPhone = el('supPhone');
const supNotes = el('supNotes');

const masterForm = el('masterForm');
const alertDiv = el('alertMsg');

let suppliersData = [];

// ================= SAFE JSON =================
async function safeJson(res) {
    try {
        return await res.json();
    } catch {
        return null;
    }
}

// ================= LOAD DATA =================
async function loadInitialData() {
    try {
        const res = await fetch('http://localhost:5000/api/suppliers', {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const data = await safeJson(res);
        if (!res.ok || !Array.isArray(data)) throw new Error();

        suppliersData = data;

        supplierSelect.innerHTML = '<option value="NEW">-- Create New Supplier --</option>';

        suppliersData.forEach(s => {
            const opt = document.createElement('option');
            opt.value = s.Supplier_ID;
            opt.textContent = `${s.Name || 'Unnamed'} (${s.Phone_Number || 'No Phone'})`;
            supplierSelect.appendChild(opt);
        });

        loadInventoryList();
    } catch (err) {
        showAlert("❌ Failed to load suppliers", "red");
    }
}

// ================= INVENTORY =================
async function loadInventoryList() {
    try {
        const res = await fetch('http://localhost:5000/api/recent-inventory', {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const data = await safeJson(res);
        if (!res.ok || !Array.isArray(data)) throw new Error();

        const tbody = el('inventoryTableBody');
        tbody.innerHTML = '';

        data.forEach(item => {
            const stock = +item.Stock || 0;

            tbody.innerHTML += `
                <tr>
                    <td class="p-3">${item.Barcode || '-'}</td>
                    <td class="p-3">${item.Product || '-'}</td>
                    <td class="p-3">Rs.${(+item.Cost || 0).toFixed(2)}</td>
                    <td class="p-3">Rs.${(+item.Price || 0).toFixed(2)}</td>
                    <td class="p-3 text-center ${stock < 5 ? 'text-red-500' : 'text-green-600'}">${stock}</td>
                    <td class="p-3 text-center">${item.Batch_Number || '-'}</td>
                </tr>`;
        });

    } catch {
        showAlert("❌ Inventory load failed", "red");
    }
}

// ================= CALCULATIONS =================
function calculateValues() {
    const buy = Math.max(0, +buyPrice.value || 0);
    const sell = Math.max(0, +retailPrice.value || 0);
    const quantity = Math.max(0, +qty.value || 0);
    const paid = Math.max(0, +amountPaid.value || 0);

    el('netProfitDisplay').innerText = `Rs. ${(sell - buy).toFixed(2)}`;

    const total = buy * quantity;
    totalBill.value = total.toFixed(2);

    const due = total - paid;
    el('dueDisplay').innerText = `Rs. ${due.toFixed(2)}`;
}

// events
[buyPrice, retailPrice, qty, amountPaid].forEach(e => {
    e.addEventListener('input', calculateValues);
});

// ================= SUPPLIER AUTO FILL =================
supplierSelect.addEventListener('change', () => {
    if (supplierSelect.value === "NEW") {
        supName.value = "";
        supPhone.value = "";
        supNotes.value = "";
        return;
    }

    const selected = suppliersData.find(s => String(s.Supplier_ID) === supplierSelect.value);

    if (selected) {
        supName.value = selected.Name || "";
        supPhone.value = selected.Phone_Number || "";
        supNotes.value = selected.Notes || "";
    }
});

// ================= BARCODE SCALE PARSER =================
function parseScaleBarcode(scannedCode) {
    // EAN-13 Barcode Scale Parser (Starts with 21 or 20)
    if (scannedCode.length === 13 && (scannedCode.startsWith('21') || scannedCode.startsWith('20'))) {
        const pluCode = scannedCode.substring(2, 7); // e.g. 00015
        const weightRaw = scannedCode.substring(7, 12); // e.g. 01500
        const weightKg = parseInt(weightRaw) / 1000; // 1.5 kg

        return { isScale: true, productCode: pluCode, weight: weightKg };
    }
    return { isScale: false, barcode: scannedCode };
}

// ================= AUTO PRODUCT =================
async function fetchProductData(scannedCode) {
    if (!scannedCode) return;

    const parsedData = parseScaleBarcode(scannedCode);
    // Search DB with PLU if scale barcode, else full barcode
    const searchCode = parsedData.isScale ? parsedData.productCode : parsedData.barcode;

    try {
        const res = await fetch(`http://localhost:5000/api/products/barcode/${searchCode}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!res.ok) {
            // Do not show error on new items, just let them type
            return;
        }

        const p = await safeJson(res);
        if (!p) return;

        // Show the base product code in the UI
        barcode.value = searchCode;
        prodName.value = p.Name || '';
        brandName.value = p.Brand || '';
        unitType.value = p.Unit || '';
        sizeWeight.value = p.Description || '';

        buyPrice.value = p.Cost_Price || 0;
        retailPrice.value = p.Sell_Price || 0;

        if (parsedData.isScale) {
            qty.value = parsedData.weight;
            showAlert(`⚡ Scale detected! Auto-filled weight: ${parsedData.weight} Kg`, "green");
        } else {
            showAlert("⚡ Product details auto-filled!", "green");
        }

        calculateValues();
    } catch { }
}

// 1. Mouse එක එලියෙන් ක්ලික් කරද්දී Auto-fill වෙන්න
barcode.addEventListener('blur', () => fetchProductData(barcode.value.trim()));

// 2. Scanner එකෙන් Enter එබෙද්දී Auto-fill වෙන්න
barcode.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        e.preventDefault();

        const scannedValue = barcode.value.trim();
        fetchProductData(scannedValue);

        const parsedData = parseScaleBarcode(scannedValue);
        if (!parsedData.isScale) {
            qty.focus();
        } else {
            amountPaid.focus();
        }
    }
});

// ================= BATCH =================
function generateBatch(code, date) {
    const d = new Date();

    const part = date
        ? date.replace(/-/g, '')
        : `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}`;

    return `B-${code}-${part}`;
}

// ================= SUBMIT =================
masterForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    if (!barcode.value.trim() || !prodName.value.trim() || +qty.value <= 0) {
        return showAlert("❌ Fill required fields", "red");
    }

    const total = +totalBill.value || 0;
    const paid = +amountPaid.value || 0;

    const payload = {
        Category_ID: +document.querySelector('input[name="category"]:checked').value,
        Barcode: barcode.value.trim(),
        Product_Name: prodName.value.trim(),
        Brand_Name: brandName.value.trim(),
        Unit_Type: unitType.value.trim(),
        Size_Weight: sizeWeight.value.trim(),
        Stock_Quantity: +qty.value,
        Expire_Date: expireDate.value || null,
        Batch_Number: generateBatch(barcode.value, expireDate.value),

        Buying_Price: +buyPrice.value || 0,
        Retail_Price: +retailPrice.value || 0,
        Wholesale_Price: +wholePrice.value || 0,

        Total_Bill: total,
        Amount_Paid: paid,
        Remaining_Due: total - paid,

        Is_New_Supplier: supplierSelect.value === 'NEW',
        Supplier_ID: supplierSelect.value === 'NEW' ? null : supplierSelect.value,
        Supplier_Name: supName.value.trim(),
        Supplier_Phone: supPhone.value.trim(),
        Supplier_Notes: supNotes.value.trim()
    };

    try {
        const res = await fetch('http://localhost:5000/api/master-receive', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(payload)
        });

        const data = await safeJson(res);

        if (res.ok) {
            showAlert(`✅ ${data?.message || 'Saved successfully'}`, "green");
            masterForm.reset();
            calculateValues();
            loadInitialData();
        } else {
            showAlert(data?.message || "Error", "red");
        }

    } catch {
        showAlert("❌ Server Error", "red");
    }
});

// ================= ALERT =================
function showAlert(msg, type) {
    alertDiv.classList.remove('hidden');

    alertDiv.className = `mb-6 p-4 font-bold text-center rounded ${type === "green"
        ? "bg-green-100 text-green-700"
        : "bg-red-100 text-red-700"
        }`;

    alertDiv.innerText = msg;

    setTimeout(() => {
        alertDiv.classList.add('hidden');
    }, 4000);
}

// ================= INIT =================
window.onload = () => {
    calculateValues();
    loadInitialData();
};
