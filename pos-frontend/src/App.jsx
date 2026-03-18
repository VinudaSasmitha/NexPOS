import { useState, useEffect, useMemo, useCallback } from "react";
import axios from "axios";
import "./App.css";

function App() {
  const [products, setProducts] = useState([]);
  const [cart, setCart] = useState([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedCategory, setSelectedCategory] = useState("All");
  const [isLoading, setIsLoading] = useState(true);
  const [cash, setCash] = useState(0);

  const categories = ["All", "Beverages", "Snacks", "Groceries", "Personal Care"];

  // ================= LOAD CART =================
  useEffect(() => {
    const saved = localStorage.getItem("cart");
    if (saved) setCart(JSON.parse(saved));
  }, []);

  // ================= SAVE CART =================
  useEffect(() => {
    localStorage.setItem("cart", JSON.stringify(cart));
  }, [cart]);

  // ================= FETCH PRODUCTS =================
  useEffect(() => {
    const fetchProducts = async () => {
      try {
        setIsLoading(true);
        const { data } = await axios.get("http://localhost:5000/api/products");
        setProducts(data);
      } catch (err) {
        console.warn("Fallback data used");
        setProducts([
          { Product_ID: 1, Name: "Coca Cola 1.5L", Category: "Beverages", Price: 450, Barcode: "111" },
          { Product_ID: 2, Name: "Munchee Cracker", Category: "Snacks", Price: 200, Barcode: "222" },
          { Product_ID: 3, Name: "Samba Rice 5kg", Category: "Groceries", Price: 1100, Barcode: "333" },
          { Product_ID: 4, Name: "Signal Toothpaste", Category: "Personal Care", Price: 180, Barcode: "444" },
        ]);
      } finally {
        setIsLoading(false);
      }
    };

    fetchProducts();
  }, []);

  // ================= FILTER =================
  const filteredProducts = useMemo(() => {
    return products.filter((p) => {
      const name = p.Name?.toLowerCase() || "";
      return (
        name.includes(searchQuery.toLowerCase()) &&
        (selectedCategory === "All" || p.Category === selectedCategory)
      );
    });
  }, [products, searchQuery, selectedCategory]);

  // ================= CART =================
  const addToCart = useCallback((product) => {
    setCart((prev) => {
      const exist = prev.find((i) => i.Product_ID === product.Product_ID);

      if (exist) {
        return prev.map((i) =>
          i.Product_ID === product.Product_ID
            ? { ...i, qty: i.qty + 1 }
            : i
        );
      }

      return [...prev, { ...product, qty: 1 }];
    });
  }, []);

  const updateQty = (id, amount) => {
    setCart((prev) =>
      prev
        .map((item) =>
          item.Product_ID === id
            ? { ...item, qty: item.qty + amount }
            : item
        )
        .filter((item) => item.qty > 0)
    );
  };

  const removeFromCart = (id) => {
    setCart((prev) => prev.filter((i) => i.Product_ID !== id));
  };

  const clearCart = () => setCart([]);

  // ================= BARCODE =================
  const handleBarcode = (e) => {
    if (e.key === "Enter") {
      const product = products.find((p) => p.Barcode === e.target.value);
      if (product) {
        addToCart(product);
      } else {
        alert("Product not found");
      }
      e.target.value = "";
    }
  };

  // ================= CALCULATIONS =================
  const subtotal = useMemo(
    () => cart.reduce((sum, i) => sum + i.Price * i.qty, 0),
    [cart]
  );

  const tax = subtotal * 0.1;
  const total = subtotal + tax;
  const balance = cash - total;

  // ================= PRINT =================
  const handlePrint = () => {
    const receipt = `
--- NexPOS ---
${new Date().toLocaleString()}

${cart.map(i => `${i.Name} x${i.qty} = Rs.${i.Price * i.qty}`).join("\n")}

Subtotal: Rs.${subtotal.toFixed(2)}
Tax: Rs.${tax.toFixed(2)}
Total: Rs.${total.toFixed(2)}

Cash: Rs.${cash}
Balance: Rs.${balance.toFixed(2)}
`;

    const win = window.open();
    win.document.write(`<pre>${receipt}</pre>`);
    win.print();
  };

  return (
    <div className="app">

      {/* HEADER */}
      <div className="header">
        <h1>NexPOS</h1>

        <input
          placeholder="Search..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
        />

        <input
          placeholder="Scan barcode..."
          onKeyDown={handleBarcode}
        />
      </div>

      {/* CATEGORY */}
      <div className="categories">
        {categories.map((cat) => (
          <button
            key={cat}
            className={selectedCategory === cat ? "active" : ""}
            onClick={() => setSelectedCategory(cat)}
          >
            {cat}
          </button>
        ))}
      </div>

      {/* PRODUCTS */}
      {isLoading ? (
        <p>Loading...</p>
      ) : (
        <div className="products">
          {filteredProducts.map((p) => (
            <div
              key={p.Product_ID}
              className="card"
              onClick={() => addToCart(p)}
            >
              <h3>{p.Name}</h3>
              <p>{p.Category}</p>
              <strong>Rs. {p.Price}</strong>
            </div>
          ))}
        </div>
      )}

      {/* CART */}
      <div className="cart">
        <h2>Cart</h2>

        {cart.map((item) => (
          <div key={item.Product_ID} className="cart-item">
            <p>{item.Name}</p>

            <button
              onClick={(e) => {
                e.stopPropagation();
                updateQty(item.Product_ID, -1);
              }}
            >-</button>

            {item.qty}

            <button
              onClick={(e) => {
                e.stopPropagation();
                updateQty(item.Product_ID, 1);
              }}
            >+</button>

            <span>Rs. {item.Price * item.qty}</span>

            <button onClick={() => removeFromCart(item.Product_ID)}>X</button>
          </div>
        ))}

        <hr />

        <p>Subtotal: Rs. {subtotal.toFixed(2)}</p>
        <p>Tax: Rs. {tax.toFixed(2)}</p>
        <h3>Total: Rs. {total.toFixed(2)}</h3>

        <input
          type="number"
          placeholder="Cash"
          value={cash}
          onChange={(e) => setCash(Number(e.target.value))}
        />

        <p>Balance: Rs. {balance.toFixed(2)}</p>

        <button disabled={cart.length === 0 || cash < total} onClick={handlePrint}>
          Pay & Print
        </button>

        <button onClick={clearCart}>Clear</button>
      </div>
    </div>
  );
}

export default App;