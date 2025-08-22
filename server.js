require("dotenv").config();
const express = require("express");
const morgan = require("morgan");
const bodyParser = require("body-parser");
const cors = require("cors");

// Import separated middleware
const { authenticate, authorize, addPermissions } = require("./middleware");

const app = express();

// CORS configuration for frontend access
// CORS configuration for frontend access and proxy
app.use(
  cors({
    origin: [
      "http://localhost:5173", // Your Hoppscotch frontend
      "http://localhost:5001", // Your Hoppscotch backend
      "http://localhost:3000", // This auth server
    ],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "X-Requested-With",
      "Access-Control-Allow-Origin",
      "Access-Control-Allow-Headers",
    ],
  })
);
// Handle preflight requests - fixed approach
app.use((req, res, next) => {
  if (req.method === "OPTIONS") {
    res.header("Access-Control-Allow-Origin", req.headers.origin);
    res.header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
    res.header(
      "Access-Control-Allow-Headers",
      "Content-Type,Authorization,X-Requested-With"
    );
    res.header("Access-Control-Allow-Credentials", "true");
    return res.sendStatus(200);
  }
  next();
});

app.use(morgan("combined"));
app.use(bodyParser.json());

// Use items.js module for item storage and logic
const itemsDb = require("./items");

// Health check (public)
// Health check (public)
app.get("/health", (req, res) => {
  res.json({ status: "UP", timestamp: new Date().toISOString() });
});

// Proxy endpoint for your Hoppscotch clone
app.all("/api/proxy", async (req, res) => {
  try {
    console.log("🔄 Proxy request received:", {
      method: req.method,
      url: req.body?.url,
      headers: req.body?.headers,
      body: req.body?.body,
    });

    const { url, method = "GET", headers = {}, body } = req.body;

    if (!url) {
      return res.status(400).json({ error: "URL is required" });
    }

    // Forward the request
    const axios = require("axios");
    const response = await axios({
      method,
      url,
      headers: {
        ...headers,
        // Ensure proper CORS headers are passed through
        "Access-Control-Allow-Origin": req.headers.origin,
        "Access-Control-Allow-Credentials": "true",
      },
      data: body,
      validateStatus: () => true, // Don't throw on HTTP errors
    });

    // Set CORS headers for the proxy response
    res.set({
      "Access-Control-Allow-Origin": req.headers.origin,
      "Access-Control-Allow-Credentials": "true",
      "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
      "Access-Control-Allow-Headers":
        "Content-Type,Authorization,X-Requested-With",
    });

    res.status(response.status).json(response.data);
  } catch (error) {
    console.error("❌ Proxy error:", error.message);
    res.status(500).json({
      error: "Proxy request failed",
      details: error.message,
    });
  }
});

// CRUD routes (protected) - using separated middleware
app.get("/items", authenticate, authorize("read"), (req, res) => {
  const items = itemsDb.getAllItems();
  res.status(200).json({
    success: true,
    count: items.length,
    items,
  });
});

app.get("/items/:id", authenticate, authorize("read"), (req, res) => {
  const id = Number(req.params.id);
  const item = itemsDb.getItem(id);
  if (!item) {
    return res.status(404).json({
      success: false,
      error: "Item not found",
      id,
    });
  }
  res.status(200).json({ success: true, item });
});

app.post("/items", authenticate, authorize("write"), (req, res) => {
  const name = String(req.body?.name || "").trim();
  if (!name) {
    return res.status(400).json({
      success: false,
      error: "'name' is required",
    });
  }
  const item = itemsDb.createItem(name);
  res.status(201).json({
    success: true,
    message: "Item created successfully",
    item,
  });
});

app.put("/items/:id", authenticate, authorize("write"), (req, res) => {
  const id = Number(req.params.id);
  const name = String(req.body?.name || "").trim();
  if (!name) {
    return res.status(400).json({
      success: false,
      error: "'name' is required",
    });
  }
  const updated = itemsDb.updateItem(id, name);
  if (!updated) {
    return res.status(404).json({
      success: false,
      error: "Item not found",
      id,
    });
  }
  res.status(200).json({
    success: true,
    message: "Item updated successfully",
    item: updated,
  });
});

app.delete("/items/:id", authenticate, authorize("delete"), (req, res) => {
  const id = Number(req.params.id);
  const deleted = itemsDb.deleteItem(id);
  if (!deleted) {
    return res.status(404).json({
      success: false,
      error: "Item not found",
      id,
    });
  }
  res.status(200).json({
    success: true,
    message: "Item deleted successfully",
    item: deleted,
  });
});

// Debug endpoint to see user info - with permissions
app.get("/me", authenticate, addPermissions, (req, res) => {
  res.json({
    user: req.user,
    permissions: req.userPermissions,
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(`[ERROR] ${err.message}`);
  res.status(err.status || 500).json({
    error: "Internal Server Error",
    message: process.env.NODE_ENV === "development" ? err.message : undefined,
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
});
