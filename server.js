require("dotenv").config();
const express = require("express");
const morgan = require("morgan");
const bodyParser = require("body-parser");
const cors = require("cors");
const { authenticate, authorize } = require("./auth");

const app = express();

// CORS configuration for frontend access
app.use(
  cors({
    origin: ["http://localhost:5173", "http://localhost:3000"],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  })
);

// Handle preflight requests for specific routes
app.options("/items", cors());
app.options("/items/:id", cors());
app.options("/me", cors());

app.use(morgan("combined"));
app.use(bodyParser.json());

// Use items.js module for item storage and logic
const itemsDb = require("./items");

// Health check (public)
app.get("/health", (req, res) => {
  res.json({ status: "UP" });
});

// CRUD routes (protected)
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

// Debug endpoint to see user info
app.get("/me", authenticate, (req, res) => {
  res.json(req.user);
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
  console.log(`Server running on port ${PORT}`);
});
