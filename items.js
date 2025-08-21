// items.js
// In-memory items store and CRUD logic as a module

let items = new Map(); // id -> { id, name }
let nextId = 1;

function getAllItems() {
  return Array.from(items.values());
}

function getItem(id) {
  return items.get(id);
}

function createItem(name) {
  const id = nextId++;
  const item = { id, name };
  items.set(id, item);
  return item;
}

function updateItem(id, name) {
  if (!items.has(id)) return null;
  const updated = { id, name };
  items.set(id, updated);
  return updated;
}

function deleteItem(id) {
  if (!items.has(id)) return null;
  const deleted = items.get(id);
  items.delete(id);
  return deleted;
}

module.exports = {
  getAllItems,
  getItem,
  createItem,
  updateItem,
  deleteItem,
};
