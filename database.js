// In-memory data store
const users = []; // Stores: { id, username, email, password }
const tasks = []; // Stores: { id, userId, title, description, completed, createdAt }

module.exports = { users, tasks };