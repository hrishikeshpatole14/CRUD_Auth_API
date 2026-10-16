const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const { users, tasks } = require('./database');
const authenticateToken = require('./authMiddleware');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// ==========================================
// 1. AUTHENTICATION ENDPOINTS
// ==========================================

// REGISTER USER
app.post('/api/auth/register', async (req, res) => {
    const { username, email, password } = req.body;

    // Input Validation
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields (username, email, password) are required.' });
    }

    // Check existing user
    const existingUser = users.find(u => u.email === email);
    if (existingUser) {
        return res.status(400).json({ error: 'User with this email already exists.' });
    }

    // Hash Password
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
        id: users.length + 1,
        username,
        email,
        password: hashedPassword
    };

    users.push(newUser);

    res.status(201).json({
        message: 'User registered successfully!',
        user: { id: newUser.id, username: newUser.username, email: newUser.email }
    });
});

// LOGIN USER
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    // Input Validation
    if (!email || !password) {
        return res.status(400).json({ error: 'Please provide email and password.' });
    }

    const user = users.find(u => u.email === email);
    if (!user) {
        return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(401).json({ error: 'Invalid credentials.' });
    }

    // Generate JWT Token
    const token = jwt.sign(
        { id: user.id, email: user.email },
        process.env.JWT_SECRET || 'supersecretkey123',
        { expiresIn: '1h' }
    );

    res.status(200).json({
        message: 'Login successful!',
        token
    });
});

// ==========================================
// 2. PROTECTED CRUD ENDPOINTS (TASKS)
// ==========================================

// CREATE TASK (POST)
app.post('/api/tasks', authenticateToken, (req, res) => {
    const { title, description } = req.body;

    // Input Validation
    if (!title || title.trim() === '') {
        return res.status(400).json({ error: 'Task title is required.' });
    }

    const newTask = {
        id: tasks.length + 1,
        userId: req.user.id,
        title: title.trim(),
        description: description || '',
        completed: false,
        createdAt: new Date().toISOString()
    };

    tasks.push(newTask);
    res.status(201).json(newTask);
});

// READ ALL TASKS FOR LOGGED-IN USER (GET)
app.get('/api/tasks', authenticateToken, (req, res) => {
    const userTasks = tasks.filter(t => t.userId === req.user.id);
    res.status(200).json(userTasks);
});

// READ SINGLE TASK BY ID (GET)
app.get('/api/tasks/:id', authenticateToken, (req, res) => {
    const taskId = parseInt(req.params.id);
    const task = tasks.find(t => t.id === taskId && t.userId === req.user.id);

    if (!task) {
        return res.status(404).json({ error: 'Task not found.' });
    }

    res.status(200).json(task);
});

// UPDATE TASK (PUT)
app.put('/api/tasks/:id', authenticateToken, (req, res) => {
    const taskId = parseInt(req.params.id);
    const taskIndex = tasks.findIndex(t => t.id === taskId && t.userId === req.user.id);

    if (taskIndex === -1) {
        return res.status(404).json({ error: 'Task not found.' });
    }

    const { title, description, completed } = req.body;

    // Validation
    if (title !== undefined && title.trim() === '') {
        return res.status(400).json({ error: 'Task title cannot be empty.' });
    }

    tasks[taskIndex] = {
        ...tasks[taskIndex],
        title: title !== undefined ? title.trim() : tasks[taskIndex].title,
        description: description !== undefined ? description : tasks[taskIndex].description,
        completed: completed !== undefined ? Boolean(completed) : tasks[taskIndex].completed
    };

    res.status(200).json(tasks[taskIndex]);
});

// DELETE TASK (DELETE)
app.delete('/api/tasks/:id', authenticateToken, (req, res) => {
    const taskId = parseInt(req.params.id);
    const taskIndex = tasks.findIndex(t => t.id === taskId && t.userId === req.user.id);

    if (taskIndex === -1) {
        return res.status(404).json({ error: 'Task not found.' });
    }

    tasks.splice(taskIndex, 1);
    res.status(200).json({ message: 'Task deleted successfully.' });
});

// START SERVER
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));