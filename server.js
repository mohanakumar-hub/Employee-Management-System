require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcryptjs');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware configurations
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session Configuration for Authentication
app.use(session({
    secret: 'supersecretkey',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1800000 } // Session expires in 30 minutes
}));

// 1. Database Connection
mongoose.connect(process.env.MONGO_URI)
.then(() => console.log('MongoDB connected successfully!'))
.catch(err => console.error('Database connection error:', err));

// 2. Employee Schema Configuration
const employeeSchema = new mongoose.Schema({
    name: { type: String, required: [true, 'Name is required'], trim: true },
    email: { 
        type: String, 
        required: [true, 'Email is required'], 
        unique: true,
        lowercase: true,
        match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address']
    },
    position: { type: String, required: [true, 'Position is required'] },
    salary: { type: Number, required: [true, 'Salary is required'], min: [0, 'Salary cannot be negative'] }
});

const Employee = mongoose.model('Employee', employeeSchema);

// Admin Credentials
const ADMIN_USER = "admin";
const ADMIN_PASS_HASH = bcrypt.hashSync("admin123", 10);

// Authentication Routes
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (username === ADMIN_USER && bcrypt.compareSync(password, ADMIN_PASS_HASH)) {
        req.session.isAdmin = true;
        return res.status(200).json({ message: "Login successful" });
    }
    res.status(401).json({ error: "Invalid credentials" });
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// Middleware to protect API endpoints
const requireAuth = (req, res, next) => {
    if (!req.session.isAdmin) {
        return res.status(401).json({ error: "Unauthorized access denied" });
    }
    next();
};

// 3. Protected API Routes
app.post('/api/employees', requireAuth, async (req, res) => {
    try {
        const newEmployee = new Employee(req.body);
        await newEmployee.save();
        res.status(201).json({ message: 'Employee added successfully!', employee: newEmployee });
    } catch (error) {
        res.status(400).json({ error: 'Validation Error: ' + error.message });
    }
});

app.get('/api/employees', requireAuth, async (req, res) => {
    try {
        const employees = await Employee.find();
        res.json(employees);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/employees/:id', requireAuth, async (req, res) => {
    try {
        const updatedEmployee = await Employee.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });
        res.json({ message: 'Employee updated successfully!', employee: updatedEmployee });
    } catch (error) {
        res.status(400).json({ error: 'Validation Error: ' + error.message });
    }
});

app.delete('/api/employees/:id', requireAuth, async (req, res) => {
    try {
        await Employee.findByIdAndDelete(req.params.id);
        res.json({ message: 'Employee deleted successfully!' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Page Routing with Strict Protection (Fix applied here)
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/', (req, res) => {
    if (!req.session.isAdmin) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Serve other static files if needed
app.use(express.static(path.join(__dirname)));

// Start server
app.listen(PORT, () => {
    console.log(`Backend server is running on port ${PORT}`);
});