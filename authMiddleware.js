const jwt = require('jsonwebtoken');

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    console.log("👉 Received Auth Header:", authHeader); // Debug log

    const token = authHeader && authHeader.split(' ')[1]; // Extract Bearer token

    if (!token) {
        console.log("❌ No token found in header");
        return res.status(401).json({ error: 'Access denied. No authentication token provided.' });
    }

    try {
        const secret = process.env.JWT_SECRET || 'supersecretkey123';
        const verified = jwt.verify(token, secret);
        req.user = verified;
        next();
    } catch (err) {
        console.log("❌ JWT Verification Failed:", err.message); // Debug log
        return res.status(401).json({ error: 'Invalid or expired token.' });
    }
};

module.exports = authenticateToken;