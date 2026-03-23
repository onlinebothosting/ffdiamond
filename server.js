const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const session = require('express-session');
const dotenv = require('dotenv');
const path = require('path');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');

dotenv.config();

const app = express();

// Security Middleware
app.use(helmet({ contentSecurityPolicy: false }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { success: false, message: 'Too many requests!' }
});
app.use('/api/', limiter);

// CORS
app.use(cors({
    origin: ['http://localhost:3000'],
    credentials: true
}));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Session - FIXED
app.use(session({
    secret: process.env.SESSION_SECRET || 'mysecretkey123',
    resave: true,
    saveUninitialized: true,
    cookie: {
        secure: false,
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000,
        sameSite: 'lax'
    }
}));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
.then(() => console.log('🔥 MongoDB Connected'))
.catch(err => console.error('MongoDB Error:', err));

// ==================== MODELS ====================

// User Schema (NEW)
const UserSchema = new mongoose.Schema({
    uid: { type: String, required: true, unique: true, trim: true },
    gameName: { type: String, required: true, trim: true },
    recoveryEmail: { type: String, required: true, trim: true, lowercase: true },
    password: { type: String }, // optional password
    hasPassword: { type: Boolean, default: false },
    totalDiamondsClaimed: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
    lastLogin: { type: Date },
    isActive: { type: Boolean, default: true }
});

const User = mongoose.model('User', UserSchema);

// Claim Schema (updated with userId)
const ClaimSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    uid: { type: String, required: true, trim: true },
    gameName: { type: String, required: true, trim: true },
    recoveryEmail: { type: String, required: true, trim: true, lowercase: true },
    server: { type: String, required: true, default: 'IND' },
    diamondAmount: { type: Number, required: true },
    diamondIcon: { type: String },
    ipAddress: { type: String },
    userAgent: { type: String },
    sessionId: { type: String },
    status: { type: String, enum: ['pending', 'processing', 'completed', 'failed'], default: 'pending' },
    claimedAt: { type: Date, default: Date.now }
});

const Claim = mongoose.model('Claim', ClaimSchema);

// Diamond Pack Schema
const DiamondPackSchema = new mongoose.Schema({
    id: { type: Number, required: true, unique: true },
    amount: { type: Number, required: true },
    icon: { type: String, required: true },
    stock: { type: Number, default: 100 },
    tag: { type: String, default: null },
    color: { type: String, default: 'gold' },
    price: { type: String, default: 'Free' },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const DiamondPack = mongoose.model('DiamondPack', DiamondPackSchema);

// Admin Log Schema
const AdminLogSchema = new mongoose.Schema({
    username: { type: String, required: true },
    action: { type: String },
    details: { type: Object },
    ipAddress: { type: String },
    userAgent: { type: String },
    timestamp: { type: Date, default: Date.now }
});

const AdminLog = mongoose.model('AdminLog', AdminLogSchema);

// ==================== INITIALIZE ====================
async function initializeDiamondPacks() {
    const count = await DiamondPack.countDocuments();
    if (count === 0) {
        const defaultPacks = [
            { id: 1, amount: 100, icon: '💎', stock: 48, tag: null, color: 'cyan', price: 'Free', isActive: true },
            { id: 2, amount: 310, icon: '💎💎', stock: 35, tag: null, color: 'gold', price: 'Free', isActive: true },
            { id: 3, amount: 520, icon: '💎💎💎', stock: 28, tag: 'POPULAR', color: 'purple', price: 'Free', isActive: true },
            { id: 4, amount: 1060, icon: '🔷💎🔷', stock: 18, tag: null, color: 'gold', price: 'Free', isActive: true },
            { id: 5, amount: 2180, icon: '👑💎', stock: 12, tag: 'HOT', color: 'pink', price: 'Free', isActive: true },
            { id: 6, amount: 5600, icon: '🔥👑💎', stock: 5, tag: 'ELITE', color: 'purple', price: 'Free', isActive: true }
        ];
        await DiamondPack.insertMany(defaultPacks);
        console.log('✅ Default diamond packs initialized');
    }
}

mongoose.connection.once('open', () => {
    initializeDiamondPacks();
});

// ==================== MIDDLEWARE ====================
const requireAdmin = async (req, res, next) => {
    if (!req.session.admin) {
        return res.status(401).json({ success: false, message: 'Unauthorized access' });
    }
    next();
};

const requireUser = async (req, res, next) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Please login first' });
    }
    next();
};

// ==================== USER AUTH ROUTES ====================

// User Login/Register (by UID)
app.post('/api/user/login', async (req, res) => {
    try {
        const { uid, gameName, recoveryEmail, password } = req.body;
        
        if (!uid) {
            return res.status(400).json({ success: false, message: 'UID is required!' });
        }
        
        // Check if user exists
        let user = await User.findOne({ uid: uid });
        
        if (!user) {
            // Create new user if doesn't exist
            if (!gameName || !recoveryEmail) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'New user! Please fill all fields.' 
                });
            }
            
            user = new User({
                uid: uid,
                gameName: gameName,
                recoveryEmail: recoveryEmail,
                password: password ? await bcrypt.hash(password, 10) : null,
                hasPassword: !!password,
                lastLogin: new Date()
            });
            await user.save();
        } else {
            // Existing user - update last login
            user.lastLogin = new Date();
            await user.save();
            
            // If password is set and provided, verify
            if (user.hasPassword && password) {
                const isValid = await bcrypt.compare(password, user.password);
                if (!isValid) {
                    return res.status(401).json({ success: false, message: 'Invalid password!' });
                }
            } else if (user.hasPassword && !password) {
                return res.status(401).json({ 
                    success: false, 
                    message: 'This account has password protection. Please enter password!' 
                });
            }
        }
        
        // Set session
        req.session.userId = user._id;
        req.session.userUid = user.uid;
        req.session.userGameName = user.gameName;
        
        req.session.save((err) => {
            if (err) {
                return res.status(500).json({ success: false, message: 'Session error' });
            }
            res.json({ 
                success: true, 
                message: 'Login successful!',
                user: {
                    uid: user.uid,
                    gameName: user.gameName,
                    hasPassword: user.hasPassword
                }
            });
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Server error!' });
    }
});

// User logout
app.post('/api/user/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// Check user session
app.get('/api/user/check', (req, res) => {
    res.json({ 
        isLoggedIn: !!req.session.userId,
        user: req.session.userId ? {
            uid: req.session.userUid,
            gameName: req.session.userGameName
        } : null
    });
});

// Get user dashboard data
app.get('/api/user/dashboard', requireUser, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        // Get user's claims
        const claims = await Claim.find({ uid: user.uid }).sort({ claimedAt: -1 });
        
        // Get stats
        const stats = {
            totalClaims: claims.length,
            totalDiamonds: claims.reduce((sum, c) => sum + c.diamondAmount, 0),
            pendingClaims: claims.filter(c => c.status === 'pending').length,
            completedClaims: claims.filter(c => c.status === 'completed').length,
            lastClaim: claims[0]?.claimedAt || null
        };
        
        res.json({ 
            success: true, 
            user: {
                uid: user.uid,
                gameName: user.gameName,
                recoveryEmail: user.recoveryEmail,
                hasPassword: user.hasPassword,
                totalDiamondsClaimed: user.totalDiamondsClaimed,
                createdAt: user.createdAt,
                lastLogin: user.lastLogin
            },
            claims,
            stats
        });
        
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Set/Update user password
app.post('/api/user/set-password', requireUser, async (req, res) => {
    try {
        const { password } = req.body;
        
        if (!password || password.length < 4) {
            return res.status(400).json({ success: false, message: 'Password must be at least 4 characters' });
        }
        
        const user = await User.findById(req.session.userId);
        user.password = await bcrypt.hash(password, 10);
        user.hasPassword = true;
        await user.save();
        
        res.json({ success: true, message: 'Password set successfully!' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ==================== CLAIM ROUTES (Updated) ====================

// Submit claim (with user association)
app.post('/api/claim', async (req, res) => {
    try {
        const { uid, gameName, recoveryEmail, server, diamondAmount, diamondIcon } = req.body;
        
        // Validation
        if (!uid || !gameName || !recoveryEmail || !diamondAmount) {
            return res.status(400).json({ success: false, message: 'All fields are required!' });
        }
        
        if (!/^\d{8,12}$/.test(uid)) {
            return res.status(400).json({ success: false, message: 'Invalid UID! Must be 8-12 digits.' });
        }
        
        
        // Check for duplicate claims
        const existingClaim = await Claim.findOne({
            uid: uid,
            claimedAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
        });
        
        if (existingClaim) {
            return res.status(400).json({ 
                success: false, 
                message: 'You have already claimed diamonds in the last 24 hours!' 
            });
        }
        
        // Reduce stock
        const pack = await DiamondPack.findOne({ amount: parseInt(diamondAmount) });
        if (pack && pack.stock > 0) {
            pack.stock -= 1;
            await pack.save();
        }
        
        // Find or create user
        let user = await User.findOne({ uid: uid });
        if (!user) {
            user = new User({
                uid: uid,
                gameName: gameName,
                recoveryEmail: recoveryEmail,
                hasPassword: false
            });
            await user.save();
        }
        
        // Update user total diamonds
        user.totalDiamondsClaimed += parseInt(diamondAmount);
        await user.save();
        
        // Save claim
        const claim = new Claim({
            userId: user._id,
            uid,
            gameName,
            recoveryEmail,
            server: server || 'IND',
            diamondAmount: parseInt(diamondAmount),
            diamondIcon: diamondIcon || '💎',
            ipAddress: req.ip || req.headers['x-forwarded-for'],
            userAgent: req.headers['user-agent'],
            sessionId: req.sessionID,
            status: 'pending'
        });
        
        await claim.save();
        
        // Auto login after claim
        req.session.userId = user._id;
        req.session.userUid = user.uid;
        req.session.userGameName = user.gameName;
        
        req.session.save();
        
        res.json({ 
            success: true, 
            message: `✅ Success! ${diamondAmount} Diamonds claimed!`,
            claimId: claim._id,
            redirectTo: '/user-dashboard.html'
        });
        
    } catch (error) {
        console.error('Claim Error:', error);
        res.status(500).json({ success: false, message: 'Server error!' });
    }
});

// ==================== ADMIN ROUTES (Same as before) ====================
// ... (keep all existing admin routes)
// Get diamond packs (public)
app.get('/api/packs', async (req, res) => {
    try {
        const packs = await DiamondPack.find({ isActive: true }).sort({ amount: 1 });
        res.json({ success: true, packs });
    } catch (error) {
        const fallbackPacks = [
            { id: 1, amount: 100, icon: '💎', stock: 48, tag: null, color: 'cyan', price: 'Free' },
            { id: 2, amount: 310, icon: '💎💎', stock: 35, tag: null, color: 'gold', price: 'Free' },
            { id: 3, amount: 520, icon: '💎💎💎', stock: 28, tag: 'POPULAR', color: 'purple', price: 'Free' },
            { id: 4, amount: 1060, icon: '🔷💎🔷', stock: 18, tag: null, color: 'gold', price: 'Free' },
            { id: 5, amount: 2180, icon: '👑💎', stock: 12, tag: 'HOT', color: 'pink', price: 'Free' },
            { id: 6, amount: 5600, icon: '🔥👑💎', stock: 5, tag: 'ELITE', color: 'purple', price: 'Free' }
        ];
        res.json({ success: true, packs: fallbackPacks });
    }
});

// Admin: Get all diamond packs
app.get('/api/admin/packs', requireAdmin, async (req, res) => {
    try {
        const packs = await DiamondPack.find().sort({ amount: 1 });
        res.json({ success: true, packs });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Admin: Add new diamond pack
app.post('/api/admin/packs', requireAdmin, async (req, res) => {
    try {
        const { amount, icon, stock, tag, color, price } = req.body;
        
        if (!amount || !icon) {
            return res.status(400).json({ success: false, message: 'Amount and icon are required!' });
        }
        
        const lastPack = await DiamondPack.findOne().sort({ id: -1 });
        const newId = lastPack ? lastPack.id + 1 : 7;
        
        const newPack = new DiamondPack({
            id: newId,
            amount: parseInt(amount),
            icon,
            stock: stock || 100,
            tag: tag || null,
            color: color || 'gold',
            price: price || 'Free',
            isActive: true
        });
        
        await newPack.save();
        
        await AdminLog.create({
            username: req.session.adminUsername,
            action: 'add_diamond',
            details: { amount, icon, stock },
            ipAddress: req.ip
        });
        
        res.json({ success: true, pack: newPack, message: 'Diamond pack added!' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Admin: Update diamond pack
app.put('/api/admin/packs/:id', requireAdmin, async (req, res) => {
    try {
        const packId = parseInt(req.params.id);
        const { amount, icon, stock, tag, color, price, isActive } = req.body;
        
        const pack = await DiamondPack.findOne({ id: packId });
        if (!pack) {
            return res.status(404).json({ success: false, message: 'Pack not found' });
        }
        
        if (amount) pack.amount = parseInt(amount);
        if (icon) pack.icon = icon;
        if (stock !== undefined) pack.stock = parseInt(stock);
        if (tag !== undefined) pack.tag = tag;
        if (color) pack.color = color;
        if (price) pack.price = price;
        if (isActive !== undefined) pack.isActive = isActive;
        pack.updatedAt = new Date();
        
        await pack.save();
        
        await AdminLog.create({
            username: req.session.adminUsername,
            action: 'edit_diamond',
            details: { id: packId, amount, stock },
            ipAddress: req.ip
        });
        
        res.json({ success: true, pack, message: 'Diamond pack updated!' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Admin: Delete diamond pack
app.delete('/api/admin/packs/:id', requireAdmin, async (req, res) => {
    try {
        const packId = parseInt(req.params.id);
        const pack = await DiamondPack.findOneAndDelete({ id: packId });
        
        if (!pack) {
            return res.status(404).json({ success: false, message: 'Pack not found' });
        }
        
        await AdminLog.create({
            username: req.session.adminUsername,
            action: 'delete_diamond',
            details: { id: packId, amount: pack.amount },
            ipAddress: req.ip
        });
        
        res.json({ success: true, message: 'Diamond pack deleted!' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Admin login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
            req.session.admin = true;
            req.session.adminUsername = username;
            
            req.session.save((err) => {
                if (err) {
                    return res.status(500).json({ success: false, message: 'Session error' });
                }
                
                AdminLog.create({
                    username,
                    action: 'login',
                    ipAddress: req.ip,
                    userAgent: req.headers['user-agent']
                }).catch(console.error);
                
                res.json({ success: true, message: 'Login successful!' });
            });
        } else {
            res.status(401).json({ success: false, message: 'Invalid credentials!' });
        }
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error!' });
    }
});

app.post('/api/admin/logout', async (req, res) => {
    if (req.session.admin) {
        await AdminLog.create({
            username: req.session.adminUsername,
            action: 'logout',
            ipAddress: req.ip
        }).catch(console.error);
    }
    req.session.destroy();
    res.json({ success: true });
});

app.get('/api/admin/check', (req, res) => {
    res.json({ isAdmin: req.session.admin === true });
});

app.get('/api/admin/claims', requireAdmin, async (req, res) => {
    try {
        const claims = await Claim.find().sort({ claimedAt: -1 });
        
        await AdminLog.create({
            username: req.session.adminUsername,
            action: 'view_claims',
            ipAddress: req.ip
        }).catch(console.error);
        
        const stats = {
            total: claims.length,
            today: claims.filter(c => c.claimedAt.toDateString() === new Date().toDateString()).length,
            thisWeek: claims.filter(c => c.claimedAt >= new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)).length,
            byDiamond: {},
            byServer: {}
        };
        
        claims.forEach(claim => {
            const amount = claim.diamondAmount.toString();
            stats.byDiamond[amount] = (stats.byDiamond[amount] || 0) + 1;
            stats.byServer[claim.server] = (stats.byServer[claim.server] || 0) + 1;
        });
        
        res.json({ success: true, claims, stats });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.put('/api/admin/claims/:id/status', requireAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        const claim = await Claim.findByIdAndUpdate(req.params.id, { status }, { new: true });
        
        if (!claim) {
            return res.status(404).json({ success: false, message: 'Claim not found' });
        }
        
        res.json({ success: true, claim });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.delete('/api/admin/claims/:id', requireAdmin, async (req, res) => {
    try {
        await Claim.findByIdAndDelete(req.params.id);
        res.json({ success: true, message: 'Claim deleted' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/admin/logs', requireAdmin, async (req, res) => {
    try {
        const logs = await AdminLog.find().sort({ timestamp: -1 }).limit(100);
        res.json({ success: true, logs });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
    try {
        const users = await User.find().sort({ createdAt: -1 });
        res.json({ success: true, users });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Serve HTML
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/user-dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'user-dashboard.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`🔐 Admin panel: http://localhost:${PORT}/admin`);
    console.log(`👤 User dashboard: http://localhost:${PORT}/user-dashboard`);
    console.log(`💎 User panel: http://localhost:${PORT}`);
});
