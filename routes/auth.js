const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

const generateToken = (userId) => {
    return jwt.sign({ userId }, JWT_SECRET, { 
        expiresIn: process.env.JWT_EXPIRES_IN || '30d'
    });
};

const authenticate = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ 
                error: 'Access token required'
            });
        }

        const token = authHeader.substring(7);
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId);
        
        if (!user || user.status !== 'active') {
            return res.status(401).json({ 
                error: 'Invalid or expired token'
            });
        }

        if (user.isLocked()) {
            return res.status(401).json({ 
                error: 'Account temporarily locked'
            });
        }

        req.user = user;
        next();
    } catch (error) {
        return res.status(401).json({ 
            error: 'Invalid token'
        });
    }
};

router.post('/check-user', async (req, res) => {
    try {
        const { phoneNumber, pin } = req.body;

        if (!phoneNumber || !pin) {
            return res.status(400).json({ error: 'Phone number and PIN are required' });
        }
        if (!/^\d{6}$/.test(pin)) {
            return res.status(400).json({ error: 'PIN must be exactly 6 digits' });
        }

        let user = await User.findOne({ phoneNumber });

        if (!user) {
            return res.json({
                exists: false,
                message: 'New user - please complete registration'
            });
        } else {
            const validPin = await user.comparePin(pin);
            if (!validPin) {
                await user.incrementLoginAttempts();
                return res.status(401).json({ error: 'Invalid PIN' });
            }
            if (user.isLocked()) {
                return res.status(401).json({ error: 'Account temporarily locked' });
            }
            if (user.status !== 'active') {
                return res.status(401).json({ error: 'Account is not active' });
            }
            await user.resetLoginAttempts();

            const token = generateToken(user._id);
            return res.json({
                exists: true,
                message: 'Login successful',
                user: {
                    id: user._id,
                    name: user.name,
                    phoneNumber: user.phoneNumber,
                    authMethod: user.authMethod,
                    usage: user.usage,
                    storageLimit: user.storageLimit
                },
                token
            });
        }
    } catch (error) {
        console.error('Check user error:', error);
        res.status(500).json({ error: 'Failed to check user' });
    }
});

router.post('/phone-pin', async (req, res) => {
    try {
        const { phoneNumber, name, pin, email } = req.body;

        if (!phoneNumber || !pin) {
            return res.status(400).json({ error: 'Phone number and PIN are required' });
        }
        if (!/^\d{6}$/.test(pin)) {
            return res.status(400).json({ error: 'PIN must be exactly 6 digits' });
        }

        let user = await User.findOne({ phoneNumber });

        if (!user) {
            if (!name || name.trim() === '') {
                return res.status(400).json({ error: 'Name is required for new users' });
            }
            user = new User({
                _id: phoneNumber,
                phoneNumber,
                name: name.trim(),
                email: email && email.trim() !== '' ? email.trim() : undefined,
                authMethod: 'phone-pin',
                pinHash: pin
            });
            await user.save();
        } else {
            const validPin = await user.comparePin(pin);
            if (!validPin) {
                await user.incrementLoginAttempts();
                return res.status(401).json({ error: 'Invalid PIN' });
            }
            if (user.isLocked()) {
                return res.status(401).json({ error: 'Account temporarily locked' });
            }
            if (user.status !== 'active') {
                return res.status(401).json({ error: 'Account is not active' });
            }
            await user.resetLoginAttempts();
            if (!user.name && name) {
                user.name = name;
                await user.save();
            }
        }

        const token = generateToken(user._id);
        res.json({
            message: user.createdAt === user.updatedAt ? 'Registered successfully' : 'Login successful',
            user: {
                id: user._id,
                name: user.name,
                phoneNumber: user.phoneNumber,
                authMethod: user.authMethod,
                usage: user.usage,
                storageLimit: user.storageLimit
            },
            token
        });
    } catch (error) {
        console.error('Phone+PIN auth error:', error);
        res.status(500).json({ error: 'Authentication failed' });
    }
});

router.post('/change-pin', authenticate, async (req, res) => {
    try {
        const { currentPin, newPin } = req.body;
        const user = req.user;

        if (!currentPin || !newPin) {
            return res.status(400).json({ error: 'Current PIN and new PIN are required' });
        }
        if (!/^\d{6}$/.test(newPin)) {
            return res.status(400).json({ error: 'New PIN must be exactly 6 digits' });
        }

        const validPin = await user.comparePin(currentPin);
        if (!validPin) {
            return res.status(401).json({ error: 'Current PIN is incorrect' });
        }

        user.pinHash = newPin; // will hash in pre-save
        await user.save();
        res.json({ message: 'PIN changed successfully' });
    } catch (error) {
        console.error('Change PIN error:', error);
        res.status(500).json({ error: 'Failed to change PIN' });
    }
});

router.get('/profile', authenticate, async (req, res) => {
    try {
        const user = req.user;
        
        res.json({
            id: user._id,
            name: user.name,
            email: user.email,
            phoneNumber: user.phoneNumber,
            authMethod: user.authMethod,
            profile: user.profile,
            usage: {
                ...user.usage,
                storageUsedFormatted: formatBytes(user.usage.storageUsed),
                storageLimitFormatted: formatBytes(user.storageLimit),
                usagePercentage: Math.round((user.usage.storageUsed / user.storageLimit) * 100)
            },
            status: user.status,
            createdAt: user.createdAt
        });

    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({
            error: 'Failed to get profile'
        });
    }
});

router.put('/profile', authenticate, async (req, res) => {
    try {
        const user = req.user;
        const { name, email, phoneNumber, profile } = req.body;

        const updates = {};
        if (name) updates.name = name;
        if (email && email !== user.email) {
            // Check if email is already taken
            const emailExists = await User.findOne({ email, _id: { $ne: user._id } });
            if (emailExists) {
                return res.status(409).json({
                    error: 'Email already in use'
                });
            }
            updates.email = email;
        }
        if (phoneNumber && phoneNumber !== user.phoneNumber) {
            // Check if phone is already taken
            const phoneExists = await User.findOne({ phoneNumber, _id: { $ne: user._id } });
            if (phoneExists) {
                return res.status(409).json({
                    error: 'Phone number already in use'
                });
            }
            updates.phoneNumber = phoneNumber;
        }
        if (profile) {
            updates['profile'] = { ...user.profile, ...profile };
        }

        const updatedUser = await User.findByIdAndUpdate(user._id, updates, { new: true });

        res.json({
            message: 'Profile updated successfully',
            user: {
                id: updatedUser._id,
                name: updatedUser.name,
                email: updatedUser.email,
                phoneNumber: updatedUser.phoneNumber,
                profile: updatedUser.profile
            }
        });

    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({
            error: 'Failed to update profile'
        });
    }
});

router.post('/verify', authenticate, (req, res) => {
    res.json({
        valid: true,
        user: {
            id: req.user._id,
            name: req.user.name,
            authMethod: req.user.authMethod
        }
    });
});

function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

module.exports = { router, authenticate };