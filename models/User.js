const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
    _id: { 
        type: String, 
        required: true 
    },
    email: {
        type: String,
        sparse: true,
        lowercase: true,
        trim: true
    },
    phoneNumber: {
        type: String,
        sparse: true,
        trim: true
    },
    name: {
        type: String,
        trim: true
    },
    password: {
        type: String,
        required: function() {
            return this.authMethod === 'password';
        }
    },
    pinHash: {
        type: String,
        required: function() {
            return this.authMethod === 'phone-pin';
        }
    },
    authMethod: {
        type: String,
        enum: ['phone', 'email', 'password', 'phone-pin'],
        default: 'phone-pin'
    },
    profile: {
        avatar: String,
        preferences: {
            theme: { type: String, default: 'light' },
            language: { type: String, default: 'en' },
            notifications: { type: Boolean, default: true }
        }
    },
    usage: {
        storageUsed: { type: Number, default: 0 },
        documentsCount: { type: Number, default: 0 },
        lastLogin: Date
    },
    security: {
        failedLoginAttempts: { type: Number, default: 0 },
        lockoutUntil: Date,
        encryptionKey: { type: String }
    },
    status: {
        type: String,
        enum: ['active', 'inactive', 'suspended'],
        default: 'active'
    },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
}, {
    timestamps: true
});

UserSchema.index({ email: 1 }, { sparse: true });
UserSchema.index({ phoneNumber: 1 }, { sparse: true });
UserSchema.index({ status: 1 });

UserSchema.virtual('storageLimit').get(function() {
    return 100 * 1024 * 1024;
});

UserSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 10);
    }
    if (this.isModified('pinHash') && this.pinHash && !this.pinHash.startsWith('$2')) {
        this.pinHash = await bcrypt.hash(this.pinHash, 10);
    }
    this.updatedAt = new Date();
    next();
});

UserSchema.methods.comparePassword = async function(candidatePassword) {
    if (!this.password) return false;
    return bcrypt.compare(candidatePassword, this.password);
};

UserSchema.methods.comparePin = async function(candidatePin) {
    if (!this.pinHash) return false;
    return bcrypt.compare(candidatePin, this.pinHash);
};

UserSchema.methods.isLocked = function() {
    return !!(this.security.lockoutUntil && this.security.lockoutUntil > Date.now());
};

UserSchema.methods.incrementLoginAttempts = function() {
    if (this.security.lockoutUntil && this.security.lockoutUntil < Date.now()) {
        return this.updateOne({
            $unset: { 'security.lockoutUntil': 1 },
            $set: { 'security.failedLoginAttempts': 1 }
        });
    }
    
    const updates = { $inc: { 'security.failedLoginAttempts': 1 } };
    
    if (this.security.failedLoginAttempts + 1 >= 5 && !this.isLocked()) {
        updates.$set = { 'security.lockoutUntil': new Date(Date.now() + 30 * 60 * 1000) };
    }
    
    return this.updateOne(updates);
};

UserSchema.methods.resetLoginAttempts = function() {
    return this.updateOne({
        $unset: {
            'security.failedLoginAttempts': 1,
            'security.lockoutUntil': 1
        },
        $set: {
            'usage.lastLogin': new Date()
        }
    });
};

UserSchema.methods.canUpload = function(fileSize) {
    return (this.usage.storageUsed + fileSize) <= this.storageLimit;
};

UserSchema.methods.updateUsage = function(sizeChange, documentCountChange = 0) {
    return this.updateOne({
        $inc: {
            'usage.storageUsed': sizeChange,
            'usage.documentsCount': documentCountChange
        }
    });
};

module.exports = mongoose.model('User', UserSchema);