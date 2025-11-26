const mongoose = require('mongoose');

const DocumentSchema = new mongoose.Schema({
    _id: { 
        type: String, 
        required: true 
    },
    user_id: { 
        type: String, 
        required: true, 
        ref: 'User',
        index: true
    },
    encrypted_blob: { 
        type: Buffer, 
        required: true 
    },
    encrypted_metadata: { 
        type: Buffer, 
        required: true 
    },
    originalFilename: {
        type: String,
        trim: true
    },
    mimeType: {
        type: String,
        required: true,
        default: 'image/jpeg'
    },
    fileSize: {
        type: Number,
        required: true,
        min: 0
    },
    category: {
        type: String,
        default: 'other'
    },
    tags: [{
        type: String,
        trim: true,
        lowercase: true
    }],
    extractedText: {
        type: Buffer
    },
    aiGeneratedSummary: {
        type: Buffer
    },
    aiAnalysis: {
        type: Buffer
    },
    status: {
        type: String,
        enum: ['processing', 'ready', 'failed'],
        default: 'processing'
    },
    analytics: {
        viewCount: { type: Number, default: 0 },
        lastViewed: Date
    },
    
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
}, {
    timestamps: true
});

DocumentSchema.index({ user_id: 1, createdAt: -1 });
DocumentSchema.index({ user_id: 1, category: 1 });
DocumentSchema.index({ user_id: 1, tags: 1 });
DocumentSchema.index({ user_id: 1, status: 1 });

DocumentSchema.virtual('fileSizeFormatted').get(function() {
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    if (this.fileSize === 0) return '0 Bytes';
    const i = Math.floor(Math.log(this.fileSize) / Math.log(1024));
    return Math.round(this.fileSize / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
});

DocumentSchema.pre('save', function(next) {
    this.updatedAt = new Date();
    next();
});

DocumentSchema.methods.incrementViewCount = function() {
    return this.updateOne({
        $inc: { 'analytics.viewCount': 1 },
        $set: { 'analytics.lastViewed': new Date() }
    });
};

DocumentSchema.methods.addTag = function(tag) {
    if (!this.tags.includes(tag.toLowerCase())) {
        return this.updateOne({
            $push: { tags: tag.toLowerCase() }
        });
    }
    return Promise.resolve();
};

DocumentSchema.methods.removeTag = function(tag) {
    return this.updateOne({
        $pull: { tags: tag.toLowerCase() }
    });
};

// Static methods
DocumentSchema.statics.findByUser = function(userId, options = {}) {
    const query = { 
        user_id: userId,
        status: { $ne: 'failed' }
    };
    
    if (options.category) {
        query.category = options.category;
    }
    
    if (options.tags && options.tags.length > 0) {
        query.tags = { $in: options.tags };
    }
    
    return this.find(query)
        .sort({ createdAt: -1 })
        .limit(options.limit || 50)
        .skip(options.skip || 0);
};

DocumentSchema.statics.getStorageUsage = function(userId) {
    return this.aggregate([
        { $match: { user_id: userId } },
        {
            $group: {
                _id: null,
                totalSize: { $sum: '$fileSize' },
                documentCount: { $sum: 1 }
            }
        }
    ]);
};

module.exports = mongoose.model('Document', DocumentSchema);