const express = require('express');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');
const Document = require('../models/Document');
const User = require('../models/User');
const { authenticate } = require('./auth');

const router = express.Router();

const storage = multer.diskStorage({
    destination: async (req, file, cb) => {
        const uploadDir = path.join(__dirname, '..', 'uploads', req.user._id);
        await fs.mkdir(uploadDir, { recursive: true });
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, `${uuidv4()}${path.extname(file.originalname)}`);
    }
});

const upload = multer({
    storage,
    limits: {
        fileSize: 50 * 1024 * 1024,
        files: 1
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = [
            'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/bmp', 'image/webp',
            'application/pdf',
            'application/msword', 
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel', 
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'text/plain', 'text/csv'
        ];
        
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Unsupported file type'), false);
        }
    }
});

const encryptFile = (data, encryptionKey) => {
    const key = crypto.createHash('sha256').update(encryptionKey).digest();
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(data);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return Buffer.concat([iv, encrypted]);
};

const decryptFile = (encryptedData, encryptionKey) => {
    try {
        if (!encryptedData || !Buffer.isBuffer(encryptedData)) {
            throw new Error('Invalid encrypted data: not a buffer');
        }
        
        if (encryptedData.length < 17) {
            throw new Error('Invalid encrypted data: too short (minimum 17 bytes required)');
        }
        
        const key = crypto.createHash('sha256').update(encryptionKey).digest();
        const iv = encryptedData.slice(0, 16);
        const encrypted = encryptedData.slice(16);
        
        if (encrypted.length === 0 || encrypted.length % 16 !== 0) {
            throw new Error('Invalid encrypted data: incorrect block length');
        }
        
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        let decrypted = decipher.update(encrypted);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted;
    } catch (error) {
        throw new Error(`Decryption failed: ${error.message}`);
    }
};

router.post('/upload', authenticate, upload.single('document'), async (req, res) => {
    try {
        const user = req.user;

        if (!req.file) {
            return res.status(400).json({
                error: 'No file uploaded'
            });
        }

        const { category, description, tags, isPrivate, title, ocrText, documentType, aiGeneratedSummary } = req.body;
        const fileSize = req.file.size;

        if (user.usage.storageUsed + fileSize > user.storageLimit) {
            await fs.unlink(req.file.path).catch(() => {});
            
            return res.status(413).json({
                error: 'Storage limit exceeded',
                used: user.usage.storageUsed,
                limit: user.storageLimit,
                required: fileSize
            });
        }

        const fileData = await fs.readFile(req.file.path);
        const encryptionKey = user.security?.encryptionKey || user._id;
        const encryptedBlob = encryptFile(fileData, encryptionKey);

        const metadata = {
            title: title || req.file.originalname || `Document_${Date.now()}`,
            description: description || '',
            isPrivate: isPrivate === 'true' || isPrivate === true,
            documentType: documentType || '',
            uploadDate: new Date().toISOString()
        };
        const metadataString = JSON.stringify(metadata);
        const encryptedMetadata = encryptFile(Buffer.from(metadataString), encryptionKey);

        let encryptedOcrText = undefined;
        if (ocrText) {
            encryptedOcrText = encryptFile(Buffer.from(ocrText), encryptionKey);
        }

        let encryptedAiSummary = undefined;
        if (aiGeneratedSummary) {
            encryptedAiSummary = encryptFile(Buffer.from(aiGeneratedSummary), encryptionKey);
        }

        const docId = uuidv4();

        const document = new Document({
            _id: docId,
            user_id: user._id,
            encrypted_blob: encryptedBlob,
            encrypted_metadata: encryptedMetadata,
            extractedText: encryptedOcrText,
            aiGeneratedSummary: encryptedAiSummary,
            originalFilename: req.file.originalname,
            mimeType: req.file.mimetype,
            fileSize: fileSize,
            category: category || 'other',
            tags: tags ? tags.split(',').map(tag => tag.trim()) : [],
            status: 'ready'
        });

        await document.save();

        await User.findByIdAndUpdate(user._id, {
            $inc: { 
                'usage.storageUsed': fileSize,
                'usage.documentCount': 1
            }
        });

        await fs.unlink(req.file.path).catch(() => {});

        res.status(201).json({
            message: 'Document uploaded successfully',
            document: {
                id: document._id,
                title: metadata.title,
                description: metadata.description,
                category: document.category,
                tags: document.tags,
                size: document.fileSize,
                mimeType: document.mimeType,
                uploadDate: metadata.uploadDate,
                isPrivate: metadata.isPrivate
            },
            usage: {
                storageUsed: user.usage.storageUsed + fileSize,
                storageLimit: user.storageLimit,
                documentCount: user.usage.documentCount + 1
            }
        });

    } catch (error) {
        console.error('Document upload error:', error);
        
        if (req.file) {
            await fs.unlink(req.file.path).catch(() => {});
        }

        res.status(500).json({
            error: 'Document upload failed'
        });
    }
});

router.get('/list', authenticate, async (req, res) => {
    try {
        const user = req.user;
        const page = parseInt(req.query.page) || 1;
        const limit = Math.min(parseInt(req.query.limit) || 20, 100);
        const skip = (page - 1) * limit;

        const { category, search, sortBy = 'createdAt', sortOrder = 'desc' } = req.query;

        const filter = { user_id: user._id };
        
        if (category && category !== 'all') {
            filter.category = category;
        }

        const sort = {};
        sort[sortBy] = sortOrder === 'desc' ? -1 : 1;

        const [documents, total] = await Promise.all([
            Document.find(filter)
                .select('-encrypted_blob')
                .sort(sort)
                .skip(skip)
                .limit(limit),
            Document.countDocuments(filter)
        ]);

        const decryptedDocuments = documents.map(doc => {
            let metadata = {};
            let isCorrupted = false;
            let ocrText = null;
            let aiSummary = null;
            
            const encryptionKey = user.security?.encryptionKey || user._id;
            
            if (doc.encrypted_metadata) {
                try {
                    const decryptedMeta = decryptFile(doc.encrypted_metadata, encryptionKey);
                    metadata = JSON.parse(decryptedMeta.toString());
                } catch (err) {
                    metadata = { 
                        title: doc.originalFilename || 'Unknown', 
                        description: 'Warning: Metadata could not be decrypted' 
                    };
                    isCorrupted = true;
                }
            } else {
                metadata = { title: doc.originalFilename || 'Untitled', description: '' };
            }
            
            if (doc.extractedText) {
                try {
                    const decryptedOcr = decryptFile(doc.extractedText, encryptionKey);
                    ocrText = decryptedOcr.toString();
                } catch (err) {
                    ocrText = null;
                }
            }
            
            if (doc.aiGeneratedSummary) {
                try {
                    const decryptedSummary = decryptFile(doc.aiGeneratedSummary, encryptionKey);
                    aiSummary = decryptedSummary.toString();
                } catch (err) {
                    aiSummary = null;
                }
            }

            return {
                id: doc._id,
                title: metadata.title || doc.originalFilename || 'Untitled',
                description: metadata.description || '',
                category: doc.category,
                tags: doc.tags,
                size: doc.fileSize,
                mimeType: doc.mimeType,
                uploadDate: metadata.uploadDate || doc.createdAt,
                isPrivate: metadata.isPrivate || false,
                viewCount: doc.analytics?.viewCount || 0,
                lastAccessed: doc.analytics?.lastAccessed,
                documentType: metadata.documentType || '',
                ocrText: ocrText,
                aiGeneratedSummary: aiSummary,
                isCorrupted: isCorrupted
            };
        });

        let filteredDocuments = decryptedDocuments;
        if (search) {
            const searchLower = search.toLowerCase();
            filteredDocuments = decryptedDocuments.filter(doc => 
                doc.title.toLowerCase().includes(searchLower) ||
                doc.description.toLowerCase().includes(searchLower) ||
                doc.tags.some(tag => tag.toLowerCase().includes(searchLower)) ||
                (doc.ocrText && doc.ocrText.toLowerCase().includes(searchLower)) ||
                (doc.aiGeneratedSummary && doc.aiGeneratedSummary.toLowerCase().includes(searchLower)) ||
                (doc.documentType && doc.documentType.toLowerCase().includes(searchLower))
            );
        }

        res.json({
            documents: filteredDocuments,
            pagination: {
                current: page,
                total: Math.ceil(total / limit),
                count: filteredDocuments.length,
                totalDocuments: total
            },
            categories: await Document.distinct('category', { userId: user._id })
        });

    } catch (error) {
        console.error('Documents list error:', error);
        res.status(500).json({
            error: 'Failed to retrieve documents'
        });
    }
});

router.get('/:documentId', authenticate, async (req, res) => {
    try {
        const user = req.user;
        const document = await Document.findOne({
            _id: req.params.documentId,
            user_id: user._id
        }).select('-encrypted_blob');

        if (!document) {
            return res.status(404).json({
                error: 'Document not found'
            });
        }

        let metadata = {};
        let isCorrupted = false;
        
        if (document.encrypted_metadata) {
            try {
                const encryptionKey = user.security?.encryptionKey || user._id;
                const decryptedMeta = decryptFile(document.encrypted_metadata, encryptionKey);
                metadata = JSON.parse(decryptedMeta.toString());
            } catch (err) {
                metadata = { 
                    title: document.originalFilename || 'Unknown', 
                    description: 'Warning: Metadata could not be decrypted' 
                };
                isCorrupted = true;
            }
        } else {
            metadata = { title: document.originalFilename || 'Untitled', description: '' };
        }

        res.json({
            id: document._id,
            title: metadata.title || document.originalFilename || 'Untitled',
            description: metadata.description || '',
            category: document.category,
            tags: document.tags,
            file: {
                originalName: document.originalFilename,
                mimeType: document.mimeType,
                size: document.fileSize
            },
            metadata: metadata,
            analytics: document.analytics,
            createdAt: document.createdAt,
            updatedAt: document.updatedAt
        });

    } catch (error) {
        console.error('Get document error:', error);
        res.status(500).json({
            error: 'Failed to get document'
        });
    }
});

router.get('/:documentId/download', authenticate, async (req, res) => {
    try {
        const user = req.user;
        const document = await Document.findOne({
            _id: req.params.documentId,
            user_id: user._id
        });

        if (!document) {
            return res.status(404).json({
                error: 'Document not found'
            });
        }

        if (!document.encrypted_blob) {
            return res.status(500).json({
                error: 'Document data is missing or corrupted'
            });
        }
        
        const encryptionKey = user.security?.encryptionKey || user._id;
        let decryptedData;
        
        try {
            decryptedData = decryptFile(document.encrypted_blob, encryptionKey);
        } catch (err) {
            console.error(`Failed to decrypt document ${document._id}:`, err.message);
            return res.status(500).json({
                error: 'Document is corrupted and cannot be decrypted'
            });
        }

        await Document.findByIdAndUpdate(document._id, {
            $inc: { 'analytics.viewCount': 1 },
            $set: { 'analytics.lastAccessed': new Date() }
        });

        res.setHeader('Content-Type', document.mimeType);
        res.setHeader('Content-Disposition', `attachment; filename="${document.originalFilename}"`);
        res.setHeader('Content-Length', document.fileSize);

        res.send(decryptedData);

    } catch (error) {
        console.error('Document download error:', error);
        res.status(500).json({
            error: 'Failed to download document'
        });
    }
});

router.put('/:documentId', authenticate, async (req, res) => {
    try {
        const user = req.user;
        const { title, description, category, tags, isPrivate } = req.body;

        const document = await Document.findOne({
            _id: req.params.documentId,
            user_id: user._id
        });

        if (!document) {
            return res.status(404).json({
                error: 'Document not found'
            });
        }

        let metadata = {};
        if (document.encrypted_metadata) {
            try {
                const encryptionKey = user.security?.encryptionKey || user._id;
                const decryptedMeta = decryptFile(document.encrypted_metadata, encryptionKey);
                metadata = JSON.parse(decryptedMeta.toString());
            } catch (err) {
                metadata = {};
            }
        }

        if (title) metadata.title = title;
        if (description !== undefined) metadata.description = description;
        if (isPrivate !== undefined) metadata.isPrivate = isPrivate === 'true' || isPrivate === true;

        const encryptionKey = user.security?.encryptionKey || user._id;
        const encryptedMetadata = encryptFile(Buffer.from(JSON.stringify(metadata)), encryptionKey);

        const updates = { encrypted_metadata: encryptedMetadata };
        if (category) updates.category = category;
        if (tags !== undefined) {
            updates.tags = Array.isArray(tags) 
                ? tags 
                : tags.split(',').map(tag => tag.trim());
        }

        const updatedDocument = await Document.findByIdAndUpdate(
            req.params.documentId,
            updates,
            { new: true }
        ).select('-encrypted_blob');

        res.json({
            message: 'Document updated successfully',
            document: {
                id: updatedDocument._id,
                title: metadata.title,
                description: metadata.description,
                category: updatedDocument.category,
                tags: updatedDocument.tags,
                isPrivate: metadata.isPrivate,
                updatedAt: updatedDocument.updatedAt
            }
        });

    } catch (error) {
        console.error('Document update error:', error);
        res.status(500).json({
            error: 'Failed to update document'
        });
    }
});

router.delete('/:documentId', authenticate, async (req, res) => {
    try {
        const user = req.user;
        const document = await Document.findOne({
            _id: req.params.documentId,
            user_id: user._id
        });

        if (!document) {
            return res.status(404).json({
                error: 'Document not found'
            });
        }

        await User.findByIdAndUpdate(user._id, {
            $inc: {
                'usage.storageUsed': -document.fileSize,
                'usage.documentCount': -1
            }
        });

        await Document.findByIdAndDelete(req.params.documentId);

        res.json({
            message: 'Document deleted successfully',
            freedSpace: document.fileSize
        });

    } catch (error) {
        console.error('Document delete error:', error);
        res.status(500).json({
            error: 'Failed to delete document'
        });
    }
});

router.get('/stats/storage', authenticate, async (req, res) => {
    try {
        const user = req.user;

        const stats = await Document.aggregate([
            { $match: { user_id: user._id } },
            {
                $group: {
                    _id: '$category',
                    count: { $sum: 1 },
                    totalSize: { $sum: '$fileSize' },
                    avgSize: { $avg: '$fileSize' }
                }
            }
        ]);

        const recentDocuments = await Document.find({ user_id: user._id })
            .select('originalFilename encrypted_metadata fileSize createdAt')
            .sort({ createdAt: -1 })
            .limit(5);

        res.json({
            overall: {
                totalDocuments: user.usage.documentCount,
                storageUsed: user.usage.storageUsed,
                storageLimit: user.storageLimit,
                storagePercentage: Math.round((user.usage.storageUsed / user.storageLimit) * 100)
            },
            byCategory: stats,
            recentDocuments: recentDocuments.map(doc => {
                let metadata = {};
                if (doc.encrypted_metadata) {
                    try {
                        const encryptionKey = user.security?.encryptionKey || user._id;
                        const decryptedMeta = decryptFile(doc.encrypted_metadata, encryptionKey);
                        metadata = JSON.parse(decryptedMeta.toString());
                    } catch (err) {
                        metadata = { title: doc.originalFilename };
                    }
                } else {
                    metadata = { title: doc.originalFilename || 'Untitled' };
                }
                return {
                    id: doc._id,
                    title: metadata.title || doc.originalFilename,
                    uploadDate: metadata.uploadDate || doc.createdAt,
                    size: doc.fileSize
                };
            })
        });

    } catch (error) {
        console.error('Storage stats error:', error);
        res.status(500).json({
            error: 'Failed to get storage statistics'
        });
    }
});

module.exports = router;