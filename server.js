require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const requestLogger = require('./middleware/requestLogger');

const authRoutes = require('./routes/auth');
const documentRoutes = require('./routes/documents');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy - required for Vercel/cloud deployments behind reverse proxies
app.set('trust proxy', 1);

app.use(helmet());
app.use(compression());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter);

const corsOptions = {
  origin: true,
  credentials: true,
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true }));

// Log all incoming requests
app.use(requestLogger());

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/doc_collection_mobile';

// MongoDB connection with serverless-optimized settings
mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 30000,
    socketTimeoutMS: 45000,
    maxPoolSize: 10,
    minPoolSize: 1,
    maxIdleTimeMS: 30000,
    bufferCommands: false,
})
    .then(() => console.log('✅ Connected to MongoDB'))
    .catch(err => console.error('❌ MongoDB Connection Error:', err));

// Handle MongoDB connection errors
mongoose.connection.on('error', err => {
    console.error('MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
    console.log('MongoDB disconnected');
});

app.use('/api/auth', authRoutes.router);
app.use('/api/documents', documentRoutes);

app.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'ok', 
        message: 'Mobile Document Storage Server is running',
        timestamp: new Date().toISOString(),
        version: '1.5.0'
    });
});

app.use((error, req, res, next) => {
    console.error('Error:', error);
    res.status(error.status || 500).json({
        error: error.message || 'Internal Server Error'
    });
});

app.use('*', (req, res) => {
    res.status(404).json({ error: 'API endpoint not found' });
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});

module.exports = app;
