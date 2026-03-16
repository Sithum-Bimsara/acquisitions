import express from 'express';
import helmet from 'helmet';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import logger from '#config/logger.js';
import authRoutes from '#routes/auth.routes.js';
import securityMiddleware from '#middleware/security.middleware.js';

const app = express();
app.use(helmet());
app.use(cookieParser());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(morgan('combined', { stream: { write: (message) => logger.info(message.trim()) } }));
app.use(securityMiddleware);

app.get('/', (req, res) => {
  logger.info('Hello from Acquisitions!');
  res.status(200).send('Hello from Acquisitions!');
});
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString(), uptime: process.uptime() });
});
app.get('/api', (req, res) => {
  res.status(200).json({ message: 'Acquisitions API is running!' });
});

app.use('/api/auth', authRoutes);

export default app;