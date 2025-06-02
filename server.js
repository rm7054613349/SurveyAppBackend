
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const authRoutes = require('./routes/auth');
const surveyRoutes = require('./routes/survey');
const responseRoutes = require('./routes/response');
const categoryRoutes = require('./routes/category');
const sectionRoutes = require('./routes/section');
const subsectionRoutes = require('./routes/subsection');
const adminRoutes=require('./routes/adminRoutes')
const employeeRoutes=require('./routes/employeeRoutes')
const employeeEvent=require('./routes/eventEmployee')
const adminEvent=require('./routes/eventAdmin')
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const mime = require('mime-types');


dotenv.config();
const app = express();

// MongoDB connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => {
    console.error('MongoDB connection error:', err.message, err.stack);
    process.exit(1);
  });



  // Request logging middleware
app.use((req, res, next) => {
  console.log(`Request received: ${req.method} ${req.originalUrl} at ${new Date().toISOString()}`); // Debug log
  console.log(`Request headers:`, req.headers); // Debug log
  next();
});

// Configurable upload directory
const UPLOAD_DIR = path.join(__dirname, 'uploads');

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (!fs.existsSync(UPLOAD_DIR)) {
      fs.mkdirSync(UPLOAD_DIR, { recursive: true });
    }
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const timestamp = Date.now();
    const sanitizedOriginalName = file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '');
    cb(null, `${timestamp}-${sanitizedOriginalName}`);
  },
});

const upload = multer({ storage });

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/uploads', express.static('uploads'));

// Routes


//for Documents Center
app.use('/api/documentsections', require('./routes/intranet/sectionRoutes'));
app.use('/api/documentsubsections', require('./routes/intranet/subsectionRoutes'));
app.use('/api/documents', require('./routes/intranet/documentRoutes'));




//for Announcement
app.use('/api/admin', adminRoutes);
app.use('/api/employee', employeeRoutes);



//for Event 
app.use('/api/adminevent', adminEvent);
app.use('/api/employeeevent', employeeEvent);





app.use('/api/auth', authRoutes);
app.use('/api/survey', surveyRoutes);
app.use('/api/response', responseRoutes);
app.use('/api/category', categoryRoutes);
app.use('/api/section', sectionRoutes);
app.use('/api/subsection', subsectionRoutes);

// File download endpoint
app.get('/api/files/:filename', (req, res) => {
  const filename = req.params.filename;
  const filePath = path.join(UPLOAD_DIR, filename);

  console.log(`GET /api/files/${filename} requested at ${new Date().toISOString()}`, {
    filename,
    filePath,
    cwd: process.cwd(),
    __dirname,
    uploadDir: UPLOAD_DIR,
  });

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      console.error(`File not found in ./Uploads: ${filename}`, {
        error: err?.message,
        filePath,
      });
      return res.status(404).json({ message: `File ${filename} not found` });
    }

    console.log('Found file in ./Uploads:', {
      filename,
      filePath,
      size: stats.size,
      lastModified: stats.mtime,
    });

    res.setHeader('Content-Type', mime.lookup(filename) || 'application/octet-stream');
    const stream = fs.createReadStream(filePath);
    stream.on('error', error => {
      console.error(`Stream error for ${filename}:`, error);
      res.status(500).json({ message: 'Error reading file' });
    });
    stream.on('end', () => {
      console.log(`Successfully served file: ${filename}`);
    });
    stream.pipe(res);
  });
});

// Debug route to list files in Uploads
app.get('/api/uploads/list', (req, res) => {
  fs.readdir(UPLOAD_DIR, (err, files) => {
    if (err) {
      console.error('Failed to list files in Uploads:', err);
      return res.status(500).json({ message: 'Failed to list files', error: err.message });
    }
    console.log('Listing files in Uploads:', files);
    res.json({ files });
  });
});

// Error handling
app.use((err, req, res, next) => {
  console.error('Server error:', err.stack);
  res.status(500).json({ message: 'Something went wrong!', error: err.message });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));