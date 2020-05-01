const path = require('path');
const express = require("express");
const bodyParser = require("body-parser");
const feedRoutes = require("./routes/feed");
const authRoutes = require("./routes/auth");
const mongoose = require('mongoose');
const multer = require('multer');
const { uuid } = require('uuidv4');

const app = express();
const MONGODB_URI = 'mongodb+srv://Oscar1996:quiwi25550@nodejs-raroh.mongodb.net/messages?retryWrites=true&w=majority';

const fileStorage = multer.diskStorage({
   destination: (req, file, cb) => {
      cb(null, 'images');
   },
   filename: (req, file, cb) => {
      cb(null, uuid() + '-' + file.originalname);  //new Date().toISOString().replace(/:/g, '-') + '-' + file.originalname
   }
});

const fileFilter = (req, file, cb) => {
   if (
      file.mimetype === 'image/png' ||
      file.mimetype === 'image/jpg' ||
      file.mimetype === 'image/jpeg'
   ) {
      cb(null, true);
   } else {
      cb(null, false);
   }
};

app.use(bodyParser.json()); //application/json
app.use('/images', express.static(path.join(__dirname, 'images')));
app.use(multer({ storage: fileStorage, fileFilter: fileFilter }).single('image'));

//Setting the API settings
app.use((req, res, next) => {
   res.setHeader('Access-Control-Allow-Origin', '*');
   res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE');
   res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
   next();
});

//Routes
app.use("/feed", feedRoutes);
app.use('/auth', authRoutes);

//Error handler
app.use((error, req, res, next) => {
   const status = error.statusCode || 500;
   const message = error.message;
   const data = error.data;
   res.status(status).json({ message: message, data: data });
});

mongoose
   .connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
   .then(() => {
      const server = app.listen(8080);
      const io = require('./socket').init(server);
      io.on('connection', socket => {
         console.log('Client connected');
      });
   })
   .catch(err => {
      console.log(err);
   });


