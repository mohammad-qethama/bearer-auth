'use strict';

// Start up DB Server
require('dotenv').config();
const mongoose = require('mongoose');
const options = {
  useNewUrlParser: true,
  useCreateIndex: true,
  useUnifiedTopology: true,
};
mongoose.connect(process.env.MONGODB_URI, options).then(()=>{

require('./src/server.js').startup(process.env.PORT);

}).catch(error =>{
  console.error('cant start the Server', error);
});


