'use strict';

const base64 = require('base-64');
const User = require('../models/users.js');

module.exports = async (req, res, next) => {
    
  // console.log(req.headers.authorization)
  // console.log(!req.headers.authorization)
  if (!req.headers.authorization) { return _authError(); }
  else{
    
   let basic = req.headers.authorization.split(' ').pop();
  
  //  console.log(base64.decode(basic));
    
  
   let [user, pass] = base64.decode(basic).split(':');
  //  console.log({user});

   try {
     req.user = await User.authenticateBasic(user, pass)
     next();
  }  catch (e) {
     res.status(403).send('Invalid Login');
  }
 }
}

