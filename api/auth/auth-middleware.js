const express = require("express");
const User = require("../users/users-model");
const bcrypt = require("bcryptjs");

/*
  If the user does not have a session saved in the server

  status 401
  {
    "message": "You shall not pass!"
  }
*/
function restricted (req, res, next){
  if(req.session.user){
    // if(req.session && req.session.user){
    next()
  }else{
    res.status(401).json({message:"You shall not pass!"})
  }
}

/*
  If the username in req.body already exists in the database

  status 422
  {
    "message": "Username taken"
  }
*/
// async function checkUsernameFree(req, res, next) {
//   try{
//     const rows = await User.findBy({username:req.body.username})
//     if(!rows.length){
//       next()
//     }else{
//       res.status(422).json({message:"Username taken"})
//     }

//   }catch(e){
//     res.status(500).json(`Server error: ${e}`)
//   }
// }

// code above and below are similar and pass same tests
// Gabe's way below
async function checkUsernameFree(req, res, next) {
  try{
    const users = await User.findBy({username:req.body.username})
    if(!users.length){
    next()
    }
    else next(
      {message:"Username taken", status: 422})
  }catch(err){
    next(err)
  }
}

/*
  If the username in req.body does NOT exist in the database

  status 401
  {
    "message": "Invalid credentials"
  }
*/
async function checkUsernameExists(req, res, next) {
  try{
    const rows = await User.findBy({username:req.body.username})
    if(rows.length){
      req.userData = rows[0]
      next()
    }else{
      res.status(401).json({message:"Invalid credentials"})
    }

  } catch(e){
      res.status(500).json(`Server error: ${e}`)
  }
}

// code above and below are similar, not passing same tests
// Gabe's way below

// async function checkUsernameExists(req, res, next) {
//   try{
//     const users = await User.findBy({username:req.body.username})
//     if(!users.length){
//       req.user = users[0]
//     next()
//     }
//     else next(
//       {message:"Invalid credentials", status: 401})
//   }catch(err){
//     next(err)
//   }
// }



/*
  If password is missing from req.body, or if it's 3 chars or shorter

  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
*/
function checkPasswordLength(req, res, next) {
  if(!req.body.password || req.body.password.length < 3){
    res.status(422).json({message:"Password must be longer than 3 chars"})
    
  } else{
    next()
  }
}

// Don't forget to add these to the `exports` object so they can be required in other modules

module.exports = {
  restricted,
  checkUsernameExists,
  checkPasswordLength,
  checkUsernameFree
}