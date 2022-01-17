// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const User = require("../users/users-model");

const {checkUsernameFree, checkUsernameExists, checkPasswordLength} = require("./auth-middleware");


/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */

  
  router.post("/register",checkPasswordLength, checkUsernameFree, async (req, res) => {
    const {username, password} = req.body
    try{
      const hash = bcrypt.hashSync(password,10) //2 to the 10th power
      const newUser = await User.add({username:username, password:hash})
      res.status(201).json(newUser)

    } catch(e){
      res.status(500).json(`Server errors: ${e}`)
    }
  });


/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */

 

  router.post("/login", checkUsernameExists, (req, res) => {
    const {password} = req.body

    try{
      const verified = bcrypt.compareSync(password, req.userData.password)
      
      if(verified){
        req.session.user = req.userData
        // make it so the cookie is set on the client
        // make it so server stores a session with a session id
        res.json({message:`Welcome ${req.userData.username}`})
      }else{
        res.status(401).json({message:"Invalid credentials"})
      }

    }catch(e){
      res.status(500).json(`Server error: ${e}`)
    }
  })


/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

  router.get("/logout", (req, res) => {
    if(req.session.user){
      req.session.destroy(err => {
        if(err){
          res.status(500).json("can't log out")
        }else{
          res.status(200).json({message:"logged out"})
        }
      })
    }else{
      res.status(200).json({message:"no session"})
    }
  });

  // code above and below is similar, both pass tests
  // Gabe's way below
  
  // router.get("/logout", (req, res, next) => {
  //   if (req.session.user) {
  //     req.session.destroy(err => {
  //       if(err) {
  //         next(err)
  //       } else {
  //         res.json({message: "logged out"})
  //       }
  //     })
  //   } else {
  //     res.json({message: "no session"})
  //   }
  // })

 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;