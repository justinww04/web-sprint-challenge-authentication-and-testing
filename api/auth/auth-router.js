const router = require('express').Router();
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const {JWT_SECRET} = require('../secrets/index')
const {
  checkBodyInfo,
  checkUsernameExists,
  checkUsernameInDb
} = require('./auth-middleware')
const Auth = require('./auth-model')

router.post('/register', checkBodyInfo, checkUsernameExists, (req, res, next) => {
 
      const {username, password} = req.body
      const hash = bcrypt.hashSync(password, 8)
      Auth.createAccount({username, password: hash})
        .then(result => {
          res.status(201).json(result)
        })
        .catch(next)
  });

router.post('/login', checkBodyInfo,checkUsernameInDb,(req, res, next) => {
  
    if(bcrypt.compareSync(req.body.password, req.user.password)){
      const token = buildToken(req.user)
      res.json({
        message:`Welcome, ${req.user.username}`,
        token: token
      })
    } else {
      next({status:401, message:'invalid credentials'})
    }
});

function buildToken(user) {
  const payload = {
    subject: user.id,
    username: user.username
  }
  const options = {
    expiresIn :'1d',
  }
  return jwt.sign(payload, JWT_SECRET, options)
}

module.exports = router;