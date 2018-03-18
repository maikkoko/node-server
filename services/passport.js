const passport = require('passport')
const User = require('../models/user')
const config = require('../config')
const JwtStrategy = require('passport-jwt').Strategy
const ExtractJwt = require('passport-jwt').ExtractJwt
const LocalStrategy = require('passport-local')

// Create local strategy
const localOptions = { usernameField: 'email' }

const localLogin = new LocalStrategy(
  localOptions,
  function(email, password, done) {
    // Verify email and password
    User.findOne({ email: email }, function(err, user) {
      if (err) { return done(err) }
      if (!user) { return done(null, false) }

      // Compare Passwords
      user.comparePassword(password, function(err, isMatch) {
        if (err) { return done(err) }
        if (!isMatch) { return done(null, false) }

        return done(null, user)
      })
    })
  }
)

// Setup options for JWT Strat
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
}

// Create Strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
  // See if user id is in db
  User.findById(payload.sub, function(err, user) {
    if (err) {
      return done(err, false)
    }

    if (user) {
      done(null, user)
    } else {
      done(null, false)
    }
  })
})

// Tell Passport to use strategy
passport.use(localLogin)
passport.use(jwtLogin)