require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const app = express();
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const findOrCreate = require("mongoose-findorcreate");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const passportLocalMongoose = require("passport-local-mongoose");
// const bcrypt = require('bcrypt');
// const saltRounds = 10;
//const md5 = require("md5");
//const encrypt = require("mongoose-encryption");

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));
//TELLING OUR APP TO USE SESSIONS PACKAGE
app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false,
}));
//TELLING OUR APP TO USE PASSPORT AND USE ITS INITIALIZE PACKAGE AND TO ALSO USE PASSPORT IN DEALING WITH SESSIONS
app.use(passport.initialize());
app.use(passport.session());



//CONNECTING TO MONGOOSE AND CREATING DATABASE
mongoose.connect("mongodb://localhost:27017/userDB");

//setting new user schema
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});
//use passportlocalmongoose as a plugin
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
  //ENCRYPTING THE DATABASE's PASSWORD
  //userSchema.plugin(encrypt, {secret:process.env.SECRET, encryptedFields: ["password"]});
  //ENCRYPTION USING HASH FUNCTIONS



//creating mongoose model
const User = mongoose.model("User",userSchema);

//passportLocalMongoose configuration
passport.use(User.createStrategy());
//makes the cookie containing identity of the user
passport.serializeUser(function(user,done){
  done(null,user.id);
});
//breaks the cookie revaling identity
passport.deserializeUser(function(id,done){
  User.findById(id,function(err,user){
    done(err,user);
  });
});



//adding new google authentication code
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));





//FETCHING HOME PAGE
app.get("/",function(req,res){
  res.render("home");
});

//setting up the button copied from google
app.get("/auth/google",
  passport.authenticate("google",{ scope: ["profile"]})
);


app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });








//FETCHING LOGIN PAGE
app.get("/login",function(req,res){
  res.render("login");
});


app.get("/secrets",function(req,res){
  // //rendering secrets only when the user are logged in
  // if(req.isAuthenticated()){
  //   res.render("secrets");
  // }else{
  //   res.redirect("/login");
  // }
//no longer a privlzd PAGE
//finding all the secrets of user which are not null
User.find({"secret":{$ne: null}}, function(err,foundUsers){
  if(err){
    console.log(err);
  }else{
    res.render("secrets",{usersWithSecrets: foundUsers})
  }
})


});


app.get("/submit",function(req,res){
  if(req.isAuthenticated()){
    res.render("submit");
  }else{
    res.render("/login");
  }
});

app.post("/submit",function(req,res){
  const submittedSecret =  req.body.secret;
  //passports saves users detail in req during the SESSION so
  //console.log(req.user.id)
User.findById(req.user.id,function(err,foundUser){
  if(err){
    console.log(err);
  }else{
    if(foundUser){
      foundUser.secret = submittedSecret;
      foundUser.save(function(){
        res.redirect("/secrets");
      });
    }
  }
});
});








//FETCHING REGISTER PAGE
app.get("/register",function(req,res){
  res.render("register");
});


app.get("/logout",function(req,res){
  req.logout();
  res.redirect("/");
})




//FETCHING INFO FROM REGISTER
app.post("/register",function(req,res){
  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //     // Store hash in your password DB.
  //     //creating new user document
  //     const newUser = new User({
  //     email: req.body.username,
  //     password: hash
  //     });
  //     newUser.save(function(err){
  //       if(err){
  //         console.log(err);
  //       }else{
  //         //only rendering the secrets page once the user is logged in!
  //         res.render("secrets");
  //       }
  //     });
  //     });



//TAPPING INTO USER MODEL AND CALLING REGISTER WHICH COMES FROM PASSPORTLOCALMONGOOSE
//BEACUSE OF THIS PACKAGE WE CAN PREVENT CREATING NEW USER AND INTERACTING WTH MONGOOSE DIRECTLY
User.register({username: req.body.username}, req.body.password,function(err,user){
  if(err){
    console.log(err);
    res.redirect("/register");
  }else{
    //if no error found then we authenticate the user
    //local is the type of authenitcation that we are using
    passport.authenticate("local")(req, res, function(){
      res.redirect("/secrets");
    });
  }
});
  });












//FETCHING INFO FROM LOGIN
app.post("/login",function(req,res){
//   const username = req.body.username;
//   const password = req.body.password;
// User.findOne({email:username},function(err,foundUser){
//   if(err){
//     console.log(err);
//   }else{
//     if(foundUser){
//       bcrypt.compare(password, foundUser.password, function(err, result) {
//     if(result === true){
//         res.render("secrets");
//     }
//   });
//       }
//     }
// });

const user = new User({
  username: req.body.username,
  password: req.body.password
});
//using passport to login and authenticate
req.login(user, function(err){
  if(err){
    console.log(err);
  }else{
    passport.authenticate("local")(req, res, function(){
      res.redirect("/secrets");
  });
}
});
});











app.listen(3000,function(){
  console.log("Server started on port 3000");
});
