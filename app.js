require('dotenv').config()
//basically anywhere after this line we can use the variables in env file
const express=require("express");
const bodyParser=require("body-parser");
const ejs=require("ejs");
const app=express();
const mongoose=require("mongoose");
const session=require("express-session");
const passport=require("passport");
const passportLocalMongoose=require("passport-local-mongoose");
const GoogleStrategy = require( 'passport-google-oauth2' ).Strategy;
const findOrCreate = require('mongoose-findorcreate')
// const bcrypt = require('bcrypt');
// const saltRounds = 10;
// const myPlaintextPassword = 's0/\/\P4$$w0rD';
// const someOtherPlaintextPassword = 'not_bacon';

// const encrypt=require("mongoose-encryption");
// const md5=require("md5");
// const bcrypt=require("bcrypt");
// const saltRounds=10;

/*
node provides us with a runtime enviornment which allows us to run javascript in our computer rather than limiting its uses to just a browser.It has a plethora of applications which are not limited to webd, it helps to make webd easier, makes the code shorter and easier to understand.it also allows us to add middleware to our websites.


get-> it requests a piece of information from the server, it could be a html page or something from the database created.

post->it sends information to the server from the website, like filling out a form and sending it to the server, or logging in which makes a post request and then the server checks this information in the database.

put->upadate resourse already present with something other
*/
// const salt = bcrypt.genSaltSync(saltRounds);
// const hash = bcrypt.hashSync(myPlaintextPassword, salt);
app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended:true}));

app.use(session({
    secret: 'hello there this is ayushman',
    resave: false,
    saveUninitialized: true,
  }));
// Now a session (ID and object) will be created for every unique user across multiple HTTP requests.
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017/userDB?directConnection=true&serverSelectionTimeoutMS=2000&appName=mongosh+1.10.1")

const userSchema=new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    secret:String
});


userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


const User=new mongoose.model("User",userSchema);



passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    cb(null, { id: user.id, username: user.username });
  });
});
passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});


passport.use(new GoogleStrategy({
    clientID:process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    passReqToCallback   : true,
    userProfileURL:'https://www.googleapis.com/oauth2/v3/userinfo'
  },
  function(request, accessToken, refreshToken, profile, done) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));


app.get("/",function(req,res){
    res.render("home");
})
app.get("/login",function(req,res){
    res.render("login");
})
app.get("/register",function(req,res){
    res.render("register");
})
app.get("/secrets",function(req,res){
    async function render_secrets(){
    const foundusers=await User.find({"secret":{$ne:null}});
     if(foundusers)
     {
        res.render("secrets",{usersWithSecrets:foundusers});
     }
     else
     {
      res.redirect("/register");
     }
    }
    render_secrets();    
});
app.get('/logout', function(req, res, next){
    req.logout(function(err) {
      if (err) { return next(err); }
      res.redirect('/');
    });
  });

app.get('/auth/google',
  passport.authenticate('google', { scope:
      [ 'profile' ] }
));
app.get( '/auth/google/secrets',
    passport.authenticate( 'google', {
        successRedirect: '/secrets',
        failureRedirect: '/login'
}));
app.post("/register", function(req, res){

  User.register({username: req.body.username}, req.body.password, function(err, user){
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });

});
app.post("/login", function(req, res){

    const user = new User({
      username: req.body.username,
      password: req.body.password
    });
    
    req.login(user, function(err){
      if (err) {
        console.log(err);
      } else {
        passport.authenticate("local")(req, res, function(){
          res.redirect("/secrets");
        });
      }
    });
  //   async function checkUser(username, password) {
  //     //... fetch user from a db etc.
  
  //     const match = await bcrypt.compare(password, user.passwordHash);
  
  //     if(match) {
  //         res.redirect("/secrets");
  //     }
  
  //     //...
  // }
  });
  app.get("/submit",function(req,res){
    if(req.isAuthenticated()){
      res.render("submit");
    }
    else{
      res.render("/login");
    }
  });
  app.post("/submit",function(req,res){
    const submittedSecret=req.body.secret;
    async function find_user(){
    const foundUser=User.findById(req.user.id);
    if(foundUser)
    {
      foundUser.secret=submittedSecret;
      foundUser.save(function(){
        res.redirect("/redirect");
      });
    }
    else
    {
      console.log(founduser);
    }
  }
  find_user();
  });
app.listen(3000,function(){
    console.log("server started on port 3000");
})





