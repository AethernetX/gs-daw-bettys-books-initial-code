const { check, validationResult } = require('express-validator');

const redirectLogin = (req, res, next) => {
    if (!req.session.userId ) {
      res.redirect('./login') // redirect to the login page
    } else { 
        next (); // move to the next middleware function
    } 
}

// Create a new router
const express = require("express");
const bcrypt = require("bcrypt");

const saltRounds = 10;

const router = express.Router();

router.get('/register', function (req, res, next) {
    res.render('register.ejs');                                                       
})    

router.post('/registered',[check("email").isEmail(), check("password").isLength({min: 6})], function (req, res, next) {
    // saving data in database
    const error = validationResult(req);
    if(!error.isEmpty()) {
        res.redirect("./register");
    } else {
        //sanatise forms
        req.sanitize(req.body.first);
        req.sanitize(req.body.last);
        req.sanitize(req.body.email);
        req.sanitize(req.body.username);
        req.sanitize(req.body.password);
        const plainPassword = req.body.password;

        bcrypt.hash(plainPassword, saltRounds, function(err, hashedPassword) {

            if(err){
                next(err)
            } else {
                let sqlquery = "INSERT INTO users (firstName, lastName, email, username, password) VALUES (?,?,?,?,?)"

                let newrecord = [req.body.first, req.body.last, req.body.email, req.body.username, hashedPassword]
                db.query(sqlquery, newrecord, (error, result) => {
                    if (error) {
                        next(error)
                    }
                    else
                    res.send(' Hello '+ req.body.first + ' '+ req.body.last +' you are now registered!  We will send an email to you at ' + req.body.email)                                                                           
                })
            }

        
        })
    }
    

})

router.get("/login", function (req, res, next) {
    res.render("login.ejs");
})

//cannot be asked to make a logged in mode whatever
router.post("/loggingIn", function (req, res, next) {

    //sanatise
    req.sanitize(req.body.username);
    req.sanitize(req.body.password);

    let usernameQuery = "SELECT * FROM users WHERE username = ?";
    
    db.query(usernameQuery, [req.body.username], (err, result) => {
        if(err) {
            next(err);
        } else if(result.length == 1) {
            bcrypt.compare(req.body.password, result[0].password, (error, result) => {
                if(error) {
                    next(error);
                } else if(result == true) {
                    // Save user session here, when login is successful
                    req.session.userId = req.body.username;
                    res.send("logging in...");

                } else {
                    res.send("wrong password...");
                }
            })
        } else {
            res.send("cannot find username");
        }

        }
    )

});

router.get('/logout', redirectLogin, (req,res) => {
        req.session.destroy(err => {
        if (err) {
          return res.redirect('/')
        }
        res.send('you are now logged out. <a href='+'./'+'>Home</a>');
        })
    })


// Export the router object so index.js can access it
module.exports = router