// Create a new router
const express = require("express");
const bcrypt = require("bcrypt");

const saltRounds = 10;

const router = express.Router();

router.get('/register', function (req, res, next) {
    res.render('register.ejs');                                                       
})    

router.post('/registered', function (req, res, next) {
    // saving data in database

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

    

})

router.get("/login", function (req, res, next) {
    res.render("login.ejs");
})

//cannot be asked to make a logged in mode whatever
router.post("/loggingIn", function (req, res, next) {

    let usernameQuery = "SELECT * FROM users WHERE username = ?";
    
    db.query(usernameQuery, [req.body.username], (err, result) => {
        if(err) {
            next(err);
        } else if(result.length == 1) {
            bcrypt.compare(req.body.password, result[0].password, (error, result) => {
                if(error) {
                    next(error);
                } else if(result == true) {
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

// Export the router object so index.js can access it
module.exports = router