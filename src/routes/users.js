const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const keys = require("../../config/keys");
const Validator = require("validator");
const isEmpty = require("is-empty");
const _ = require('lodash');
// Load User model
const User = require("../models/User");
const verifyToken = require("../middleware/token-validator");

// @route POST api/users/signUp
// @desc SignUp user
// @access Public
router.post("/signUp", (req, res) => {
    let errors = {};

    req.body.name = !isEmpty(req.body.name) ? req.body.name : "";
    req.body.email = !isEmpty(req.body.email) ? req.body.email : "";
    req.body.password = !isEmpty(req.body.password) ? req.body.password : "";
    req.body.confirmPassword = !isEmpty(req.body.confirmPassword) ? req.body.confirmPassword : "";

    if (Validator.isEmpty(req.body.name)) {
        errors.name = "Name is required";
    }

    // Email checks
    if (Validator.isEmpty(req.body.email)) {
        errors.email = "Email is required";
    } else if (!Validator.isEmail(req.body.email)) {
        errors.email = "Email is invalid";
    }

    // Password checks
    if (Validator.isEmpty(req.body.password)) {
        errors.password = "Password is required";
    }

    if (Validator.isEmpty(req.body.confirmPassword)) {
        errors.confirmPassword = "Confirm password is required";
    }

    if (!Validator.isLength(req.body.password, { min: 6, max: 30 })) {
        errors.password = "Password must be at least 6 characters";
    }

    if (!Validator.equals(req.body.password, req.body.confirmPassword)) {
        errors.confirmPassword = "Passwords mismatch";
    }


    // Check validation
    if (!isEmpty(errors)) {
        return res.status(400).json(errors);
    }

    User.findOne({ email: req.body.email }).then(user => {
        if (user) {
            return res.status(400).json({ email: "Email already exists" });
        } else {
            const newUser = new User({
                name: req.body.name,
                email: req.body.email,
                password: req.body.password
            });
            // Hash password before saving in database
            bcrypt.genSalt(10, (err, salt) => {
                bcrypt.hash(newUser.password, salt, (err, hash) => {
                    if (err) throw err;
                    newUser.password = hash;
                    newUser
                        .save()
                        .then(user => res.json(user))
                        .catch(err => console.log(err));
                });
            });
        }
    });
});


// @route POST api/users/login
// @desc Login user and return JWT token
// @access Public
router.post("/login", (req, res) => {
    // Form validation
    let errors = {};
    // Convert empty fields to an empty string so we can use validator functions
    req.body.email = !isEmpty(req.body.email) ? req.body.email : "";
    req.body.password = !isEmpty(req.body.password) ? req.body.password : "";

    // Email checks
    if (Validator.isEmpty(req.body.email)) {
        errors.email = "Email field is required";
    } else if (!Validator.isEmail(req.body.email)) {
        errors.email = "Email is invalid";
    }

    // Password checks
    if (Validator.isEmpty(req.body.password)) {
        errors.password = "Password field is required";
    }

    // Check validation
    if (!isEmpty(errors)) {
        return res.status(400).json(errors);
    }

    const email = req.body.email;
    const password = req.body.password;
    // Find user by email
    User.findOne({ email }).then(user => {
        // Check if user exists
        if (!user) {
            return res.status(404).json({ email: "Email not found" });
        }
        // Check password
        bcrypt.compare(password, user.password).then(isMatch => {
            if (isMatch) {
                // User matched
                // Create JWT Payload
                const payload = {
                    id: user.id,
                    name: user.name
                };
                // Sign token
                jwt.sign(
                    payload,
                    keys.secretOrKey,
                    {
                        expiresIn: 31556926 // 1 year in seconds
                    },
                    (err, token) => {
                        res.json({
                            success: true,
                            token: token
                        });
                    }
                );
            } else {
                return res
                    .status(400)
                    .json({ password: "Password incorrect" });
            }
        });
    });
});

// @route Get api/users/getCurrentLoggedInUser
// @desc get user detail
// @access Public
router.get("/getCurrentLoggedInUser", verifyToken, (req, res) => {
    if (!req.user) {
        res.status(403)
            .send({
                message: "Invalid JWT token"
            });
    } else {
        res.json(req.user);
    }
});

// @route POST api/users/resetPassword
// @desc resetPassword for user
// @access Public
router.post("/resetPassword", (req, res) => {
    let errors = {};

    req.body.email = !isEmpty(req.body.email) ? req.body.email : "";
    req.body.password = !isEmpty(req.body.password) ? req.body.password : "";
    req.body.confirmPassword = !isEmpty(req.body.confirmPassword) ? req.body.confirmPassword : "";

    // Email checks
    if (Validator.isEmpty(req.body.email)) {
        errors.email = "Email is required";
    } else if (!Validator.isEmail(req.body.email)) {
        errors.email = "Email is invalid";
    }

    // Password checks
    if (Validator.isEmpty(req.body.password)) {
        errors.password = "Password is required";
    }

    if (Validator.isEmpty(req.body.confirmPassword)) {
        errors.confirmPassword = "Confirm password is required";
    }

    if (!Validator.isLength(req.body.password, { min: 6, max: 30 })) {
        errors.password = "Password must be at least 6 characters";
    }

    if (!Validator.equals(req.body.password, req.body.confirmPassword)) {
        errors.confirmPassword = "Passwords mismatch";
    }


    // Check validation
    if (!isEmpty(errors)) {
        return res.status(400).json(errors);
    }

    User.findOne({ email: req.body.email }).then(user => {
        if (user) {
            user.lastUpdationTime = new Date();
            // Hash password before saving in database
            bcrypt.genSalt(10, (err, salt) => {
                bcrypt.hash(req.body.password, salt, (err, hash) => {
                    if (err) throw err;
                    user.password = hash;
                    user.save()
                        .then(user => res.json(user))
                        .catch(err => console.log(err));
                });
            });
        }
    });
});

// @route POST api/users/list
// @desc fetch list of users
// @access Public
router.get("/list", (req, res) => {
    const match = {};
    if (req.query.searchTerm) {
        match.$or = [
            {
                'name': {
                    $regex: `.*${req.query.searchTerm}`,
                    $options: '-i'
                }
            },
            {
                'email': { $regex: `.*${req.query.searchTerm}`, $options: '-i' }
            }
        ]
        // match.name = {
        //     $regex: `.*${req.query.searchTerm}`,
        //     $options: '-i'
        // }
    }

    console.log(match);
    User.find(match).then(user => {
        if (user) {
            res.json(user)
        }
    });
});

// @route POST api/users/remove/:id
// @desc resetPassword for user
// @access Public
router.get("/remove/:id", (req, res) => {
    const id = req.params.id;
    User.findOne({ _id: id }).then(user => {
        if (user) {
            user.remove()
                .then(user => res.json(user))
                .catch(err => console.log(err));
        }
    });
});

// @route POST api/users/updateuser/:id
// @desc update user
// @access Public
router.post("/updateuser/:id", (req, res) => {
    console.log(req);
    const id = req.params.id;
    let errors = {};

    req.body.name = !isEmpty(req.body.name) ? req.body.name : "";
    req.body.email = !isEmpty(req.body.email) ? req.body.email : "";

    // Email checks
    if (Validator.isEmpty(req.body.email)) {
        errors.email = "Email is required";
    } else if (!Validator.isEmail(req.body.email)) {
        errors.email = "Email is invalid";
    }

    // Password checks
    if (req.body.password && Validator.isEmpty(req.body.password)) {
        errors.password = "Password is required";
    }

    if (req.body.confirmPassword && Validator.isEmpty(req.body.confirmPassword)) {
        errors.confirmPassword = "Confirm password is required";
    }

    if (req.body.password && !Validator.isLength(req.body.password, { min: 6, max: 30 })) {
        errors.password = "Password must be at least 6 characters";
    }

    if (req.body.password && req.body.confirmPassword && !Validator.equals(req.body.password, req.body.confirmPassword)) {
        errors.confirmPassword = "Passwords mismatch";
    }


    // Check validation
    if (!isEmpty(errors)) {
        return res.status(400).json(errors);
    }

    User.findOne({ _id: id }).then(user => {
        if (user) {
            user.lastUpdationTime = new Date();
            if (req.body.name) {
                user.name = req.body.name;
            }

            if (req.body.email) {
                user.email = req.body.email;
            }

            if (req.body.password) {
                bcrypt.genSalt(10, (err, salt) => {
                    bcrypt.hash(req.body.password, salt, (err, hash) => {
                        if (err) throw err;
                        user.password = hash;
                        user.save()
                            .then(user => res.json(user))
                            .catch(err => console.log(err));
                    });
                });
            } else {
                user.save()
                    .then(user => res.json(user))
                    .catch(err => console.log(err));
            }
        }
    }).catch(err => console.log(err));
});

module.exports = router;