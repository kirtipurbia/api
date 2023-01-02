const jwt = require("jsonwebtoken");
const User = require("../models/User");
const keys = require("../../config/keys");

const verifyToken = (req, res, next) => {
    if (req.headers && req.headers.authorization) {
        jwt.verify(req.headers.authorization, keys.secretOrKey, function (err, decode) {
            if (err) req.user = undefined;
            if (decode && decode.id) {
                User.findOne({
                    _id: decode.id
                })
                    .exec((err, user) => {
                        if (err) {
                            res.status(500)
                                .send({
                                    message: err
                                });
                        } else {
                            req.user = user;
                            next();
                        }
                    })
            }
        });
    } else {
        req.user = undefined;
        next();
    }
};
module.exports = verifyToken;