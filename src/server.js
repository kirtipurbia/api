const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const app = express();
const users = require("./routes/users");
var cors = require('cors')

app.use(cors());
// Bodyparser middleware
app.use(
    bodyParser.urlencoded({
        extended: false
    })
);
app.use(bodyParser.json());
// DB Config
const db = require("../config/keys").mongoURI;
// Connect to MongoDB
mongoose.set("strictQuery", false);
const uri = "mongodb+srv://admin:YOIbMbwMGXYnPKXK@mycluster.9yaphws.mongodb.net/MyDB?retryWrites=true&w=majority";

mongoose
    .connect(
        uri, // db,
        { useNewUrlParser: true }
    )
    .then(() => {
        console.log("MongoDB successfully connected")
        app.use("/api/users", users);
        const port = process.env.PORT || 5000;
        app.listen(port, () => console.log(`Server up and running on port ${port} !`));
    })
    .catch(err => console.log(err));

process.on('unhandledRejection', error => {
    console.log('unhandledRejection', error.message);
});

