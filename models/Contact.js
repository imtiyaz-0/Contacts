const mongoose = require('mongoose');

const contactSchema = new mongoose.Schema({
    name: String ,
    phone: String ,
    email: String,
    linkedin: String,
    twitter: String
});

module.exports=mongoose.model('Contact' , contactSchema);