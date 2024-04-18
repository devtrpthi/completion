const mongoose = require('mongoose')

const userSchema = new mongoose.Schema({
    email: {type: String, required: true, unique: true},
    password: {type: String, required: true},
    otp: {type: String},
    location: { type: String},
    age: {type: Number},
    workDetails: {type: String}
})

module.exports = mongoose.model('User', userSchema)