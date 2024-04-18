const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const nodemailer = require('nodemailer')
const dotenv = require('dotenv')
dotenv.config()
const authMiddleware = require('./middleware/token')
const User = require('./models/User')

const app = express()



//mongodb_connection
try {
const MONGODB_URI = process.env.MONGODB_URI 
mongoose.connect(MONGODB_URI,{
    useNewUrlParser: true,
    useUnifiedTopology: true
})
}
catch (err){
    console.log(err)
}

app.post('/signup', async(req,res) => {
    try {
        const {email,password} = req.body
        const hashPass = await bcrypt.hash(password,10)

        //otp generation
        const otp = Math.floor(Math.random()*1000000)  
        
        const newUser = new User({email,password: hashPass, otp})
        await newUser.save()

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL,
                pass: process.env.PASSWORD
            }
        })

        await transporter.sendMail({
            to: email,
            subject: 'email verification',
            text: `OTP to complete registration is ${otp}`
        })

        res.status(200).send('OTP sent')
    }
    catch (err) {
        console.log(err)
    }
})

app.post('/verify', async(req,res) => {
    try {
        const {email, otp} = req.body
        const user = await User.findOne({ email,otp})

        if(!user) {
            return res.status(400).send('invalid otp')
        }

        res.status(200).send('Account is verified')
    }
    catch (err) {
        console.log(err)
    }
})

//adding extra info regarding a user

app.post('/more-info', authMiddleware ,async(req,res) => {
    try {
        const {location,age,workDetails} = req.body

        const user = await User.findById(req.userId)
         
        if(!user) {
            return res.status(400).send('no such error')
        }

        user.location = location
        user.age = age
        user.workDetails = workDetails

        await user.save()

        res.status(200).send('details saved')
    } 
    catch(err){
        console.log(err)
    }
})

//login
app.post('/login', async(req,res) => {
    try {
        const {email,password} = req.body

        const user = await User.findOne({email})

        if(!user || !(await bcrypt.compare(password,user.password))) {
            return res.status(400).send('invalid user')
        }
        // jwt token generate
        const token = jwt.sign({ userId: user._id}, process.env.JWT_SECRET || 'yoursecretkey', {expiresIn: '3h'})

        res.status(200).json({token})
    } 
    catch(err){
        console.log(err)
    }
})

//complete profile
app.get('/profile', async(req,res) => {
    try {
        const user = await User.findById(req.userId)

        if(!user) {
            return res.status(400).send('User not found')
        }

        res.status(200).json(user)
    }
    catch (err) {
        console.log(err)
    }
})

const PORT = process.env.PORT || 3000
app.listen(PORT,() => {
    console.log(`Server started on ${PORT}`)
})