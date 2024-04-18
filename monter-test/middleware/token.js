const jwt = require('jsonwebtoken')

module.exports = (req,res,next) => {
    const token = req.headers.authorization?.split(' ')[1]

    if(!token) {
        return res.status(401).send('Access denied')
    }

    try {
        const decodedToken = jwt.verify(token,'secretKey')
        req.userId = decodedToken.userId
        next()
    }
    catch(err){
        console.log(err)
    }
}