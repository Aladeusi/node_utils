const jwt=require("jsonwebtoken");

//resposify
const responsify=(res,code,body)=>{
  body=(code.toString().search("20")<0)?{error:body}:{result:body};
  
    if("access_token" in body.result){
        //To enable Postman api client read access_token from this http response
        res.status(code).send({code, body, access_token:body.result.access_token})
    }else{
         res.status(code).send({code, body});
    }

}

//Generate and return jwt access_token of specified user
const generateJwtAccessToken=(res, user, expiresIn)=>{
    jwt.sign({user}, "MyCustomEncryptionSecretKey", {expiresIn},(err, token)=>{
        if(err){
            responsify(res, 500, err);
        }else{
            responsify(res, 200, {access_token:token});
        }
        
    });
} 


//get authenticated user object
const getJwtCurentUser=(req)=>{
   //Perform header-level verification first.
    // Get auth header value
    const bearerHeader = req.headers['authorization'];
    // Check if bearer is undefined
    if(typeof bearerHeader !== 'undefined') {
      // Split at the space
      const bearer = bearerHeader.split(' ');
      // decode user access token to user object using your jwt encoding secret key;
     return jwt.decode(bearer[1], "MyCustomEncryptionSecretKey");
    } else {
      // Forbidden
      return "Bad access token";
    }  

}


// Verify jwt access_token
const jwtAuthorize=(req, res, next)=> {
    //Perform header-level verification first.
    // Get auth header value
    const bearerHeader = req.headers['authorization'];
    // Check if bearer is undefined
    if(typeof bearerHeader !== 'undefined') {
      // Split at the space
      const bearer = bearerHeader.split(' ');
      // Get token from array
      const bearerToken = bearer[1];
      // Set the token
      req.token = bearerToken;
      
      //Now do jwt-level verification for the access token to check if it exist in session.
      jwt.verify(req.token, 'MyCustomEncryptionSecretKey', (err, authData) => {
        if(err) {
          responsify(res, 403, err);
        }else{

            //next middleware
            next();
        }
      });


    } else {
      // Forbidden
      responsify(res, 403, "Unauthorized request.");
    }
  
  }


  

//export list 
module.exports={responsify,jwtAuthorize, generateJwtAccessToken, getJwtCurentUser};