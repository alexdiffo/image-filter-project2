import * as jwt from 'jsonwebtoken';
import { Router, Request, Response } from 'express';
import { NextFunction } from 'connect';
import { config } from './config/config';

const router: Router = Router();

interface User {
    email: string,
    password: string
}

const user: User = {
    email: process.env.APP_USERMAIL,
    password: process.env.APP_PASSWORD
}



function generateJWT(user: User): string {
    //@TODO Use jwt to create a new JWT Payload containing
    return jwt.sign(user, config.jwt.secret);
}


// Generate JWT
router.get('/', async (req: Request, res: Response) => {

    const jwt = generateJWT(user);
    res.status(200).send({ message: " token for authorization ", token: jwt });
});


export const Auth: Router = router;




export function requireAuth(req: Request, res: Response, next: NextFunction) {
    //console.warn("auth.router not yet implemented, you'll cover this in lesson 5")
    //return next();
    if (!req.headers || !req.headers.authorization) {
        return res.status(401).send({ message: 'No authorization headers.' });
    }


    const token_bearer = req.headers.authorization.split(' ');
    if (token_bearer.length != 2) {
        return res.status(401).send({ message: 'Malformed token.' });
    }

    const token = token_bearer[1];

    return jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(500).send({ auth: false, message: 'Failed to authenticate.' });
        }
        return next();
    });
}