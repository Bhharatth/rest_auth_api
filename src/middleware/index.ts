import express from 'express';
import { merge, get } from 'lodash';
import { getUsersBySessionToken } from '../db/users';

export const isAuthenticated = async (req: express.Request, res: express.Response, next: express.NextFunction) => {

    try {
        const sessionToken = req.cookies['USER-AUTH-COOKIE'];

        if (!sessionToken) {
            return res.sendStatus(403);
        }
        const existingUser = await getUsersBySessionToken(sessionToken);

        if (!existingUser) {
            return res.sendStatus(403);
        }
        merge(req, { identity: existingUser });
        return next();

    } catch (error) {
        console.log(error);
        return res.sendStatus(400);

    }

}

export const isOwner = async (req: express.Request, res: express.Response, next: express.NextFunction) => {

    try {

        const {id} = req.params;
        const currentUserId = get(req, 'identity._id') as string;

        if(!currentUserId){
            res.sendStatus(400);
        }
        
        if(currentUserId.toString() !== id){
            return res.sendStatus(403);
        }
        next();
    } catch (error) {
        console.log(error)
        res.sendStatus(400);
        
    }
}