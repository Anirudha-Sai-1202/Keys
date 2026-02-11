import { verifySSOToken } from '../utils/ssoAuth.js';
import { asyncHandler } from '../utils/errorHandler.js';

/**
 * Middleware to verify SSO tokens
 * This middleware checks if the user is authenticated via SSO
 * and attaches user info to the request
 */
export const verifySSOTokenMiddleware = asyncHandler(async (req, res, next) => {
    try {
        // Try to get token from cookie first (SSO sets it as httpOnly cookie)
        let token = req.cookies.userToken;

        // If not in cookie, try Authorization header
        if (!token && req.headers.authorization?.startsWith('Bearer ')) {
            token = req.headers.authorization.substring(7);
        }

        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required - no token provided'
            });
        }

        // Verify token with SSO server
        const result = await verifySSOToken(token);

        if (!result.valid) {
            return res.status(401).json({
                success: false,
                message: 'Invalid or expired token'
            });
        }

        // Attach user info to request
        req.ssoUser = result.user;
        req.userId = result.user.id || result.user._id;

        next();
    } catch (error) {
        console.error('SSO token verification error:', error);
        return res.status(500).json({
            success: false,
            message: 'Error verifying authentication'
        });
    }
});

/**
 * Hybrid middleware that tries both local and SSO token verification
 * This allows gradual migration from local to SSO authentication
 */
export const verifyHybridToken = asyncHandler(async (req, res, next) => {
    try {
        // Try to get token from cookie or header
        let token = req.cookies.userToken || req.cookies.token;

        if (!token && req.headers.authorization?.startsWith('Bearer ')) {
            token = req.headers.authorization.substring(7);
        }

        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required - no token provided'
            });
        }

        // First, try SSO verification
        try {
            const ssoResult = await verifySSOToken(token);
            if (ssoResult.valid) {
                req.ssoUser = ssoResult.user;
                req.userId = ssoResult.user.id || ssoResult.user._id;
                req.authMethod = 'sso';
                return next();
            }
        } catch (ssoError) {
            console.log('SSO verification failed, trying local verification...');
        }

        // If SSO fails, try local JWT verification
        const jwt = await import('jsonwebtoken');
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Token is valid - fetch user from database
        const User = (await import('../models/user.model.js')).default;
        const user = await User.findById(decoded.userId).select('-__v');

        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'User not found'
            });
        }

        req.user = user;
        req.userId = user._id.toString();
        req.authMethod = 'local';
        next();
    } catch (error) {
        console.error('Authentication error:', error);
        return res.status(401).json({
            success: false,
            message: 'Invalid or expired token'
        });
    }
});
