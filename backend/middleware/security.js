import helmet from "helmet";

// Helmet configuration for security headers
export const helmetConfig = helmet({
	contentSecurityPolicy: {
		directives: {
			defaultSrc: ["'self'"],
			styleSrc: ["'self'", "'unsafe-inline'"],
			scriptSrc: ["'self'"],
			imgSrc: ["'self'", "data:", "https:"],
			connectSrc: ["'self'"],
			fontSrc: ["'self'"],
			objectSrc: ["'none'"],
			mediaSrc: ["'self'"],
			frameSrc: ["'none'"],
		},
	},
	crossOriginEmbedderPolicy: false, // Disable for development
});

// Request sanitization middleware
export const sanitizeRequest = (req, res, next) => {
	// Remove any potential XSS characters from request body
	if (req.body) {
		for (const key in req.body) {
			if (typeof req.body[key] === 'string') {
				// Basic XSS prevention
				req.body[key] = req.body[key]
					.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
					.replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '')
					.replace(/javascript:/gi, '')
					.replace(/on\w+\s*=/gi, '');
			}
		}
	}
	
	// Remove potential XSS from query parameters
	if (req.query) {
		for (const key in req.query) {
			if (typeof req.query[key] === 'string') {
				req.query[key] = req.query[key]
					.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
					.replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '')
					.replace(/javascript:/gi, '')
					.replace(/on\w+\s*=/gi, '');
			}
		}
	}
	
	next();
};

// IP whitelist middleware (for development/testing)
export const ipWhitelist = (whitelist = []) => {
	return (req, res, next) => {
		if (process.env.NODE_ENV === 'production' && whitelist.length > 0) {
			const clientIP = req.ip || req.connection.remoteAddress;
			if (!whitelist.includes(clientIP)) {
				return res.status(403).json({
					success: false,
					message: 'Access denied from this IP address',
				});
			}
		}
		next();
	};
};

// Request logging middleware
export const requestLogger = (req, res, next) => {
	const start = Date.now();
	
	res.on('finish', () => {
		const duration = Date.now() - start;
		const logData = {
			method: req.method,
			url: req.url,
			status: res.statusCode,
			duration: `${duration}ms`,
			ip: req.ip,
			userAgent: req.get('User-Agent'),
			timestamp: new Date().toISOString(),
		};
		
		// Log errors and slow requests
		if (res.statusCode >= 400) {
			console.warn('⚠️  Request error:', logData);
		} else if (duration > 2000) {
			console.warn('🐌 Slow request:', logData);
		} else if (process.env.NODE_ENV === 'development' && req.url !== '/api/health') {
			// Only log non-health check requests in development
			console.log('📝 Request:', `${req.method} ${req.url} - ${res.statusCode} (${duration}ms)`);
		}
	});
	
	next();
};
