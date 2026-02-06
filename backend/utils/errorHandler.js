// Custom error classes
export class ValidationError extends Error {
	constructor(message) {
		super(message);
		this.name = 'ValidationError';
		this.statusCode = 400;
	}
}

export class AuthenticationError extends Error {
	constructor(message = 'Authentication failed') {
		super(message);
		this.name = 'AuthenticationError';
		this.statusCode = 401;
	}
}

export class AuthorizationError extends Error {
	constructor(message = 'Access denied') {
		super(message);
		this.name = 'AuthorizationError';
		this.statusCode = 403;
	}
}

export class NotFoundError extends Error {
	constructor(message = 'Resource not found') {
		super(message);
		this.name = 'NotFoundError';
		this.statusCode = 404;
	}
}

export class ConflictError extends Error {
	constructor(message = 'Resource already exists') {
		super(message);
		this.name = 'ConflictError';
		this.statusCode = 409;
	}
}

export class RateLimitError extends Error {
	constructor(message = 'Too many requests') {
		super(message);
		this.name = 'RateLimitError';
		this.statusCode = 429;
	}
}

export class ServerError extends Error {
	constructor(message = 'Internal server error') {
		super(message);
		this.name = 'ServerError';
		this.statusCode = 500;
	}
}

// Error response formatter
export const formatErrorResponse = (error, includeStack = false) => {
	const response = {
		success: false,
		message: error.message || 'An error occurred',
		error: {
			name: error.name || 'Error',
			statusCode: error.statusCode || 500,
		}
	};

	// Include stack trace in development
	if (includeStack && process.env.NODE_ENV === 'development') {
		response.error.stack = error.stack;
	}

	return response;
};

// Async error handler wrapper
export const asyncHandler = (fn) => {
	return (req, res, next) => {
		Promise.resolve(fn(req, res, next)).catch(next);
	};
};

// Global error handler middleware
export const globalErrorHandler = (error, req, res, next) => {
	console.error('Error occurred:', {
		message: error.message,
		stack: error.stack,
		url: req.url,
		method: req.method,
		ip: req.ip,
		userAgent: req.get('User-Agent'),
		timestamp: new Date().toISOString(),
	});

	// Handle specific error types
	let statusCode = error.statusCode || 500;
	let message = error.message || 'Internal server error';

	// Handle MongoDB errors
	if (error.name === 'ValidationError') {
		statusCode = 400;
		if (error.errors && typeof error.errors === 'object') {
			message = Object.values(error.errors).map(val => val.message).join(', ');
		} else {
			message = error.message || 'Validation error';
		}
	} else if (error.code === 11000) {
		statusCode = 409;
		if (error.keyValue && typeof error.keyValue === 'object') {
			const field = Object.keys(error.keyValue)[0];
			message = `${field} already exists`;
		} else {
			message = 'Duplicate key error';
		}
	} else if (error.name === 'CastError') {
		statusCode = 400;
		message = 'Invalid ID format';
	}

	// Handle JWT errors
	if (error.name === 'JsonWebTokenError') {
		statusCode = 401;
		message = 'Invalid token';
	} else if (error.name === 'TokenExpiredError') {
		statusCode = 401;
		message = 'Token expired';
	}

	const response = formatErrorResponse(
		{ ...error, statusCode, message },
		process.env.NODE_ENV === 'development'
	);

	res.status(statusCode).json(response);
};
