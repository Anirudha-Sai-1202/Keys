import toast from "react-hot-toast";

// Error message mapping for better user experience
const ERROR_MESSAGES = {
	// Network errors
	'Network Error': 'Unable to connect to the server. Please check your internet connection.',
	'ERR_NETWORK': 'Network connection failed. Please try again.',
	'ERR_INTERNET_DISCONNECTED': 'No internet connection. Please check your network.',
	
	// Authentication errors
	'Invalid credentials': 'The email or password you entered is incorrect.',
	'User already exists': 'An account with this email already exists.',
	'User not found': 'No account found with this email address.',
	'Invalid or expired verification code': 'The verification code is invalid or has expired.',
	'Invalid or expired reset token': 'The password reset link is invalid or has expired.',
	
	// Validation errors
	'All fields are required': 'Please fill in all required fields.',
	'Email is required': 'Please enter your email address.',
	'Password is required': 'Please enter your password.',
	'Name is required': 'Please enter your name.',
	
	// Server errors
	'Server error': 'Something went wrong on our end. Please try again later.',
	'Internal server error': 'Server is temporarily unavailable. Please try again later.',
};

// Get user-friendly error message
export const getUserFriendlyMessage = (error) => {
	if (!error) return 'An unexpected error occurred';
	
	// If it's a string, check if we have a mapping
	if (typeof error === 'string') {
		return ERROR_MESSAGES[error] || error;
	}
	
	// If it's an axios error
	if (error.response) {
		const message = error.response.data?.message || error.message;
		return ERROR_MESSAGES[message] || message || 'Server error occurred';
	}
	
	// If it's a network error
	if (error.request) {
		return ERROR_MESSAGES[error.code] || ERROR_MESSAGES['Network Error'];
	}
	
	// Default case
	const message = error.message || error.toString();
	return ERROR_MESSAGES[message] || message || 'An unexpected error occurred';
};

// Handle and display error with toast
export const handleError = (error, customMessage = null) => {
	const message = customMessage || getUserFriendlyMessage(error);
	
	// Log error for debugging (only in development)
	if (import.meta.env.DEV) {
		console.error('Error occurred:', error);
	}
	
	// Show toast notification
	toast.error(message, {
		duration: 5000,
		position: 'top-center',
		style: {
			background: '#ef4444',
			color: 'white',
		},
	});
	
	return message;
};

// Handle success messages
export const handleSuccess = (message, options = {}) => {
	toast.success(message, {
		duration: 4000,
		position: 'top-center',
		style: {
			background: '#10b981',
			color: 'white',
		},
		...options,
	});
};

// Handle loading states
export const handleLoading = (message = 'Loading...') => {
	return toast.loading(message, {
		position: 'top-center',
	});
};

// Dismiss toast
export const dismissToast = (toastId) => {
	toast.dismiss(toastId);
};

// Async operation wrapper with error handling
export const withErrorHandling = async (operation, errorMessage = null) => {
	try {
		return await operation();
	} catch (error) {
		handleError(error, errorMessage);
		throw error; // Re-throw so calling code can handle it if needed
	}
};

// Form error state manager
export class FormErrorManager {
	constructor() {
		this.errors = {};
	}
	
	setError(field, message) {
		this.errors[field] = message;
	}
	
	clearError(field) {
		delete this.errors[field];
	}
	
	clearAllErrors() {
		this.errors = {};
	}
	
	getError(field) {
		return this.errors[field];
	}
	
	hasError(field) {
		return !!this.errors[field];
	}
	
	hasAnyErrors() {
		return Object.keys(this.errors).length > 0;
	}
	
	getAllErrors() {
		return { ...this.errors };
	}
}
