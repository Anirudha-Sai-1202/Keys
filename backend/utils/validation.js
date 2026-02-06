import validator from "validator";

// Email validation
export const validateEmail = (email) => {
	if (!email) {
		return { isValid: false, message: "Email is required" };
	}
	
	if (!validator.isEmail(email)) {
		return { isValid: false, message: "Please provide a valid email address" };
	}
	
	// Additional email length check
	if (email.length > 254) {
		return { isValid: false, message: "Email address is too long" };
	}
	
	return { isValid: true };
};

// Password validation
export const validatePassword = (password) => {
	if (!password) {
		return { isValid: false, message: "Password is required" };
	}
	
	if (password.length < 6) {
		return { isValid: false, message: "Password must be at least 6 characters long" };
	}
	
	if (password.length > 128) {
		return { isValid: false, message: "Password is too long" };
	}
	
	// Check for at least one letter and one number
	if (!/(?=.*[a-zA-Z])(?=.*\d)/.test(password)) {
		return { isValid: false, message: "Password must contain at least one letter and one number" };
	}
	
	return { isValid: true };
};

// Name validation
export const validateName = (name) => {
	if (!name) {
		return { isValid: false, message: "Name is required" };
	}
	
	// Sanitize name - remove extra spaces and trim
	const sanitizedName = name.trim().replace(/\s+/g, ' ');
	
	if (sanitizedName.length < 2) {
		return { isValid: false, message: "Name must be at least 2 characters long" };
	}
	
	if (sanitizedName.length > 50) {
		return { isValid: false, message: "Name is too long" };
	}
	
	// Check for valid characters (letters, spaces, hyphens, apostrophes)
	if (!/^[a-zA-Z\s\-']+$/.test(sanitizedName)) {
		return { isValid: false, message: "Name can only contain letters, spaces, hyphens, and apostrophes" };
	}
	
	return { isValid: true, sanitizedValue: sanitizedName };
};

// Verification code validation
export const validateVerificationCode = (code) => {
	if (!code) {
		return { isValid: false, message: "Verification code is required" };
	}
	
	// Convert to string and check if it's 6 digits
	const codeStr = code.toString();
	if (!/^\d{6}$/.test(codeStr)) {
		return { isValid: false, message: "Verification code must be 6 digits" };
	}
	
	return { isValid: true };
};

// Reset token validation
export const validateResetToken = (token) => {
	if (!token) {
		return { isValid: false, message: "Reset token is required" };
	}
	
	// Check if token is a valid hex string of appropriate length
	if (!/^[a-f0-9]{40}$/.test(token)) {
		return { isValid: false, message: "Invalid reset token format" };
	}
	
	return { isValid: true };
};

// Sanitize email
export const sanitizeEmail = (email) => {
	if (!email) return email;
	return validator.normalizeEmail(email, {
		gmail_lowercase: true,
		gmail_remove_dots: false,
		gmail_remove_subaddress: false,
		outlookdotcom_lowercase: true,
		outlookdotcom_remove_subaddress: false,
		yahoo_lowercase: true,
		yahoo_remove_subaddress: false,
		icloud_lowercase: true,
		icloud_remove_subaddress: false,
	});
};

// General input sanitization
export const sanitizeInput = (input) => {
	if (typeof input !== 'string') return input;
	
	// Remove potential XSS characters and trim
	return validator.escape(input.trim());
};
