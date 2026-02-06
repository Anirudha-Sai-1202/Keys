// Email validation
export const validateEmail = (email) => {
	if (!email) {
		return { isValid: false, message: "Email is required" };
	}
	
	const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
	if (!emailRegex.test(email)) {
		return { isValid: false, message: "Please provide a valid email address" };
	}
	
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
	
	const trimmedName = name.trim();
	
	if (trimmedName.length < 2) {
		return { isValid: false, message: "Name must be at least 2 characters long" };
	}
	
	if (trimmedName.length > 50) {
		return { isValid: false, message: "Name is too long" };
	}
	
	// Check for valid characters (letters, spaces, hyphens, apostrophes)
	if (!/^[a-zA-Z\s\-']+$/.test(trimmedName)) {
		return { isValid: false, message: "Name can only contain letters, spaces, hyphens, and apostrophes" };
	}
	
	return { isValid: true, sanitizedValue: trimmedName };
};

// Verification code validation
export const validateVerificationCode = (code) => {
	if (!code) {
		return { isValid: false, message: "Verification code is required" };
	}
	
	const codeStr = code.toString().trim();
	if (!/^\d{6}$/.test(codeStr)) {
		return { isValid: false, message: "Verification code must be 6 digits" };
	}
	
	return { isValid: true };
};

// Password strength checker
export const getPasswordStrength = (password) => {
	if (!password) return { score: 0, feedback: [] };
	
	let score = 0;
	const feedback = [];
	
	// Length check
	if (password.length >= 8) {
		score += 1;
	} else {
		feedback.push("Use at least 8 characters");
	}
	
	// Uppercase check
	if (/[A-Z]/.test(password)) {
		score += 1;
	} else {
		feedback.push("Add uppercase letters");
	}
	
	// Lowercase check
	if (/[a-z]/.test(password)) {
		score += 1;
	} else {
		feedback.push("Add lowercase letters");
	}
	
	// Number check
	if (/\d/.test(password)) {
		score += 1;
	} else {
		feedback.push("Add numbers");
	}
	
// Special character check
  if (/[!@#$%^&*()_+\-[\]{};':"\\|,.<>/?]/.test(password)) {
		score += 1;
	} else {
		feedback.push("Add special characters");
	}
	
	return { score, feedback };
};

// Form validation helper
export const validateForm = (fields, validationRules) => {
	const errors = {};
	let isValid = true;
	
	for (const [fieldName, value] of Object.entries(fields)) {
		if (validationRules[fieldName]) {
			const validation = validationRules[fieldName](value);
			if (!validation.isValid) {
				errors[fieldName] = validation.message;
				isValid = false;
			}
		}
	}
	
	return { isValid, errors };
};
