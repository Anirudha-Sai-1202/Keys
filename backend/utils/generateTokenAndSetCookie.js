import jwt from "jsonwebtoken";

export const generateTokenAndSetCookie = (res, userId, role) => {
	const token = jwt.sign({ userId, role }, process.env.JWT_SECRET, {
		expiresIn: "7d",
	});

	// Cookie configuration for production deployment
	const cookieOptions = {
		httpOnly: true,
		secure: process.env.NODE_ENV === "production",
		sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
		maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
	};

	console.log('🍪 Setting cookie with options:', cookieOptions);
	console.log('🌍 Environment:', process.env.NODE_ENV);
	console.log('🔗 Client URL:', process.env.CLIENT_URL);

	res.cookie("token", token, cookieOptions);

	// Also try setting a test cookie to debug
	if (process.env.NODE_ENV === "production") {
		res.cookie("test-cookie", "test-value", {
			httpOnly: false, // Make it accessible to JS for debugging
			secure: true,
			sameSite: "none",
			maxAge: 60000, // 1 minute
		});
	}

	return token;
};
