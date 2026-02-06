import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config();

// Create transporter with environment variables
export const createTransporter = () => {
	const transporter = nodemailer.createTransport({
		host: process.env.EMAIL_HOST,
		port: parseInt(process.env.EMAIL_PORT) || 587,
		secure: process.env.EMAIL_SECURE === 'true', // true for 465, false for other ports
		auth: {
			user: process.env.EMAIL_USER,
			pass: process.env.EMAIL_PASS,
		},
		// Additional options for better reliability
		pool: true,
		maxConnections: 5,
		maxMessages: 100,
		rateLimit: 14, // 14 emails per second max
	});

	return transporter;
};

// Verify transporter configuration
export const verifyTransporter = async () => {
	try {
		const transporter = createTransporter();
		await transporter.verify();
		console.log("✅ Email transporter is ready to send emails");
		return true;
	} catch (error) {
		console.error("❌ Email transporter verification failed:", error.message);
		return false;
	}
};

// Email sender configuration
export const emailConfig = {
	from: {
		name: process.env.EMAIL_FROM_NAME || "Auth Tutorial",
		address: process.env.EMAIL_FROM || process.env.EMAIL_USER,
	},
};
