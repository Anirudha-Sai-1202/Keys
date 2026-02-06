import { createTransporter, emailConfig } from "./nodemailer.config.js";
import {
	VERIFICATION_EMAIL_TEMPLATE,
	PASSWORD_RESET_REQUEST_TEMPLATE,
	PASSWORD_RESET_SUCCESS_TEMPLATE,
	WELCOME_EMAIL_TEMPLATE,
	NOTIFICATION_EMAIL_TEMPLATE,
} from "./emailTemplates.js";

// Send verification email
export const sendVerificationEmail = async (email, verificationToken) => {
	const transporter = createTransporter();
	
	const mailOptions = {
		from: emailConfig.from,
		to: email,
		subject: "Verify your email",
		html: VERIFICATION_EMAIL_TEMPLATE.replace("{verificationCode}", verificationToken),
	};

	try {
		const info = await transporter.sendMail(mailOptions);
		console.log("✅ Verification email sent successfully:", info.messageId);
		return info;
	} catch (error) {
		console.error("❌ Error sending verification email:", error);
		throw new Error(`Error sending verification email: ${error.message}`);
	}
};

// Send welcome email
export const sendWelcomeEmail = async (email, name) => {
	const transporter = createTransporter();
	
	const mailOptions = {
		from: emailConfig.from,
		to: email,
		subject: "Welcome to our platform!",
		html: WELCOME_EMAIL_TEMPLATE.replace("{name}", name).replace("{companyName}", emailConfig.from.name),
	};

	try {
		const info = await transporter.sendMail(mailOptions);
		console.log("✅ Welcome email sent successfully:", info.messageId);
		return info;
	} catch (error) {
		console.error("❌ Error sending welcome email:", error);
		throw new Error(`Error sending welcome email: ${error.message}`);
	}
};

// Send password reset email
export const sendPasswordResetEmail = async (email, resetURL) => {
	const transporter = createTransporter();
	
	const mailOptions = {
		from: emailConfig.from,
		to: email,
		subject: "Reset your password",
		html: PASSWORD_RESET_REQUEST_TEMPLATE.replace("{resetURL}", resetURL),
	};

	try {
		const info = await transporter.sendMail(mailOptions);
		console.log("✅ Password reset email sent successfully:", info.messageId);
		return info;
	} catch (error) {
		console.error("❌ Error sending password reset email:", error);
		throw new Error(`Error sending password reset email: ${error.message}`);
	}
};

// Send password reset success email
export const sendResetSuccessEmail = async (email) => {
	const transporter = createTransporter();

	const mailOptions = {
		from: emailConfig.from,
		to: email,
		subject: "Password Reset Successful",
		html: PASSWORD_RESET_SUCCESS_TEMPLATE,
	};

	try {
		const info = await transporter.sendMail(mailOptions);
		console.log("✅ Password reset success email sent successfully:", info.messageId);
		return info;
	} catch (error) {
		console.error("❌ Error sending password reset success email:", error);
		throw new Error(`Error sending password reset success email: ${error.message}`);
	}
};

// Send notification email
export const sendNotificationEmail = async (email, name, title, message, type, metadata = {}) => {
	const transporter = createTransporter();

	// Customize subject based on notification type
	let subject = title;
	if (type === 'key_reminder') {
		subject = `🔑 Key Return Reminder - ${title}`;
	} else if (type === 'security_alert') {
		subject = `🚨 Security Alert - ${title}`;
	} else if (type === 'key_overdue') {
		subject = `⚠️ Overdue Key Alert - ${title}`;
	}

	// Prepare template variables
	const templateVars = {
		name,
		title,
		message,
		type,
		metadata: JSON.stringify(metadata, null, 2),
		currentDate: new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
		currentYear: new Date().getFullYear(),
		companyName: emailConfig.from.name || 'VNR Keys'
	};

	// Replace template variables
	let htmlContent = NOTIFICATION_EMAIL_TEMPLATE;
	Object.keys(templateVars).forEach(key => {
		const regex = new RegExp(`{${key}}`, 'g');
		htmlContent = htmlContent.replace(regex, templateVars[key]);
	});

	const mailOptions = {
		from: emailConfig.from,
		to: email,
		subject: subject,
		html: htmlContent,
	};

	try {
		const info = await transporter.sendMail(mailOptions);
		console.log("✅ Notification email sent successfully:", info.messageId);
		return info;
	} catch (error) {
		console.error("❌ Error sending notification email:", error);
		throw new Error(`Error sending notification email: ${error.message}`);
	}
};
