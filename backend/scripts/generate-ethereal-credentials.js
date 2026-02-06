import nodemailer from 'nodemailer';

// Generate Ethereal email credentials for testing
async function generateEtherealCredentials() {
    try {
        // Generate test SMTP service account from ethereal.email
        const testAccount = await nodemailer.createTestAccount();
        
        console.log('🎉 Ethereal Email Test Account Created!');
        console.log('');
        console.log('Add these credentials to your .env file:');
        console.log('');
        console.log('EMAIL_HOST=smtp.ethereal.email');
        console.log('EMAIL_PORT=587');
        console.log('EMAIL_SECURE=false');
        console.log(`EMAIL_USER=${testAccount.user}`);
        console.log(`EMAIL_PASS=${testAccount.pass}`);
        console.log(`EMAIL_FROM=${testAccount.user}`);
        console.log('EMAIL_FROM_NAME=hackathon');
        console.log('');
        console.log('📧 Preview emails at: https://ethereal.email/');
        console.log('');
        console.log('Note: Ethereal is for testing only - emails won\'t be delivered to real recipients');
        
    } catch (error) {
        console.error('❌ Error generating Ethereal credentials:', error.message);
    }
}

generateEtherealCredentials();
