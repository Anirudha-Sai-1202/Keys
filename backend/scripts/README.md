# VNR Keys Management System - Scripts

This directory contains utility scripts for managing the VNR Keys system.

## Available Scripts

### 1. User Import Script (`importUsers.js`)

Imports users with specific roles into the database. Designed to handle system administrators and security personnel.

#### Usage

```bash
# Import users (makes actual changes)
npm run import:users

# Preview changes without making them (dry run)
npm run import:users -- --dry-run
npm run import:users -- -d

# Show help
npm run import:users -- --help
```

#### Features

- ✅ **Data Validation**: Validates email format, role, and name before import
- ✅ **Duplicate Handling**: Gracefully handles existing users and updates roles if needed
- ✅ **Dry Run Mode**: Preview changes without modifying the database
- ✅ **Error Handling**: Comprehensive error handling with detailed logging
- ✅ **System Integration**: Generates compatible Google IDs for non-OAuth users
- ✅ **Domain Validation**: Warns about non-vnrvjiet.in email addresses

#### Current Users

The script is configured to import:
- `23071a7228@vnrvjiet.in` → **admin** role
- `security@vnrvjiet.in` → **security** role

#### Customization

To add more users, edit the `usersToImport` array in `importUsers.js`:

```javascript
const usersToImport = [
  {
    email: "user@vnrvjiet.in",
    name: "User Name",
    role: "admin", // or "security", "faculty", "pending"
    description: "User description"
  },
  // Add more users here...
];
```

#### Valid Roles

- `admin` - Full system access
- `security` - Security and monitoring access
- `faculty` - Faculty-specific features (requires department and facultyId)
- `pending` - Incomplete registration

### 2. API Keys Import Script (`importApiKeys.js`)

Imports department API keys into the database.

```bash
npm run import:keys
```

### 3. Other Scripts

- `npm run seed:keys` - Seed initial key data
- `npm run test:db` - Test database connection
- `npm run check-env` - Check environment configuration

## Database Connection

All scripts use the `MONGO_URI` environment variable from your `.env` file to connect to MongoDB.

## Error Handling

Scripts include comprehensive error handling:
- Validation errors are displayed with specific messages
- Database connection issues are handled gracefully
- Duplicate key errors are managed appropriately
- All operations are logged with clear status indicators

## Security Considerations

- System users are created with generated Google IDs for OAuth compatibility
- All users are marked as verified by default
- Email addresses are sanitized before storage
- Role validation ensures only valid roles are assigned

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
   - Check your `MONGO_URI` in `.env`
   - Ensure MongoDB is running
   - Verify network connectivity

2. **Validation Errors**
   - Check email format
   - Ensure role is valid
   - Verify name length (2-50 characters)

3. **Duplicate User Errors**
   - Script handles duplicates gracefully
   - Existing users will have their roles updated if different

### Getting Help

Run any script with `--help` flag for detailed usage information:

```bash
npm run import:users -- --help
```

## Development

When modifying scripts:
1. Test with `--dry-run` first
2. Validate all user input
3. Include comprehensive error handling
4. Add appropriate logging
5. Update this documentation
