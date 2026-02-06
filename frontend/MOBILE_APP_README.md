# Mobile Key Management System

A real-time key management system designed for college environments with two distinct user interfaces optimized for mobile devices.

## User Types

### 🔐 Security User (Key Monitor)
**Role:** `security`
**Dashboard:** `/dashboard/security`

#### Features:
- **QR Scanner Tab**:
  - Large, easy-to-use QR scanner interface
  - Scans QR codes from faculty for key requests and returns
  - Shows detailed popup with key information after scanning
  - Displays key number in large, bold text for visibility

- **Available Keys Tab**:
  - Lists all keys currently present in the key room
  - Green status indicators for available keys
  - Shows key number, name, and location
  - Real-time count of available keys

- **Unavailable Keys Tab**:
  - Lists all keys that are currently taken
  - Red status indicators for unavailable keys
  - Shows who took each key and when
  - **"Collect" button** for manual key return (when faculty returns without scanning)
  - Real-time count of taken keys

#### Mobile-Friendly Design:
- Large buttons and touch targets
- High contrast colors and bold text
- Simple navigation with bottom tabs
- Minimal options to reduce confusion

---

### 👨‍🏫 Faculty/Attender User (Key Taker)
**Role:** `faculty`
**Dashboard:** `/dashboard/faculty`

#### Features:
- **Taken Keys Tab**:
  - Lists all keys currently held by the user
  - Shows time when each key was taken
  - **QR Code generation** for returning keys
  - Click "Show Return QR" to display QR code for security to scan

- **Key List Tab**:
  - **Searchable list** of all available keys
  - **"Frequently Used Keys"** section at the top
    - Shows keys marked as frequently used
    - ⭐ Star icon to add/remove keys from frequent list
  - **"All Keys"** section below
    - Complete list of all keys in the system
    - Search functionality to find specific keys
  - **Key Status Indicators**:
    - Available keys: Green "Generate QR to Request" button
    - Unavailable keys: Red "Not Available" label with current holder's name

#### Mobile-Friendly Design:
- Responsive card layouts
- Touch-friendly search interface
- Clear visual status indicators
- Easy QR code generation and display

---

## QR Code Workflow

### Key Request Process:
1. Faculty finds desired key in "Key List"
2. Clicks "Generate QR to Request Key"
3. QR code is generated and displayed
4. Security scans the QR code
5. System shows popup with key details to security
6. Security confirms → Key is assigned to faculty
7. Key moves to faculty's "Taken Keys" and security's "Unavailable Keys"

### Key Return Process:
1. Faculty goes to "Taken Keys" tab
2. Clicks "Show Return QR" for the key to return
3. QR code is displayed
4. Security scans the QR code
5. System shows popup confirming return
6. Key moves back to "Available Keys" for security

### Manual Collection (Security Only):
- If faculty returns key without scanning, security can manually mark it as returned
- Click "Collect" button in "Unavailable Keys" tab
- Shows confirmation popup with key number in large text

---

## Technical Features

### Real-time Updates:
- Key status changes are reflected immediately across all users
- Live counts of available/unavailable keys
- Instant QR code generation

### Mobile Optimization:
- Responsive design for Android/iOS
- Touch-friendly interface elements
- Bottom navigation for easy thumb access
- Large text and buttons for accessibility

### QR Code Technology:
- Uses `react-qr-code` for generation
- Uses `qr-scanner` for camera-based scanning
- JSON-encoded data with request/return types
- Unique IDs for tracking transactions

### Status Management:
- Green: Available keys
- Red: Unavailable/taken keys
- Yellow: Pending states (if needed)
- Visual indicators with icons and colors

---

## Getting Started

1. **Login** with your credentials
2. **Role-based redirect** to appropriate dashboard
3. **Security users** start with QR Scanner tab
4. **Faculty users** start with Taken Keys tab
5. **Navigate** using bottom tab bar

---

## Key Features Summary

✅ **Mobile-first design**
✅ **Role-based access control**
✅ **Real-time QR code generation/scanning**
✅ **Manual key collection option**
✅ **Frequently used keys management**
✅ **Search functionality**
✅ **Visual status indicators**
✅ **Large, accessible UI elements**
✅ **Responsive card layouts**
✅ **Bottom navigation for mobile**

The system is designed to be extremely simple and intuitive for non-technical users while providing all necessary functionality for efficient key management in a college environment.