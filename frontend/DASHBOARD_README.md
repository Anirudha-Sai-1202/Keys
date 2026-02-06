# Hackathon Dashboard Boilerplate

A comprehensive, responsive dashboard boilerplate built with React, Tailwind CSS, and Framer Motion for hackathon projects.

## Features

### 🎯 Core Features
- **Responsive Design**: Works seamlessly on desktop, tablet, and mobile devices
- **Modern UI**: Clean, professional interface with smooth animations
- **Authentication Integration**: Built-in login/logout functionality
- **Navigation**: Intuitive navbar and sliding sidebar navigation

### 📱 Dashboard Pages
1. **Home Page** (`/dashboard`)
   - Welcome section with user greeting
   - Statistics cards showing key metrics
   - Recent activity feed
   - Quick action buttons

2. **Profile Page** (`/dashboard/profile`)
   - User profile information display
   - Editable profile form with validation
   - Profile picture placeholder
   - Account statistics

3. **Contact Us Page** (`/dashboard/contact`)
   - Contact information display
   - Contact form with validation
   - Responsive layout with contact details

4. **About Us Page** (`/dashboard/about`)
   - Project mission statement
   - Team member profiles
   - Feature highlights
   - Call-to-action section

### 🎨 Design Features
- **Gradient Backgrounds**: Beautiful gradient color schemes
- **Floating Animations**: Subtle floating shape animations
- **Glass Morphism**: Modern backdrop blur effects
- **Smooth Transitions**: Framer Motion animations throughout
- **Consistent Styling**: Unified design system

### 📱 Responsive Navigation
- **Mobile-First**: Optimized for mobile devices
- **Sliding Sidebar**: Smooth slide-in/out animations
- **Overlay**: Mobile overlay for better UX
- **Desktop Toggle**: Collapsible sidebar for desktop

## Tech Stack

- **React 19**: Latest React with hooks
- **React Router DOM**: Client-side routing
- **Tailwind CSS**: Utility-first CSS framework
- **Framer Motion**: Animation library
- **Lucide React**: Modern icon library
- **Zustand**: State management
- **React Hot Toast**: Toast notifications
- **Vite**: Fast build tool

## Getting Started

### Prerequisites
- Node.js 18+ 
- npm or yarn

### Installation
1. Navigate to the frontend directory:
   ```bash
   cd hack/frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the development server:
   ```bash
   npm run dev
   ```

4. Open your browser and navigate to `http://localhost:5173`

### Authentication
The dashboard requires authentication. Use the existing login system:
- Sign up for a new account
- Verify your email
- Login to access the dashboard

## File Structure

```
src/
├── components/
│   ├── dashboard/
│   │   ├── DashboardLayout.jsx    # Main layout wrapper
│   │   ├── Navbar.jsx             # Top navigation bar
│   │   └── Sidebar.jsx            # Side navigation menu
│   ├── FloatingShape.jsx          # Animated background shapes
│   ├── Input.jsx                  # Form input component
│   └── LoadingSpinner.jsx         # Loading indicator
├── pages/
│   ├── dashboard/
│   │   ├── HomePage.jsx           # Dashboard home page
│   │   ├── ProfilePage.jsx        # User profile page
│   │   ├── ContactPage.jsx        # Contact us page
│   │   └── AboutPage.jsx          # About us page
│   ├── LoginPage.jsx              # Login page
│   ├── SignUpPage.jsx             # Registration page
│   └── ...                       # Other auth pages
├── store/
│   └── authStore.js               # Authentication state management
└── utils/
    ├── validation.js              # Form validation utilities
    └── errorHandler.js            # Error handling utilities
```

## Customization

### Colors
The dashboard uses a green/emerald color scheme. To change colors, update the Tailwind classes:
- Primary: `from-green-500 to-emerald-600`
- Background: `from-gray-900 via-green-900 to-emerald-900`

### Navigation
Add new pages by:
1. Creating a new page component in `src/pages/dashboard/`
2. Adding the route to `App.jsx`
3. Adding the menu item to `Sidebar.jsx`

### Styling
All components use Tailwind CSS classes. Modify the classes to customize:
- Layout and spacing
- Colors and gradients
- Typography
- Animations

## Features in Detail

### Profile Management
- Edit profile information
- Form validation
- Loading states
- Success/error notifications

### Contact Form
- Form validation
- Simulated form submission
- Responsive layout
- Contact information display

### Responsive Design
- Mobile-first approach
- Breakpoint-specific layouts
- Touch-friendly interactions
- Optimized for all screen sizes

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is open source and available under the MIT License.
