/* eslint-disable react-refresh/only-export-components */
import { Navigate } from 'react-router-dom';
import { useAuthStore } from '../../store/authStore';

/**
 * Component to protect routes based on user roles
 * @param {Object} props
 * @param {React.ReactNode} props.children - Child components to render if access is granted
 * @param {string|string[]} props.allowedRoles - Role(s) that are allowed to access this route
 * @param {string} props.redirectTo - Where to redirect if access is denied (default: '/dashboard')
 * @param {React.ReactNode} props.fallback - Component to show if access is denied (alternative to redirect)
 */
const RoleProtectedRoute = ({ 
	children, 
	allowedRoles, 
	redirectTo = '/dashboard',
	fallback = null 
}) => {
	const { isAuthenticated, user, hasAnyRole } = useAuthStore();

	// Check if user is authenticated
	if (!isAuthenticated) {
		return <Navigate to='/login' replace />;
	}

	// Check if user is verified
	if (!user?.isVerified) {
		return <Navigate to='/verify-email' replace />;
	}

	// Normalize allowedRoles to array
	const rolesArray = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];

	// Check if user has required role
	const hasAccess = hasAnyRole(rolesArray);

	if (!hasAccess) {
		// If fallback component is provided, show it instead of redirecting
		if (fallback) {
			return fallback;
		}
		
		// Otherwise redirect to specified route
		return <Navigate to={redirectTo} replace />;
	}

	return children;
};

/**
 * Higher-order component for role-based route protection
 * @param {string|string[]} allowedRoles - Role(s) that are allowed
 * @param {Object} options - Additional options
 * @returns {Function} Component wrapper
 */
export const withRoleProtection = (allowedRoles, options = {}) => {
	return (Component) => {
		const WrappedComponent = (props) => (
			<RoleProtectedRoute allowedRoles={allowedRoles} {...options}>
				<Component {...props} />
			</RoleProtectedRoute>
		);
		
		WrappedComponent.displayName = `withRoleProtection(${Component.displayName || Component.name})`;
		return WrappedComponent;
	};
};

/**
 * Component to show different content based on user role
 * @param {Object} props
 * @param {React.ReactNode} props.adminContent - Content for admin users
 * @param {React.ReactNode} props.operatorContent - Content for operator users
 * @param {React.ReactNode} props.responderContent - Content for responder users
 * @param {React.ReactNode} props.defaultContent - Default content if role doesn't match
 */
export const RoleBasedContent = ({ 
	adminContent, 
	operatorContent, 
	responderContent, 
	defaultContent = null 
}) => {
	const { user } = useAuthStore();

	if (!user?.role) {
		return defaultContent;
	}

	switch (user.role) {
		case 'admin':
			return adminContent || defaultContent;
		case 'operator':
			return operatorContent || defaultContent;
		case 'responder':
			return responderContent || defaultContent;
		default:
			return defaultContent;
	}
};

/**
 * Hook to check if current user has specific role(s)
 * @param {string|string[]} roles - Role(s) to check
 * @returns {boolean} Whether user has the role(s)
 */
export const useRoleCheck = (roles) => {
	const { hasAnyRole } = useAuthStore();
	const rolesArray = Array.isArray(roles) ? roles : [roles];
	return hasAnyRole(rolesArray);
};

export default RoleProtectedRoute;
