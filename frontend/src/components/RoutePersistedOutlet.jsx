import { useEffect } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import { useAuthStore } from '../store/authStore';

const RoutePersistedOutlet = () => {
  const location = useLocation();
  const { isAuthenticated } = useAuthStore();

  // Store current route whenever it changes
  useEffect(() => {
    if (isAuthenticated && location.pathname !== '/') {
      localStorage.setItem('lastVisitedRoute', location.pathname);
    }
  }, [location.pathname, isAuthenticated]);

  return <Outlet />;
};

export default RoutePersistedOutlet;