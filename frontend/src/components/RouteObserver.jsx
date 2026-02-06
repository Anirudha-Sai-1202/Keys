import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { useAuthStore } from '../store/authStore';

const RouteObserver = () => {
  const location = useLocation();
  const { isAuthenticated } = useAuthStore();

  useEffect(() => {
    if (isAuthenticated && location.pathname !== '/login') {
      localStorage.setItem('lastVisitedRoute', location.pathname);
    }
  }, [location.pathname, isAuthenticated]);

  return null;
};

export default RouteObserver;