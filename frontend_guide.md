# Frontend Implementation Guide

## API Client Setup

Create a custom API client that automatically adds the session ID to all requests:

```javascript
// src/api/apiClient.js
import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000'; // Change to your backend URL

// Create axios instance
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor - add session ID from localStorage if available
apiClient.interceptors.request.use(
  (config) => {
    const sessionId = localStorage.getItem('sessionId');
    if (sessionId) {
      config.headers['X-Session-Id'] = sessionId;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor to handle session expiration
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    
    // If error is 401 (Unauthorized) and not from a login attempt or refresh attempt
    if (error.response && error.response.status === 401 && 
        !originalRequest._retry && 
        !originalRequest.url.includes('/api/accounts/login/') &&
        !originalRequest.url.includes('/api/accounts/refresh-session/')) {
      
      originalRequest._retry = true;
      
      try {
        // Try refreshing the session
        const response = await axios.post(`${API_BASE_URL}/api/accounts/refresh-session/`, {}, {
          headers: {
            'Content-Type': 'application/json',
            'X-Session-Id': localStorage.getItem('sessionId')
          }
        });
        
        // Store new session ID
        if (response.data.session_id) {
          localStorage.setItem('sessionId', response.data.session_id);
          
          // Update header for the original request
          originalRequest.headers['X-Session-Id'] = response.data.session_id;
          
          // Retry the original request
          return apiClient(originalRequest);
        }
      } catch (refreshError) {
        // If refresh fails, redirect to login
        localStorage.removeItem('sessionId');
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }
    
    return Promise.reject(error);
  }
);

// Login function that stores sessionId
export const login = async (email, password) => {
  try {
    const response = await apiClient.post('/api/accounts/login/', { email, password });
    
    // Store session ID from response
    if (response.data.session_id) {
      localStorage.setItem('sessionId', response.data.session_id);
    }
    
    return response.data;
  } catch (error) {
    console.error('Login failed:', error);
    throw error;
  }
};

// Logout function that clears the stored sessionId
export const logout = async () => {
  try {
    await apiClient.post('/api/accounts/logout/');
    localStorage.removeItem('sessionId');
  } catch (error) {
    console.error('Logout failed:', error);
    throw error;
  }
};

// Check if session is valid
export const checkSession = async () => {
  try {
    const response = await apiClient.get('/api/accounts/session/status/');
    return response.data.is_authenticated;
  } catch (error) {
    console.error('Session check failed:', error);
    return false;
  }
};

export default apiClient;
```

## Login Component Example

```jsx
import React, { useState } from 'react';
import { login } from '../api/apiClient';
import { useNavigate } from 'react-router-dom';

function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const data = await login(email, password);
      console.log('Login successful:', data);
      navigate('/dashboard'); // Redirect to dashboard
    } catch (err) {
      setError(err.response?.data?.error || 'Login failed');
    }
  };

  return (
    <form onSubmit={handleLogin}>
      <h2>Login</h2>
      {error && <div className="error">{error}</div>}
      <div>
        <label>Email:</label>
        <input 
          type="email" 
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
      </div>
      <div>
        <label>Password:</label>
        <input 
          type="password" 
          value={password}
          onChange={(e) => setPassword(e.value)}
          required
        />
      </div>
      <button type="submit">Login</button>
    </form>
  );
}

export default LoginPage;
```

## Employee List Component Example

```jsx
import React, { useState, useEffect } from 'react';
import apiClient from '../api/apiClient';

function EmployeeList() {
  const [employees, setEmployees] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchEmployees = async () => {
      try {
        setLoading(true);
        // The apiClient will automatically add X-Session-Id header
        const response = await apiClient.get('/api/accounts/company/employees/');
        setEmployees(response.data);
        setError(null);
      } catch (err) {
        console.error('Error details:', err);
        setError(err.response?.data?.error || 'Failed to load employees');
      } finally {
        setLoading(false);
      }
    };

    fetchEmployees();
  }, []);

  if (loading) return <div>Loading employees...</div>;
  if (error) return <div>Error: {error}</div>;

  return (
    <div>
      <h2>Employee List</h2>
      {employees.length === 0 ? (
        <p>No employees found</p>
      ) : (
        <ul>
          {employees.map(employee => (
            <li key={employee.user_id}>
              {employee.first_name} {employee.last_name} - {employee.email}
              <button onClick={() => handleDelete(employee.user_id)}>Delete</button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );

  // Delete employee function
  async function handleDelete(employeeId) {
    try {
      await apiClient.delete(`/api/accounts/company/employees/${employeeId}/`);
      setEmployees(employees.filter(emp => emp.user_id !== employeeId));
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to delete employee');
    }
  }
}

export default EmployeeList;
```

## Authentication Context

Create an Authentication Context to manage session state across your application:

```jsx
// src/context/AuthContext.js
import React, { createContext, useState, useEffect, useContext } from 'react';
import { useNavigate } from 'react-router-dom';
import { login as apiLogin, logout as apiLogout, checkSession } from '../api/apiClient';

// Create context
const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  // Check session status on mount
  useEffect(() => {
    const validateSession = async () => {
      if (localStorage.getItem('sessionId')) {
        try {
          const isAuthenticated = await checkSession();
          if (!isAuthenticated) {
            // Clear stored data if session is invalid
            localStorage.removeItem('sessionId');
            setUser(null);
          } else {
            // Optionally fetch user data here
            // const userData = await fetchUserData();
            // setUser(userData);
          }
        } catch (err) {
          console.error('Session validation error:', err);
          localStorage.removeItem('sessionId');
          setUser(null);
        }
      }
      setLoading(false);
    };

    validateSession();
  }, []);

  // Login function
  const login = async (email, password) => {
    try {
      const userData = await apiLogin(email, password);
      setUser(userData.user);
      return userData;
    } catch (err) {
      console.error('Login error:', err);
      throw err;
    }
  };

  // Logout function
  const logout = async () => {
    try {
      await apiLogout();
    } catch (err) {
      console.error('Logout error:', err);
    } finally {
      localStorage.removeItem('sessionId');
      setUser(null);
      navigate('/login');
    }
  };

  // Session status helpers
  const isAuthenticated = !!localStorage.getItem('sessionId');

  // Exposed context value
  const value = {
    user,
    loading,
    login,
    logout,
    isAuthenticated
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// Custom hook to use the auth context
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
```

## Protected Route Component

Create a component to protect routes that require authentication:

```jsx
// src/components/ProtectedRoute.js
import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const ProtectedRoute = ({ children }) => {
  const { isAuthenticated, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return <div>Loading...</div>; // Or your loading component
  }

  if (!isAuthenticated) {
    // Redirect to login with return path
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return children;
};

export default ProtectedRoute;
```

## Using the Auth Context in App

Wrap your application with the AuthProvider:

```jsx
// src/App.js
import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';
import LoginPage from './pages/LoginPage';
import Dashboard from './pages/Dashboard';

function App() {
  return (
    <Router>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            }
          />
          {/* Other routes */}
        </Routes>
      </AuthProvider>
    </Router>
  );
}

export default App;
```

This approach provides a complete session management solution that:
1. Automatically refreshes expired sessions
2. Protects routes that require authentication
3. Redirects to login when session is invalid
4. Provides authentication state to all components 