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

This approach sends the session ID in a custom header instead of relying on cookies, which should solve your authentication issues. 