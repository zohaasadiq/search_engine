# API Documentation

## Authentication

### Login
**Endpoint:** `POST /api/accounts/login/`  
**Description:** Authenticates a user and returns user data with session ID  
**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```
**Status Codes:**
- `200 OK`: Login successful
- `400 BAD REQUEST`: Invalid input data
- `401 UNAUTHORIZED`: Invalid credentials

**Success Response:**
```json
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "is_company": true, // or false
    "is_active": true
  },
  "profile": {
    // Profile data varies by user type (company, individual, or employee)
    // For company:
    "name": "Company Name",
    "website": "https://example.com",
    "phone_number": "+1234567890",
    "employee_limit": 10
  },
  "session_id": "session_id_string" // New field for header-based auth
}
```

### Logout
**Endpoint:** `POST /api/accounts/logout/`  
**Description:** Logs out the current user  
**Authentication:** Required  
**Status Codes:**
- `200 OK`: Logout successful
- `401 UNAUTHORIZED`: Not authenticated

**Success Response:**
```json
{
  "message": "Logout successful"
}
```

## User Registration

### Individual Signup (Request OTP)
**Endpoint:** `POST /api/accounts/individual/signup/`  
**Description:** Sends OTP for individual registration  
**Request Body:**
```json
{
  "email": "user@example.com"
}
```
**Status Codes:**
- `200 OK`: OTP sent successfully
- `400 BAD REQUEST`: Email already exists or invalid input

### Verify Individual OTP
**Endpoint:** `POST /api/accounts/individual/verify-otp/`  
**Description:** Verifies OTP for individual registration  
**Request Body:**
```json
{
  "email": "user@example.com",
  "otp": "123456"
}
```
**Status Codes:**
- `200 OK`: OTP verified successfully
- `400 BAD REQUEST`: Invalid or expired OTP

### Complete Individual Registration
**Endpoint:** `POST /api/accounts/individual/complete-registration/`  
**Description:** Completes individual user registration  
**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "password123",
  "first_name": "John",
  "last_name": "Doe",
  "phone_number": "+1234567890",
  "date_of_birth": "1990-01-01"
}
```
**Status Codes:**
- `201 CREATED`: Registration successful
- `400 BAD REQUEST`: Email not verified or invalid input
- `500 INTERNAL SERVER ERROR`: Registration failed

### Company Signup (Request OTP)
**Endpoint:** `POST /api/accounts/company/signup/`  
**Description:** Sends OTP for company registration  
**Request Body:**
```json
{
  "email": "company@example.com"
}
```
**Status Codes:**
- `200 OK`: OTP sent successfully
- `400 BAD REQUEST`: Email already exists or invalid input

### Verify Company OTP
**Endpoint:** `POST /api/accounts/company/verify-otp/`  
**Description:** Verifies OTP for company registration  
**Request Body:**
```json
{
  "email": "company@example.com",
  "otp": "123456"
}
```
**Status Codes:**
- `200 OK`: OTP verified successfully
- `400 BAD REQUEST`: Invalid or expired OTP

### Complete Company Registration
**Endpoint:** `POST /api/accounts/company/complete-registration/`  
**Description:** Completes company registration  
**Request Body:**
```json
{
  "email": "company@example.com",
  "password": "password123",
  "name": "Company Name",
  "website": "https://example.com",
  "phone_number": "+1234567890",
  "terms_and_conditions": true
}
```
**Status Codes:**
- `201 CREATED`: Registration successful
- `400 BAD REQUEST`: Email not verified or invalid input
- `500 INTERNAL SERVER ERROR`: Registration failed

## Employee Management

### Invite Employee
**Endpoint:** `POST /api/accounts/company/invite-employee/`  
**Description:** Sends invitation to an employee  
**Authentication:** Required (Company account)  
**Request Body:**
```json
{
  "email": "employee@example.com",
  "first_name": "Jane",
  "last_name": "Smith"
}
```
**Status Codes:**
- `200 OK`: Invitation sent successfully
- `400 BAD REQUEST`: Invalid input
- `401 UNAUTHORIZED`: Authentication required
- `403 FORBIDDEN`: Not authorized (not a company account)
- `409 CONFLICT`: Email already registered

### Complete Employee Registration
**Endpoint:** `POST /api/accounts/employee/complete-registration/`  
**Description:** Completes employee registration after receiving invitation  
**Request Body:**
```json
{
  "invite_token": "token_from_email",
  "password": "password123",
  "first_name": "Jane",
  "last_name": "Smith",
  "phone_number": "+1234567890",
  "date_of_birth": "1990-01-01"
}
```
**Status Codes:**
- `201 CREATED`: Registration completed successfully
- `400 BAD REQUEST`: Invalid token or data
- `404 NOT FOUND`: Invitation not found or expired
- `409 CONFLICT`: Email already registered

### Add Employee Directly
**Endpoint:** `POST /api/accounts/company/employees/`  
**Description:** Directly adds an employee to company  
**Authentication:** Required (Company account)  
**Request Body:**
```json
{
  "email": "employee@example.com",
  "password": "password123",
  "first_name": "Jane",
  "last_name": "Smith",
  "phone_number": "+1234567890",
  "date_of_birth": "1990-01-01"
}
```
**Status Codes:**
- `201 CREATED`: Employee added successfully
- `400 BAD REQUEST`: Employee limit reached, email already exists, or invalid input
- `401 UNAUTHORIZED`: Authentication required
- `403 FORBIDDEN`: Not authorized (not a company account)

### List Employees
**Endpoint:** `GET /api/accounts/company/employees/`  
**Description:** Lists all employees for the company  
**Authentication:** Required (Company account)  
**Status Codes:**
- `200 OK`: Returns list of employees
- `401 UNAUTHORIZED`: Authentication required
- `403 FORBIDDEN`: Not authorized (not a company account)
- `404 NOT FOUND`: Company profile not found

**Success Response:**
```json
[
  {
    "user_id": "uuid",
    "email": "employee1@example.com",
    "first_name": "Jane",
    "last_name": "Smith",
    "phone_number": "+1234567890",
    "date_of_birth": "1990-01-01",
    "joining_date": "2023-01-01",
    "end_of_contract_date": null,
    "is_active": true
  },
  {
    "user_id": "uuid",
    "email": "employee2@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "phone_number": "+0987654321",
    "date_of_birth": "1992-05-15",
    "joining_date": "2023-02-01",
    "end_of_contract_date": null,
    "is_active": true
  }
]
```

### Delete Employee
**Endpoint:** `DELETE /api/accounts/company/employees/{employee_id}/`  
**Description:** Removes an employee from the company  
**Authentication:** Required (Company account)  
**Status Codes:**
- `204 NO CONTENT`: Employee deleted successfully
- `401 UNAUTHORIZED`: Authentication required
- `403 FORBIDDEN`: Not authorized (not a company account)
- `404 NOT FOUND`: Employee not found or company profile not found

## Password Management

### Forgot Password
**Endpoint:** `POST /api/accounts/password/forgot/`  
**Description:** Sends password reset OTP to user's email  
**Request Body:**
```json
{
  "email": "user@example.com"
}
```
**Status Codes:**
- `200 OK`: OTP sent successfully
- `404 NOT FOUND`: Email not registered

### Reset Password
**Endpoint:** `POST /api/accounts/password/reset/`  
**Description:** Resets password using OTP  
**Request Body:**
```json
{
  "email": "user@example.com",
  "otp": "123456",
  "new_password": "newpassword123"
}
```
**Status Codes:**
- `200 OK`: Password reset successful
- `400 BAD REQUEST`: Invalid or expired OTP
- `404 NOT FOUND`: Email not registered

### Change Password
**Endpoint:** `POST /api/accounts/password/change/`  
**Description:** Changes password for logged-in user  
**Authentication:** Required  
**Request Body:**
```json
{
  "old_password": "oldpassword123",
  "new_password": "newpassword123"
}
```
**Status Codes:**
- `200 OK`: Password changed successfully
- `400 BAD REQUEST`: Invalid old password or invalid input
- `401 UNAUTHORIZED`: Authentication required

## Query Management

### Save Query
**Endpoint:** `POST /api/accounts/save-query/`  
**Description:** Saves a user query  
**Authentication:** Required  
**Request Body:**
```json
{
  "query": "Query text",
  "summary": "Query summary",
  "main_sources": "Main sources",
  "references": "References"
}
```
**Status Codes:**
- `201 CREATED`: Query saved successfully
- `400 BAD REQUEST`: Invalid input
- `401 UNAUTHORIZED`: Authentication required

### Get User Queries
**Endpoint:** `GET /api/accounts/users/queries/`  
**Description:** Gets all queries for the current user  
**Authentication:** Required  
**Status Codes:**
- `200 OK`: Returns list of queries
- `401 UNAUTHORIZED`: Authentication required
- `404 NOT FOUND`: User not found

**Success Response:**
```json
{
  "queries": [
    {
      "query_id": "uuid",
      "query": "Query text"
    },
    {
      "query_id": "uuid",
      "query": "Another query text"
    }
  ]
}
```

### Get Query Response by ID
**Endpoint:** `GET /api/accounts/queries/{query_id}/response/`  
**Description:** Gets details of a specific query  
**Authentication:** Required  
**Status Codes:**
- `200 OK`: Returns query details
- `401 UNAUTHORIZED`: Authentication required
- `404 NOT FOUND`: Query not found

**Success Response:**
```json
{
  "query_id": "uuid",
  "summary": "Query summary",
  "main_sources": "Main sources",
  "references": "References"
}
```

## Subscription Management

### Check Subscription
**Endpoint:** `GET /api/accounts/check-subscription/`  
**Description:** Checks subscription status of current user  
**Authentication:** Required  
**Status Codes:**
- `200 OK`: Returns subscription status
- `401 UNAUTHORIZED`: Authentication required
- `404 NOT FOUND`: User not found

**Success Response:**
```json
{
  "active": true
}
```

### Create Checkout Session
**Endpoint:** `POST /api/accounts/create-checkout-session`  
**Description:** Creates a checkout session for subscription payment  
**Authentication:** Required  
**Request Body:**
```json
{
  "plan_id": "plan_id",
  "success_url": "https://example.com/success",
  "cancel_url": "https://example.com/cancel"
}
```
**Status Codes:**
- `200 OK`: Returns checkout session URL
- `400 BAD REQUEST`: Invalid input
- `401 UNAUTHORIZED`: Authentication required
- `404 NOT FOUND`: Plan not found

**Success Response:**
```json
{
  "checkout_url": "https://checkout.stripe.com/..."
}
``` 