from django.urls import path
from .views import (
    IndividualSignupView, VerifyIndividualOTPView, CompleteIndividualRegistrationView,
    CompanySignupView, VerifyCompanyOTPView, CompleteCompanyRegistrationView,
    InviteEmployeeView, CompleteEmployeeRegistrationView,
    CompanyEmployeesView, CompanyEmployeeDetailView,
    SaveQueryView, LoginView, LogoutView, GetQueriesByUserView, GetQueryResponseByIdView, 
    CheckSubscriptionView, CreateCheckoutSessionView,
    ForgotPasswordView, ResetPasswordView, ChangePasswordView,
    SubscriptionPlansView, BillingHistoryView, ActivateSubscriptionView,
    RefreshSessionView, SessionStatusView, CancelSubscriptionView
)
from .stripe_webhooks import stripe_webhook

urlpatterns = [
    # Individual Users
    path("individual/signup/", IndividualSignupView.as_view(), name="individual_signup"),
    path("individual/verify-otp/", VerifyIndividualOTPView.as_view(), name="verify_individual_otp"),
    path("individual/complete-registration/", CompleteIndividualRegistrationView.as_view(), name="complete_individual_registration"),

    # Companies
    path("company/signup/", CompanySignupView.as_view(), name="company_signup"),
    path("company/verify-otp/", VerifyCompanyOTPView.as_view(), name="verify_company_otp"),
    path("company/complete-registration/", CompleteCompanyRegistrationView.as_view(), name="complete_company_registration"),
    
    # Login/Logout
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),

    # Session Management
    path("refresh-session/", RefreshSessionView.as_view(), name="refresh_session"),
    path("session/status/", SessionStatusView.as_view(), name="session_status"),

    # Password Management
    path("password/forgot/", ForgotPasswordView.as_view(), name="forgot_password"),
    path("password/reset/", ResetPasswordView.as_view(), name="reset_password"),
    path("password/change/", ChangePasswordView.as_view(), name="change_password"),

    # Employee Management
    path("company/invite-employee/", InviteEmployeeView.as_view(), name="invite_employee"),
    path("employee/complete-registration/", CompleteEmployeeRegistrationView.as_view(), name="complete_employee_registration"),
    path("company/employees/", CompanyEmployeesView.as_view(), name="company_employees"),
    path("company/employees/<str:employee_id>/", CompanyEmployeeDetailView.as_view(), name="company_employee_detail"),

    # Query Management
    path("save-query/", SaveQueryView.as_view(), name="save_query"),
    path('users/queries/', GetQueriesByUserView.as_view(), name="get_queries_by_user"),
    path('queries/<uuid:query_id>/response/', GetQueryResponseByIdView.as_view(), name="get_query_response_by_id"),

    # Subscription Management
    path('subscription/plans/', SubscriptionPlansView.as_view(), name="subscription_plans"),
    path('subscription/status/', CheckSubscriptionView.as_view(), name="check_subscription"),
    path('subscription/billing-history/', BillingHistoryView.as_view(), name="billing_history"),
    path('subscription/create-checkout-session', CreateCheckoutSessionView.as_view(), name="create_checkout_session"),
    path('subscription/activate', ActivateSubscriptionView.as_view(), name="activate_subscription"),
    path('subscription/cancel', CancelSubscriptionView.as_view(), name="cancel_subscription"),
    
    # Stripe Webhook
    path('webhook/stripe/', stripe_webhook, name="stripe_webhook"),
]
