from django.urls import path
from .views import (
    IndividualSignupView, VerifyIndividualOTPView, CompanySignupView, AddEmployeeView, SaveQueryView, LoginView,
    LogoutView, GetQueriesByUserView, GetQueryResponseByIdView, CheckSubscriptionView, CreateCheckoutSessionView
)

urlpatterns = [
    # Individual Users
    path("individual/signup/", IndividualSignupView.as_view(), name="individual_signup"),
    path("individual/verify-otp/", VerifyIndividualOTPView.as_view(), name="verify_individual_otp"),

    # Companies
    path("company/signup/", CompanySignupView.as_view(), name="company_signup"),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),

    # Employees
    path("company/add-employee/", AddEmployeeView.as_view(), name="add_employee"),
    path("save-query/", SaveQueryView.as_view(), name="save_query"),
    path('users/queries/', GetQueriesByUserView.as_view(), name="get_queries_by_user"),
    path('queries/<uuid:query_id>/response/', GetQueryResponseByIdView.as_view(), name="get_query_response_by_id"),
    path('check-subscription/', CheckSubscriptionView.as_view(), name="check_subscription"),
    path('create-checkout-session', CreateCheckoutSessionView.as_view(), name="create_checkout_session"),

]
