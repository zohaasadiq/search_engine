from django.contrib.admin.checks import refer_to_missing_field
from django.contrib.auth import get_user_model, authenticate, login, logout, update_session_auth_hash
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.shortcuts import get_object_or_404
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import NotFound, ValidationError, AuthenticationFailed
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
import redis
import stripe
import os
import json
from dotenv import load_dotenv
from django.contrib.auth import get_user_model
from uuid import uuid4
from django.urls import reverse
from django.db import transaction
from django.http import Http404
from django.template.loader import render_to_string
from django.conf import settings

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .models import IndividualUser, Company, Employee, Query, CustomUser, SubscriptionPlan
from .serializers import (
    EmailOnlySerializer, 
    VerifyOTPSerializer,
    IndividualSignupDataSerializer,
    CompanySignupDataSerializer,
    AddEmployeeSerializer, LoginSerializer,
    CustomUserSerializer, IndividualUserSerializer, CompanySerializer, EmployeeSerializer,
    ForgotPasswordSerializer, ResetPasswordSerializer, ChangePasswordSerializer,
    EmployeeInviteSerializer, CompleteEmployeeRegistrationSerializer, EmployeeListSerializer
)

load_dotenv()
EMPLOYEE_LIMIT = int(os.getenv("EMPLOYEE_LIMIT", 10))
stripe.api_key = os.getenv("STRIPE_KEY")
redis_client = redis.StrictRedis(host="localhost", port=6379, db=0, decode_responses=True)
User = get_user_model()

CustomUser = get_user_model()

class CsrfExemptSessionAuthentication(SessionAuthentication):
    def enforce_csrf(self, request):
        return

@method_decorator(csrf_exempt, name='dispatch')
class LoginView(APIView):
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        request_body=LoginSerializer,
        responses={
            200: openapi.Response("Login successful with user data"),
            400: "Invalid credentials",
            401: "Authentication failed"
        }
    )
    def post(self, request):
        try:
            serializer = LoginSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
                
            email = serializer.validated_data["email"]
            password = serializer.validated_data["password"]

            user = authenticate(request, email=email, password=password)
            if user is None:
                raise AuthenticationFailed("Invalid email or password")
                
            login(request, user)
            
            # Get user specific data based on user type
            user_data = {"user": CustomUserSerializer(user).data}
            
            if user.is_company:
                company = Company.objects.get(user=user)
                user_data["profile"] = CompanySerializer(company).data
            else:
                try:
                    individual = IndividualUser.objects.get(user=user)
                    user_data["profile"] = IndividualUserSerializer(individual).data
                except IndividualUser.DoesNotExist:
                    try:
                        employee = Employee.objects.get(user=user)
                        user_data["profile"] = EmployeeSerializer(employee).data
                    except Employee.DoesNotExist:
                        user_data["profile"] = None
            
            # Include session ID in response so frontend can store it
            user_data["session_id"] = request.session.session_key
            
            return Response(user_data, status=status.HTTP_200_OK)
        except AuthenticationFailed as e:
            return Response({"error": str(e)}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({"error": "Login failed", "details": str(e)}, status=status.HTTP_400_BAD_REQUEST)

@method_decorator(csrf_exempt, name='dispatch')
class LogoutView(APIView):
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        responses={
            200: openapi.Response("Logout successful"),
        }
    )
    def post(self, request):
        logout(request)
        return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)

# ---- Individual Signup (OTP Sending) ----
@method_decorator(csrf_exempt, name='dispatch')
class IndividualSignupView(APIView):
    """
    Individual user signup: Sends OTP to email.
    """
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.AllowAny]  # Allow anyone to call this endpoint


    @swagger_auto_schema(
        request_body=EmailOnlySerializer,
        responses={
            200: openapi.Response("OTP sent to email"),
            400: "Email already exists or invalid input"
        }
    )
    def post(self, request):
        try:
            serializer = EmailOnlySerializer(data=request.data)
            if not serializer.is_valid():
                return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
                
            email = serializer.validated_data["email"]

            # Check if an IndividualUser already exists for this email
            if CustomUser.objects.filter(email=email).exists():
                return Response({"error": "Email already exists"}, status=status.HTTP_400_BAD_REQUEST)

            otp = get_random_string(length=6, allowed_chars="0123456789")
            redis_client.setex(f"otp:{email}", 300, otp)  # OTP valid for 5 minutes

            send_mail(
                subject="Your OTP Code",
                message=f"Your OTP code is {otp}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False,
            )
            return Response({"message": "OTP sent to email"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": "Failed to send OTP", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ---- Verify OTP for Individual User ----
@method_decorator(csrf_exempt, name='dispatch')
class VerifyIndividualOTPView(APIView):
    """
    Verify OTP for individual user registration.
    """
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        request_body=VerifyOTPSerializer,
        responses={
            200: openapi.Response("OTP verified, proceed with registration"),
            400: "Invalid or expired OTP"
        }
    )
    def post(self, request):
        try:
            serializer = VerifyOTPSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
                
            data = serializer.validated_data
            email = data["email"]
            otp = data["otp"]

            stored_otp = redis_client.get(f"otp:{email}")
            if not stored_otp:
                return Response({"error": "OTP expired or not found"}, status=status.HTTP_400_BAD_REQUEST)
            
            if stored_otp != otp:
                return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)
            
            # Save verification status in Redis
            redis_client.setex(f"verified:{email}", 1800, "true")  # verification valid for 30 minutes
            
            return Response({"message": "OTP verified, proceed with registration"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": "OTP verification failed", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ---- Complete Registration for Individual User ----
@method_decorator(csrf_exempt, name='dispatch')
class CompleteIndividualRegistrationView(APIView):
    """
    Complete registration for individual users after OTP verification.
    """
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        request_body=IndividualSignupDataSerializer,
        responses={
            201: openapi.Response("Registration successful with user data"),
            400: "Email not verified or invalid input",
            500: "Internal server error"
        }
    )
    def post(self, request):
        try:
            serializer = IndividualSignupDataSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
            
            data = serializer.validated_data
            email = data["email"]
            
            # Check if email was verified
            verified = redis_client.get(f"verified:{email}")
            if not verified:
                return Response({"error": "Email not verified"}, status=status.HTTP_400_BAD_REQUEST)
            
            # Create CustomUser
            custom_user = CustomUser.objects.create_user(
                email=email,
                password=data["password"],
                is_company=False,
            )
            
            # Create IndividualUser record
            individual = IndividualUser.objects.create(
                user=custom_user,
                first_name=data["first_name"],
                last_name=data["last_name"],
                phone_number=data["phone_number"],
                date_of_birth=data["date_of_birth"],
                terms_and_conditions=data["terms_and_conditions"],
            )
            
            # Clean up Redis
            redis_client.delete(f"verified:{email}")
            
            # Automatically log the user in
            user = authenticate(request, email=email, password=data["password"])
            if user:
                login(request, user)
                # Ensure the session is saved before accessing the session key
                request.session.save()
            
            # Return user data
            user_data = {
                "user": CustomUserSerializer(custom_user).data,
                "profile": IndividualUserSerializer(individual).data
            }
            
            # Include session ID in response so frontend can store it
            user_data["session_id"] = request.session.session_key
            
            return Response(user_data, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"error": "Registration failed", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ---- Company Signup (OTP Sending) ----
@method_decorator(csrf_exempt, name='dispatch')
class CompanySignupView(APIView):
    """
    Company signup: Sends OTP to email.
    """
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        request_body=EmailOnlySerializer,
        responses={
            200: openapi.Response("OTP sent to email"),
            400: "Email already exists or invalid input"
        }
    )
    def post(self, request):
        try:
            serializer = EmailOnlySerializer(data=request.data)
            if not serializer.is_valid():
                return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
                
            email = serializer.validated_data["email"]

            # Check if a Company already exists for this email
            if CustomUser.objects.filter(email=email).exists():
                return Response({"error": "Email already exists"}, status=status.HTTP_400_BAD_REQUEST)

            otp = get_random_string(length=6, allowed_chars="0123456789")
            redis_client.setex(f"otp:{email}", 300, otp)  # OTP valid for 5 minutes

            send_mail(
                subject="Your Company Registration OTP",
                message=f"Your OTP code for company registration is {otp}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False,
            )
            return Response({"message": "OTP sent to email"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": "Failed to send OTP", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ---- Verify OTP for Company ----
@method_decorator(csrf_exempt, name='dispatch')
class VerifyCompanyOTPView(APIView):
    """
    Verify OTP for company registration.
    """
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        request_body=VerifyOTPSerializer,
        responses={
            200: openapi.Response("OTP verified, proceed with registration"),
            400: "Invalid or expired OTP"
        }
    )
    def post(self, request):
        try:
            serializer = VerifyOTPSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
                
            data = serializer.validated_data
            email = data["email"]
            otp = data["otp"]

            stored_otp = redis_client.get(f"otp:{email}")
            if not stored_otp:
                return Response({"error": "OTP expired or not found"}, status=status.HTTP_400_BAD_REQUEST)
            
            if stored_otp != otp:
                return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)
            
            # Save verification status in Redis
            redis_client.setex(f"verified:{email}", 1800, "true")  # verification valid for 30 minutes
            
            return Response({"message": "OTP verified, proceed with registration"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": "OTP verification failed", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ---- Complete Registration for Company ----
@method_decorator(csrf_exempt, name='dispatch')
class CompleteCompanyRegistrationView(APIView):
    """
    Complete registration for companies after OTP verification.
    """
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        request_body=CompanySignupDataSerializer,
        responses={
            201: openapi.Response("Company registration successful with user data"),
            400: "Email not verified or invalid input",
            500: "Internal server error"
        }
    )
    def post(self, request):
        try:
            serializer = CompanySignupDataSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
            
            data = serializer.validated_data
            email = data["email"]
            
            # Check if email was verified
            verified = redis_client.get(f"verified:{email}")
            if not verified:
                return Response({"error": "Email not verified"}, status=status.HTTP_400_BAD_REQUEST)
            
            # Create CustomUser with is_company=True
            custom_user = CustomUser.objects.create_user(
                email=email,
                password=data["password"],
                is_company=True,
            )
            
            # Create Company record
            company = Company.objects.create(
                user=custom_user,
                name=data["name"],
                website=data.get("website", ""),
                phone_number=data["phone_number"],
                terms_and_conditions=data["terms_and_conditions"],
            )
            
            # Clean up Redis
            redis_client.delete(f"verified:{email}")
            
            # Automatically log the user in
            user = authenticate(request, email=email, password=data["password"])
            if user:
                login(request, user)
                # Ensure the session is saved before accessing the session key
                request.session.save()
            
            # Return company data
            company_data = {
                "user": CustomUserSerializer(custom_user).data,
                "profile": CompanySerializer(company).data
            }
            
            # Include session ID in response so frontend can store it
            company_data["session_id"] = request.session.session_key
            
            return Response(company_data, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"error": "Company registration failed", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ---- Add Employee (by Company) ----
@method_decorator(csrf_exempt, name='dispatch')
class AddEmployeeView(APIView):
    """
    Companies can add employees under their account.
    """
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.IsAuthenticated]  # User must be authenticated

    @swagger_auto_schema(
        request_body=AddEmployeeSerializer,
        responses={
            201: openapi.Response("Employee added successfully with employee data"),
            400: "Employee limit reached, email already exists, or invalid input",
            401: "Authentication required",
            403: "Not authorized (not a company account)",
            500: "Internal server error"
        }
    )
    def post(self, request):
        try:
            serializer = AddEmployeeSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
                
            data = serializer.validated_data
            user = request.user
            
            if not user.is_company:
                return Response({"error": "Only company accounts can add employees"}, status=status.HTTP_403_FORBIDDEN)

            try:
                company = Company.objects.get(user=user)
            except Company.DoesNotExist:
                return Response({"error": "Company profile not found"}, status=status.HTTP_404_NOT_FOUND)
                
            if company.employee_count() >= company.employee_limit:
                return Response({"error": f"Employee limit reached ({company.employee_limit})"}, 
                                status=status.HTTP_400_BAD_REQUEST)

            # Check if email already exists
            if CustomUser.objects.filter(email=data["email"]).exists():
                return Response({"error": "Email already exists"}, status=status.HTTP_400_BAD_REQUEST)
                                
            # Generate a random password for the employee
            random_password = get_random_string(
                length=10,
                allowed_chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            )

            # Create CustomUser for the employee
            custom_user = CustomUser.objects.create_user(
                email=data["email"],
                password=random_password,
                is_company=False,
            )

            # Create Employee record with additional fields
            employee = Employee.objects.create(
                user=custom_user,
                company=company,
                first_name=data["first_name"],
                last_name=data["last_name"],
                phone_number=data["phone_number"],
                date_of_birth=data["date_of_birth"],
            )

            # Send login credentials to the employee's email
            send_mail(
                subject="Your Employee Account Details",
                message=f"Hello {data['first_name']},\n\nYour account has been created.\nEmail: {data['email']}\nPassword: {random_password}\n\nPlease change your password after logging in.",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[data["email"]],
                fail_silently=False,
            )

            # Return employee data
            employee_data = {
                "message": "Employee added successfully",
                "employee": EmployeeSerializer(employee).data,
                "password_sent": True
            }

            return Response(employee_data, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"error": "Failed to add employee", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@method_decorator(csrf_exempt, name='dispatch')
class SaveQueryView(APIView):
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "query": openapi.Schema(type=openapi.TYPE_STRING),
                "corrected_query": openapi.Schema(type=openapi.TYPE_STRING),
                "summary": openapi.Schema(type=openapi.TYPE_STRING),
                "references": openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(type=openapi.TYPE_OBJECT)
                ),
            },
            required=["query", "summary"]
        ),
        responses={
            201: openapi.Response("Query saved"),
            400: "Invalid input"
        }
    )
    def post(self, request):

        print(request.user)
        data = request.data

        query_text = data.get("query")

        corrected_query = data.get("corrected_query", "")

        summary = data.get("summary", "")

        references = data.get("references", [])


        if not query_text or not data:
            return Response({"error": "Query and results are required."}, status=status.HTTP_400_BAD_REQUEST)

        user_instance = CustomUser.objects.get(pk=request.user.pk)


        query = Query.objects.create(
            user=user_instance,
            query= query_text,
            response_text= data,
            summary= summary,
            corrected_query= corrected_query,
            references= references
        )

        return Response(
            {"message": "Query saved", "query_id": query.query_id},
            status=status.HTTP_201_CREATED
        )

@method_decorator(csrf_exempt, name='dispatch')
class GetQueriesByUserView(APIView):
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        try:
            user = CustomUser.objects.get(email=user)
        except CustomUser.DoesNotExist:
            raise NotFound(f"User {user} not found.")

        queries = Query.objects.filter(user=user)
        query_list = [
            {
                "query_id": query.query_id,
                "query": query.query,
            }
            for query in queries
        ]
        return Response({"queries": query_list}, status=status.HTTP_200_OK)


@method_decorator(csrf_exempt, name='dispatch')
class GetQueryResponseByIdView(APIView):
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request, query_id):
        try:
            query = Query.objects.get(query_id=query_id)
        except Query.DoesNotExist:
            raise NotFound(f"Query with id {query_id} not found.")
        query_response = {
            "query_id": query.query_id,
            "corrected_query" : query.corrected_query,
            "summary": query.summary,
            "references": query.references
        }
        return Response(query_response, status=status.HTTP_200_OK)

@method_decorator(csrf_exempt, name='dispatch')
class CreateCheckoutSessionView(APIView):
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        operation_description="Creates a Stripe Checkout session for the given plan ID and returns the session ID.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["plan_id"],
            properties={
                "plan_id": openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="The Stripe Price ID for the subscription or one-time payment."
                )
            }
        ),
        responses={
            200: openapi.Response(
                description="Checkout session created successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "id": openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description="The Stripe Checkout Session ID"
                        )
                    }
                )
            ),
            400: "Error creating checkout session"
        }
    )
    def post(self, request):
        # Replace with your actual domain
        plan_id = request.data.get("plan_id")
        try:
            plan = SubscriptionPlan.objects.get(plan_id=plan_id)
        except SubscriptionPlan.DoesNotExist:
            return Response({"error": "Subscription plan not found"}, status=status.HTTP_400_BAD_REQUEST)
        plan_price = plan.price
        plan_name = plan.name
        domain_url = os.getenv("DOMAIN_URL")
        try:
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=["card"],
                line_items=[
                    {
                        "price_data": {
                            "currency": "usd",
                            "unit_amount": int(plan_price),
                            "product_data": {
                                "name": f"{plan_name}",
                            },
                        },
                        "quantity": 1,
                    }
                ],
                mode="payment",
                success_url=domain_url + "/success?session_id={CHECKOUT_SESSION_ID}",
                cancel_url=domain_url + "/cancel",
            )
            return Response({"id": checkout_session.id}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(csrf_exempt, name='dispatch')
class CheckSubscriptionView(APIView):
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.AllowAny]
    def get(self, request):
        user = request.user
        try:
            user = CustomUser.objects.get(email=user)
        except CustomUser.DoesNotExist:
            raise NotFound(f"User {user} not found.")
        return Response({"active": user.is_active}, status=status.HTTP_200_OK)

# ---- Forgot Password (Send OTP) ----
@method_decorator(csrf_exempt, name='dispatch')
class ForgotPasswordView(APIView):
    """
    Send OTP for password reset if email exists.
    """
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        request_body=ForgotPasswordSerializer,
        responses={
            200: openapi.Response("OTP sent to email"),
            404: "Email not registered"
        }
    )
    def post(self, request):
        try:
            serializer = ForgotPasswordSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
                
            email = serializer.validated_data["email"]

            # Check if user exists
            try:
                user = CustomUser.objects.get(email=email)
            except CustomUser.DoesNotExist:
                return Response({"error": "Email not registered"}, status=status.HTTP_404_NOT_FOUND)

            # Generate and send OTP
            otp = get_random_string(length=6, allowed_chars="0123456789")
            redis_client.setex(f"reset_otp:{email}", 300, otp)

            send_mail(
                subject="Password Reset OTP",
                message=f"Your OTP code for password reset is {otp}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False,
            )
            return Response({"message": "OTP sent to email"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": "Failed to send OTP", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ---- Reset Password (Verify OTP and Set New Password) ----
@method_decorator(csrf_exempt, name='dispatch')
class ResetPasswordView(APIView):
    """
    Verify OTP and set new password.
    """
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        request_body=ResetPasswordSerializer,
        responses={
            200: openapi.Response("Password reset successful"),
            400: "Invalid or expired OTP or invalid input",
            404: "Email not registered"
        }
    )
    def post(self, request):
        try:
            serializer = ResetPasswordSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
                
            data = serializer.validated_data
            email = data["email"]
            otp = data["otp"]
            new_password = data["new_password"]

            # Check if user exists
            try:
                user = CustomUser.objects.get(email=email)
            except CustomUser.DoesNotExist:
                return Response({"error": "Email not registered"}, status=status.HTTP_404_NOT_FOUND)

            # Verify OTP
            stored_otp = redis_client.get(f"reset_otp:{email}")
            if not stored_otp:
                return Response({"error": "OTP expired or not found"}, status=status.HTTP_400_BAD_REQUEST)
            
            if stored_otp != otp:
                return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)
            
            # Set new password
            user.set_password(new_password)
            user.save()
            
            # Clean up Redis
            redis_client.delete(f"reset_otp:{email}")
            
            return Response({"message": "Password reset successful"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": "Password reset failed", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ---- Change Password (Logged In User) ----
@method_decorator(csrf_exempt, name='dispatch')
class ChangePasswordView(APIView):
    """
    Change password for authenticated user.
    """
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        request_body=ChangePasswordSerializer,
        responses={
            200: openapi.Response("Password changed successfully"),
            400: "Invalid old password or invalid input"
        }
    )
    def post(self, request):
        try:
            serializer = ChangePasswordSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
                
            data = serializer.validated_data
            old_password = data["old_password"]
            new_password = data["new_password"]

            # Check if old password is correct
            user = request.user
            if not user.check_password(old_password):
                return Response({"error": "Current password is incorrect"}, status=status.HTTP_400_BAD_REQUEST)
            
            # Set new password
            user.set_password(new_password)
            user.save()
            
            # Update session auth hash to prevent logout
            update_session_auth_hash(request, user)
            
            return Response({"message": "Password changed successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": "Password change failed", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# ---- Invite Employee (by Company) ----
@method_decorator(csrf_exempt, name='dispatch')
class InviteEmployeeView(APIView):
    """
    Companies can invite employees who will complete their own registration.
    """
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.IsAuthenticated]  # User must be authenticated

    @swagger_auto_schema(
        request_body=EmployeeInviteSerializer,
        responses={
            200: openapi.Response("Invitation sent to employee"),
            400: "Invalid input",
            401: "Authentication required",
            403: "Not authorized (not a company account)",
            409: "Email already registered",
            500: "Internal server error"
        }
    )
    def post(self, request):
        try:
            serializer = EmployeeInviteSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
                
            email = serializer.validated_data["email"]
            user = request.user
            
            if not user.is_company:
                return Response({"error": "Only company accounts can invite employees"}, status=status.HTTP_403_FORBIDDEN)

            try:
                company = Company.objects.get(user=user)
            except Company.DoesNotExist:
                return Response({"error": "Company profile not found"}, status=status.HTTP_404_NOT_FOUND)
                
            if company.employee_count() >= company.employee_limit:
                return Response({"error": f"Employee limit reached ({company.employee_limit})"}, 
                                status=status.HTTP_400_BAD_REQUEST)

            # Check if email already exists
            if CustomUser.objects.filter(email=email).exists():
                return Response(
                    {"error": "A user with this email already exists in the system. They cannot be invited as an employee."}, 
                    status=status.HTTP_409_CONFLICT
                )
                                
            # Generate a unique token for this invitation
            invite_token = str(uuid4())
            
            # Store invitation in Redis with 7-day expiry
            invitation_data = {
                "company_id": str(company.user_id),
                "company_name": company.name,
                "email": email
            }
            redis_client.setex(f"invite:{invite_token}", 604800, json.dumps(invitation_data))  # 7 days
            
            # Generate invitation URL
            # In a real-world scenario, this would be a frontend URL
            # But for this example, we'll just include the token
            invite_url = f"/complete-employee-registration?token={invite_token}"
            
            # Send invitation email
            send_mail(
                subject=f"Invitation to join {company.name}",
                message=f"Hello,\n\nYou have been invited to join {company.name} as an employee. "
                f"Please click the following link to complete your registration:\n\n"
                f"{invite_url}\n\n"
                f"This invitation will expire in 7 days.",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False,
            )

            return Response({
                "message": "Invitation sent to employee",
                "invite_token": invite_token
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": "Failed to invite employee", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# ---- Complete Employee Registration ----
@method_decorator(csrf_exempt, name='dispatch')
class CompleteEmployeeRegistrationView(APIView):
    """
    Complete employee registration after receiving invitation.
    """
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.AllowAny]  # Allow anyone with an invitation token

    @swagger_auto_schema(
        request_body=CompleteEmployeeRegistrationSerializer,
        responses={
            201: openapi.Response("Registration completed successfully"),
            400: "Invalid token or data",
            404: "Invitation not found or expired",
            409: "Email already registered",
            500: "Internal server error"
        }
    )
    def post(self, request):
        try:
            serializer = CompleteEmployeeRegistrationSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
                
            data = serializer.validated_data
            invite_token = data["invite_token"]
            
            # Retrieve invitation data
            invitation_json = redis_client.get(f"invite:{invite_token}")
            if not invitation_json:
                return Response({"error": "Invitation not found or expired"}, status=status.HTTP_404_NOT_FOUND)
            
            invitation = json.loads(invitation_json)
            email = invitation["email"]
            company_id = invitation["company_id"]
            
            # Check if user with this email already exists
            if CustomUser.objects.filter(email=email).exists():
                return Response(
                    {"error": "This email is already registered. Please contact your company administrator."}, 
                    status=status.HTTP_409_CONFLICT
                )
            
            # Get company
            try:
                company = Company.objects.get(user_id=company_id)
            except Company.DoesNotExist:
                return Response({"error": "Company not found"}, status=status.HTTP_404_NOT_FOUND)
            
            # Use transaction to ensure all database operations succeed or fail together
            with transaction.atomic():
                # Create user account
                custom_user = CustomUser.objects.create_user(
                    email=email,
                    password=data["password"],
                    is_company=False,
                )
                
                # Create employee record with today's date as joining_date
                from django.utils import timezone
                current_date = timezone.now().date()
                
                employee = Employee.objects.create(
                    user=custom_user,
                    company=company,
                    first_name=data["first_name"],
                    last_name=data["last_name"],
                    phone_number=data["phone_number"],
                    date_of_birth=data["date_of_birth"],
                )
            
            # Clean up Redis
            redis_client.delete(f"invite:{invite_token}")
            
            # Automatically log the user in
            user = authenticate(request, email=email, password=data["password"])
            if user:
                login(request, user)
                # Ensure the session is saved before accessing the session key
                request.session.save()
            
            # Return employee data
            employee_data = {
                "message": "Registration completed successfully",
                "employee": EmployeeSerializer(employee).data
            }
            
            # Include session ID in response so frontend can store it
            employee_data["session_id"] = request.session.session_key
            
            return Response(employee_data, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"error": "Registration failed", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# ---- Company Employees Management (List and Delete) ----
@method_decorator(csrf_exempt, name='dispatch')
class CompanyEmployeesView(APIView):
    """
    List and manage company employees.
    GET: List all employees
    """
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        responses={
            200: openapi.Response("List of company employees", EmployeeListSerializer(many=True)),
            403: "Not authorized (not a company account)",
            404: "Company profile not found",
            500: "Internal server error"
        }
    )
    def get(self, request):
        """List all employees for the company"""
        try:
            user = request.user
            
            if not user.is_company:
                return Response(
                    {"error": "Only company accounts can access employee lists"}, 
                    status=status.HTTP_403_FORBIDDEN
                )

            try:
                company = Company.objects.get(user=user)
            except Company.DoesNotExist:
                return Response(
                    {"error": "Company profile not found"}, 
                    status=status.HTTP_404_NOT_FOUND
                )
                
            employees = Employee.objects.filter(company=company)
            serializer = EmployeeListSerializer(employees, many=True)
            
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {"error": "Failed to retrieve employees", "details": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@method_decorator(csrf_exempt, name='dispatch')
class CompanyEmployeeDetailView(APIView):
    """
    Manage individual employee.
    DELETE: Remove an employee
    """
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get_employee(self, employee_id, company):
        """Helper to get employee and verify ownership"""
        try:
            return Employee.objects.get(user_id=employee_id, company=company)
        except Employee.DoesNotExist:
            raise Http404("Employee not found or does not belong to your company")

    @swagger_auto_schema(
        responses={
            204: "Employee deleted successfully",
            403: "Not authorized (not a company account)",
            404: "Employee not found or company profile not found",
            500: "Internal server error"
        }
    )
    def delete(self, request, employee_id):
        """Delete an employee from the company"""
        try:
            user = request.user
            
            if not user.is_company:
                return Response(
                    {"error": "Only company accounts can delete employees"}, 
                    status=status.HTTP_403_FORBIDDEN
                )

            try:
                company = Company.objects.get(user=user)
            except Company.DoesNotExist:
                return Response(
                    {"error": "Company profile not found"}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Get employee and verify ownership
            try:
                employee = self.get_employee(employee_id, company)
            except Http404 as e:
                return Response({"error": str(e)}, status=status.HTTP_404_NOT_FOUND)
            
            # Delete employee and associated user account
            with transaction.atomic():
                # Get the user account
                user_account = employee.user
                # Delete the employee record
                employee.delete()
                # Delete the user account
                user_account.delete()
            
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            return Response(
                {"error": "Failed to delete employee", "details": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

