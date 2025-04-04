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
from django.utils import timezone
from datetime import datetime, timedelta
from django.contrib.sessions.backends.db import SessionStore

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .models import IndividualUser, Company, Employee, Query, CustomUser, SubscriptionPlan, Subscription, Transaction
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
stripe.api_key = settings.STRIPE_SECRET_KEY
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
                "result": openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "corrected_query": openapi.Schema(type=openapi.TYPE_STRING),
                        "summary": openapi.Schema(type=openapi.TYPE_STRING),
                        "references": openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Schema(type=openapi.TYPE_OBJECT)
                        ),
                        "main_sources": openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Schema(type=openapi.TYPE_OBJECT)
                        ),
                    }
                )
            },
            required=["query", "result"]
        ),
        responses={
            201: openapi.Response("Query saved"),
            400: "Invalid input"
        }
    )
    def post(self, request):
        print(f"SaveQueryView received data: {request.data}")
        data = request.data

        query_text = data.get("query", "")
        
        # Extract data from the nested result object
        result = data.get("result", {})
        corrected_query = result.get("corrected_query", "")
        summary = result.get("summary", "")
        references = result.get("references", [])

        if not query_text:
            return Response({"error": "Query is required."}, status=status.HTTP_400_BAD_REQUEST)

        user_instance = CustomUser.objects.get(pk=request.user.pk)

        # Print debug information
        print(f"Saving query with summary: {summary[:100]}...")
        print(f"Saving query with references: {references}")

        query = Query.objects.create(
            user=user_instance,
            query=query_text,
            response_text=json.dumps(data),  # Store the entire data as JSON string
            summary=summary,
            corrected_query=corrected_query,
            references=references
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
            
            # Print debug information
            print(f"Retrieved query: {query.query_id}")
            print(f"Summary: {query.summary[:100] if query.summary else 'None'}")
            print(f"References: {query.references}")
            
            query_response = {
                "query_id": query.query_id,
                "query": query.query,
                "corrected_query": query.corrected_query or "",
                "summary": query.summary or "",
                "references": query.references or []
            }
            return Response(query_response, status=status.HTTP_200_OK)
        except Query.DoesNotExist:
            raise NotFound(f"Query with id {query_id} not found.")

@method_decorator(csrf_exempt, name='dispatch')
class CreateCheckoutSessionView(APIView):
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Creates a Stripe Checkout session for the given plan ID and returns the checkout URL.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["plan_id"],
            properties={
                "plan_id": openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="The plan ID to subscribe to"
                ),
                "success_url": openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="URL to redirect after successful payment"
                ),
                "cancel_url": openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="URL to redirect if payment is cancelled"
                )
            }
        ),
        responses={
            200: openapi.Response(
                description="Checkout session created successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "checkout_url": openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description="The URL to redirect the user to Stripe Checkout"
                        )
                    }
                )
            ),
            400: "Error creating checkout session"
        }
    )
    def post(self, request):
        try:
            user = request.user
            plan_id = request.data.get("plan_id")
            success_url = request.data.get("success_url", settings.FRONTEND_URL + "/payment-success")
            cancel_url = request.data.get("cancel_url", settings.FRONTEND_URL + "/plans")
            
            # Map plan IDs to Stripe Price IDs
            # In a production environment, you would store these mappings in your database
            price_mapping = {
                'free': None,  # Free plan doesn't need payment
                'basic': 'price_1R7m8NRrRHqE0EfDoscPZ9k1',  
                'pro': 'price_1R7m8URrRHqE0EfDBvLc8Xh8',
                'premium': 'price_1R7mAARrRHqE0EfDEOftS1dS'  
            }
            
            # Get the price ID for the selected plan
            # For this example, we'll use a direct mapping
            # In a real app, you'd likely fetch this from your database
            try:
                # Try to get from database first
                plan = SubscriptionPlan.objects.get(plan_id=plan_id)
                price_id = getattr(plan, 'stripe_price_id', None)
                
                # If not in database, try fallback mapping
                if not price_id:
                    price_id = price_mapping.get(plan_id)
                    
                if not price_id:
                    return Response({"error": f"No price ID found for plan {plan_id}"}, 
                                   status=status.HTTP_400_BAD_REQUEST)
                
                plan_name = plan.name
                
            except SubscriptionPlan.DoesNotExist:
                # Fallback to direct mapping if not in database
                price_id = price_mapping.get(plan_id)
                if not price_id:
                    return Response({"error": f"Plan {plan_id} not found"}, 
                                   status=status.HTTP_400_BAD_REQUEST)
                plan_name = plan_id.capitalize()
            
            # Create the checkout session
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=["card"],
                line_items=[{
                    'price': price_id,
                    'quantity': 1,
                }],
                mode='subscription',
                success_url=f"{success_url}?session_id={{CHECKOUT_SESSION_ID}}",
                cancel_url=cancel_url,
                customer_email=user.email,
                client_reference_id=str(user.id),
                metadata={
                    'user_id': str(user.id),
                    'plan_id': plan_id
                }
            )
            
            return Response({
                "checkout_url": checkout_session.url
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(csrf_exempt, name='dispatch')
class CheckSubscriptionView(APIView):
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Gets the current user's subscription status and details",
        responses={
            200: openapi.Response(
                description="Subscription details retrieved successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "subscription": openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                "is_active": openapi.Schema(type=openapi.TYPE_BOOLEAN),
                                "plan_id": openapi.Schema(type=openapi.TYPE_STRING),
                                "plan_name": openapi.Schema(type=openapi.TYPE_STRING),
                                "current_period_end": openapi.Schema(type=openapi.TYPE_STRING, format="date-time"),
                                "status": openapi.Schema(type=openapi.TYPE_STRING),
                                "customer_portal_url": openapi.Schema(type=openapi.TYPE_STRING, nullable=True)
                            }
                        )
                    }
                )
            ),
            404: "User not found"
        }
    )
    def get(self, request):
        try:
            user = request.user
            
            # Check if user has a subscription
            from .models import Subscription
            try:
                subscription = Subscription.objects.get(user=user)
                
                # Get subscription data
                subscription_data = {
                    "is_active": subscription.status == 'active',
                    "plan_id": subscription.plan_id,
                    "plan_name": self.get_plan_name(subscription.plan_id),
                    "status": subscription.status,
                    "current_period_end": subscription.current_period_end.isoformat() if subscription.current_period_end else None,
                    "customer_portal_url": self.get_customer_portal_url(subscription.stripe_customer_id) if subscription.stripe_customer_id else None
                }
            except Subscription.DoesNotExist:
                # No subscription found, return default data
                subscription_data = {
                    "is_active": False,
                    "plan_id": "free",
                    "plan_name": "Free Plan",
                    "status": "inactive",
                    "current_period_end": None,
                    "customer_portal_url": None
                }
            
            return Response({"subscription": subscription_data}, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def get_plan_name(self, plan_id):
        """Get a human-readable name for the plan"""
        # First try to get from database
        try:
            plan = SubscriptionPlan.objects.get(plan_id=plan_id)
            return plan.name
        except SubscriptionPlan.DoesNotExist:
            # For Stripe product IDs, try to fetch from Stripe
            if plan_id.startswith('prod_'):
                try:
                    # Fetch product details from Stripe
                    product = stripe.Product.retrieve(plan_id)
                    if product and 'name' in product:
                        return product.name
                except Exception as e:
                    print(f"Error fetching product from Stripe: {e}")
            
            # Map common plan IDs to readable names as fallback
            plan_name_map = {
                'free': 'Free Plan',
                'basic': 'Basic Plan',
                'pro': 'Professional Plan',
                'premium': 'Premium Plan',
                # Add other known plan mappings here
            }
            
            if plan_id.lower() in plan_name_map:
                return plan_name_map[plan_id.lower()]
                
            # Return a formatted version of the ID as last resort
            return plan_id.replace('_', ' ').title()
    
    def get_customer_portal_url(self, stripe_customer_id):
        """Create a customer portal session for managing subscription"""
        try:
            if not stripe_customer_id:
                return None
                
            # Create portal session
            session = stripe.billing_portal.Session.create(
                customer=stripe_customer_id,
                return_url=f"{settings.FRONTEND_URL}/dashboard",
            )
            return session.url
        except Exception as e:
            print(f"Error creating customer portal: {e}")
            return None

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
            # Disable SSL verification for this request
            import ssl
            original_context = ssl._create_default_https_context
            ssl._create_default_https_context = ssl._create_unverified_context
            
            print("SSL verification disabled for email sending")
            
            serializer = ForgotPasswordSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
                
            email = serializer.validated_data["email"]

            # Check if user exists
            try:
                user = CustomUser.objects.get(email=email)
            except CustomUser.DoesNotExist:
                # Restore SSL context before returning
                ssl._create_default_https_context = original_context
                return Response({"error": "Email not registered"}, status=status.HTTP_404_NOT_FOUND)

            # Generate and send OTP
            otp = get_random_string(length=6, allowed_chars="0123456789")
            redis_client.setex(f"reset_otp:{email}", 300, otp)

            try:
                print(f"Sending OTP email to {email}")
                send_mail(
                    subject="Password Reset OTP",
                    message=f"Your OTP code for password reset is {otp}",
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[email],
                    fail_silently=False,
                )
                print("Email sent successfully")
                
                # Restore SSL context
                ssl._create_default_https_context = original_context
                
                return Response({"message": "OTP sent to email"}, status=status.HTTP_200_OK)
            except Exception as e:
                print(f"Error sending email: {str(e)}")
                # Restore SSL context
                ssl._create_default_https_context = original_context
                raise
        except Exception as e:
            print(f"Exception in ForgotPasswordView: {str(e)}")
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

# ---- Subscription Plans ----
@method_decorator(csrf_exempt, name='dispatch')
class SubscriptionPlansView(APIView):
    """
    Get available subscription plans.
    """
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        operation_description="Gets a list of available subscription plans",
        responses={
            200: openapi.Response(
                description="List of plans retrieved successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "plans": openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Items(
                                type=openapi.TYPE_OBJECT,
                                properties={
                                    "id": openapi.Schema(type=openapi.TYPE_STRING),
                                    "name": openapi.Schema(type=openapi.TYPE_STRING),
                                    "price": openapi.Schema(type=openapi.TYPE_NUMBER),
                                    "features": openapi.Schema(
                                        type=openapi.TYPE_ARRAY,
                                        items=openapi.Items(type=openapi.TYPE_STRING)
                                    ),
                                    "validity": openapi.Schema(type=openapi.TYPE_INTEGER),
                                    "is_popular": openapi.Schema(type=openapi.TYPE_BOOLEAN),
                                    "stripe_price_id": openapi.Schema(type=openapi.TYPE_STRING, nullable=True)
                                }
                            )
                        )
                    }
                )
            )
        }
    )
    def get(self, request):
        try:
            # Get all plans from the database
            plans = SubscriptionPlan.objects.all()
            
            # Format plans for response
            formatted_plans = []
            for plan in plans:
                # Get features for the plan (this assumes you have features stored somewhere)
                features = self.get_plan_features(plan)
                
                formatted_plans.append({
                    "id": str(plan.plan_id),
                    "name": plan.name,
                    "price": plan.price / 100,  # Convert from cents to dollars
                    "features": features,
                    "validity": plan.validity,
                    "is_popular": getattr(plan, 'is_popular', False),
                    "stripe_price_id": getattr(plan, 'stripe_price_id', None)
                })
            
            # If no plans in database, return sample plans
            if not formatted_plans:
                formatted_plans = [
                    {
                        "id": "free",
                        "name": "Free",
                        "price": 0,
                        "features": ["Basic search functionality", "Limited to 5 queries per day", "No subscription required"],
                        "validity": 0,  # Unlimited
                        "is_popular": False,
                        "stripe_price_id": None
                    },
                    {
                        "id": "basic",
                        "name": "Basic",
                        "price": 9.99,
                        "features": ["Advanced search functionality", "Up to 50 queries per day", "Save search history", "Email support"],
                        "validity": 30,  # 30 days
                        "is_popular": False,
                        "stripe_price_id": "price_basic123"
                    },
                    {
                        "id": "pro",
                        "name": "Professional",
                        "price": 19.99,
                        "features": ["Premium search functionality", "Unlimited queries", "Detailed analysis", "Priority support", "Export capabilities"],
                        "validity": 30,  # 30 days
                        "is_popular": True,
                        "stripe_price_id": "price_pro123"
                    },
                    {
                        "id": "premium",
                        "name": "Premium",
                        "price": 49.99,
                        "features": ["Enterprise-grade search", "Unlimited queries", "Advanced analytics", "24/7 support", "Custom integrations"],
                        "validity": 30,  # 30 days
                        "is_popular": False,
                        "stripe_price_id": "price_premium123"
                    }
                ]
            
            return Response({"plans": formatted_plans}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def get_plan_features(self, plan):
        """Get features for a plan. This is a placeholder - implement based on your data model."""
        # This is a placeholder implementation. You should modify this
        # based on how you store features for your plans.
        features_map = {
            "free": ["Basic search functionality", "Limited to 5 queries per day", "No subscription required"],
            "basic": ["Advanced search functionality", "Up to 50 queries per day", "Save search history", "Email support"],
            "pro": ["Premium search functionality", "Unlimited queries", "Detailed analysis", "Priority support", "Export capabilities"],
            "premium": ["Enterprise-grade search", "Unlimited queries", "Advanced analytics", "24/7 support", "Custom integrations"]
        }
        
        # Try to get features by plan id or return empty list
        plan_id = str(plan.plan_id).lower()
        return features_map.get(plan_id, [])

# ---- Billing History ----
@method_decorator(csrf_exempt, name='dispatch')
class BillingHistoryView(APIView):
    """
    Get user's billing history.
    """
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Gets the current user's billing history",
        responses={
            200: openapi.Response(
                description="Billing history retrieved successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "transactions": openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Items(
                                type=openapi.TYPE_OBJECT,
                                properties={
                                    "id": openapi.Schema(type=openapi.TYPE_INTEGER),
                                    "amount": openapi.Schema(type=openapi.TYPE_NUMBER),
                                    "date": openapi.Schema(type=openapi.TYPE_STRING, format="date-time"),
                                    "description": openapi.Schema(type=openapi.TYPE_STRING),
                                    "status": openapi.Schema(type=openapi.TYPE_STRING),
                                    "receipt_url": openapi.Schema(type=openapi.TYPE_STRING, nullable=True)
                                }
                            )
                        )
                    }
                )
            )
        }
    )
    def get(self, request):
        try:
            user = request.user
            
            # Get transactions from the database
            from .models import Transaction
            transactions = Transaction.objects.filter(user=user).order_by('-date')
            
            # Format transactions for response
            formatted_transactions = []
            for transaction in transactions:
                formatted_transactions.append({
                    "id": transaction.id,
                    "amount": float(transaction.amount),
                    "date": transaction.date.isoformat(),
                    "description": transaction.description,
                    "status": transaction.status,
                    "receipt_url": transaction.receipt_url
                })
            
            return Response({"transactions": formatted_transactions}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# ---- Manual Subscription Activation (for testing) ----
@method_decorator(csrf_exempt, name='dispatch')
class ActivateSubscriptionView(APIView):
    """
    Manually activate a subscription after successful payment (for testing)
    """
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Manually activates a subscription after successful payment (for testing)",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["plan_id"],
            properties={
                "plan_id": openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="The plan ID to subscribe to"
                )
            }
        ),
        responses={
            200: "Subscription activated successfully",
            400: "Error activating subscription"
        }
    )
    def post(self, request):
        try:
            user = request.user
            plan_id = request.data.get("plan_id")
            
            if not plan_id:
                return Response({"error": "plan_id is required"}, 
                               status=status.HTTP_400_BAD_REQUEST)
            
            # Get plan details
            try:
                plan = SubscriptionPlan.objects.get(plan_id=plan_id)
            except SubscriptionPlan.DoesNotExist:
                return Response({"error": f"Plan {plan_id} not found"}, 
                               status=status.HTTP_400_BAD_REQUEST)
            
            # Create or update subscription
            subscription, created = Subscription.objects.get_or_create(
                user=user,
                defaults={
                    'plan_id': plan_id,
                    'status': 'active',
                    'current_period_start': timezone.now(),
                    'current_period_end': timezone.now() + timedelta(days=plan.validity)
                }
            )
            
            if not created:
                subscription.plan_id = plan_id
                subscription.status = 'active'
                subscription.current_period_start = timezone.now()
                subscription.current_period_end = timezone.now() + timedelta(days=plan.validity)
                subscription.save()
            
            # Create a test transaction record
            Transaction.objects.create(
                user=user,
                stripe_invoice_id=f"test_invoice_{timezone.now().timestamp()}",
                amount=plan.price / 100,  # Convert from cents to dollars
                status='succeeded',
                description=f"Test payment for {plan.name}",
                date=timezone.now()
            )
                
            return Response({
                "message": "Subscription activated successfully",
                "subscription": {
                    "plan_id": subscription.plan_id,
                    "status": subscription.status,
                    "current_period_end": subscription.current_period_end.isoformat() if subscription.current_period_end else None
                }
            }, status=status.HTTP_200_OK)
                
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

@method_decorator(csrf_exempt, name='dispatch')
class RefreshSessionView(APIView):
    """
    Refreshes an expired or about-to-expire session with a new session ID.
    """
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        responses={
            200: openapi.Response("New session ID"),
            401: "Invalid session",
            400: "No session ID provided"
        }
    )
    def post(self, request):
        try:
            # Get current session ID from header
            current_session_id = request.META.get('HTTP_X_SESSION_ID')
            if not current_session_id:
                return Response({"error": "No session ID provided"}, status=status.HTTP_400_BAD_REQUEST)
            
            # Load the session from the store
            session_store = SessionStore(current_session_id)
            
            # Check if session exists and retrieve user_id
            if not session_store.exists(current_session_id) or '_auth_user_id' not in session_store:
                return Response({"error": "Invalid session"}, status=status.HTTP_401_UNAUTHORIZED)
            
            user_id = session_store.get('_auth_user_id')
            
            # Check if user still exists and is active
            try:
                user = CustomUser.objects.get(pk=user_id)
                if not user.is_active:
                    return Response({"error": "User account is inactive"}, status=status.HTTP_401_UNAUTHORIZED)
            except CustomUser.DoesNotExist:
                return Response({"error": "User not found"}, status=status.HTTP_401_UNAUTHORIZED)
            
            # Create a new session for the user
            login(request, user)
            request.session.save()  # Ensure the session is saved
            
            # Return the new session ID
            return Response({"session_id": request.session.session_key}, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({"error": "Session refresh failed", "details": str(e)}, 
                           status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
class SessionStatusView(APIView):
    """
    Checks if the current session is valid and authenticated.
    """
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        responses={
            200: openapi.Response("Session status"),
        }
    )
    def get(self, request):
        try:
            # Get session ID from header
            session_id = request.META.get('HTTP_X_SESSION_ID')
            
            if not session_id:
                return Response({"is_authenticated": False}, status=status.HTTP_200_OK)
            
            # Load the session
            session_store = SessionStore(session_id)
            
            # Check if session exists and contains user ID
            if not session_store.exists(session_id) or '_auth_user_id' not in session_store:
                return Response({"is_authenticated": False}, status=status.HTTP_200_OK)
            
            # Check if user exists and is active
            try:
                user_id = session_store.get('_auth_user_id')
                user = CustomUser.objects.get(pk=user_id)
                is_authenticated = user.is_active
            except CustomUser.DoesNotExist:
                is_authenticated = False
            
            return Response({"is_authenticated": is_authenticated}, status=status.HTTP_200_OK)
            
        except Exception as e:
            # Even in case of errors, we don't consider the user authenticated
            return Response({"is_authenticated": False, "error": str(e)}, status=status.HTTP_200_OK)

@method_decorator(csrf_exempt, name='dispatch')
class CancelSubscriptionView(APIView):
    """
    Cancels the user's subscription (sets it to not renew at the period end).
    """
    authentication_classes = [CsrfExemptSessionAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Cancel the user's subscription, which will stop it from renewing at the end of the current period.",
        responses={
            200: openapi.Response(
                description="Subscription cancellation successful",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "success": openapi.Schema(type=openapi.TYPE_BOOLEAN),
                        "message": openapi.Schema(type=openapi.TYPE_STRING),
                        "current_period_end": openapi.Schema(
                            type=openapi.TYPE_STRING, 
                            format="date-time"
                        )
                    }
                )
            ),
            400: "Error cancelling subscription",
            404: "Subscription not found"
        }
    )
    def post(self, request):
        try:
            # Print debugging information
            print(f"CancelSubscriptionView: User ID = {request.user.id}, Email = {request.user.email}")
            
            # Get the user's active subscription
            try:
                subscription = Subscription.objects.get(user=request.user, status__in=['active', 'trialing'])
                print(f"Found subscription: ID={subscription.id}, Status={subscription.status}, Stripe ID={subscription.stripe_subscription_id}")
            except Subscription.DoesNotExist:
                print(f"No active subscription found for user {request.user.email}")
                return Response(
                    {"error": "No active subscription found for this user"}, 
                    status=status.HTTP_404_NOT_FOUND
                )
                
            if not subscription.stripe_subscription_id:
                print(f"Missing Stripe subscription ID for subscription {subscription.id}")
                return Response(
                    {"error": "Missing Stripe subscription ID"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            print(f"Attempting to cancel Stripe subscription: {subscription.stripe_subscription_id}")
            
            # Cancel in Stripe (set to not renew at period end)
            stripe_subscription = stripe.Subscription.modify(
                subscription.stripe_subscription_id,
                cancel_at_period_end=True
            )
            
            print(f"Stripe subscription modified successfully: {subscription.stripe_subscription_id}")
            
            # Update the local subscription record
            subscription.status = "active_until_period_end"
            subscription.save()
            
            # Get the end date of the current period
            timestamp = stripe_subscription.current_period_end
            current_period_end = timezone.datetime.fromtimestamp(timestamp)
            # Make the datetime timezone-aware
            current_period_end = timezone.make_aware(current_period_end)
            
            return Response({
                "success": True,
                "message": "Your subscription will not renew after the current period ends.",
                "current_period_end": current_period_end.isoformat()
            }, status=status.HTTP_200_OK)
            
        except stripe.error.StripeError as e:
            print(f"Stripe error when cancelling subscription: {str(e)}")
            return Response(
                {"error": f"Stripe error: {str(e)}"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            import traceback
            print(f"Unexpected error when cancelling subscription: {str(e)}")
            traceback.print_exc()
            return Response(
                {"error": f"An error occurred: {str(e)}"}, 
                status=status.HTTP_400_BAD_REQUEST
            )

