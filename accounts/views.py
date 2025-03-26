from django.contrib.auth import get_user_model, authenticate, login, logout
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.shortcuts import get_object_or_404
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import NotFound
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
import redis
import stripe
import os
from dotenv import load_dotenv
from django.contrib.auth import get_user_model

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .models import IndividualUser, Company, Employee, Query, CustomUser, SubscriptionPlan
from .serializers import (
    IndividualSignupSerializer,
    VerifyIndividualOTPSerializer,
    CompanySignupSerializer,
    AddEmployeeSerializer, LoginSerializer,
)

load_dotenv()
EMPLOYEE_LIMIT = int(os.getenv("EMPLOYEE_LIMIT", 10))
stripe.api_key = os.getenv("STRIPE_KEY")
redis_client = redis.StrictRedis(host="localhost", port=6379, db=0, decode_responses=True)
User = get_user_model()

CustomUser = get_user_model()

class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        request_body=LoginSerializer,
        responses={
            200: openapi.Response("Login successful"),
            400: "Invalid credentials"
        }
    )
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]

        user = authenticate(request, email=email, password=password)
        if user is not None:
            login(request, user)
            return Response({"message": "Login successful"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid email or password"}, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
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
class IndividualSignupView(APIView):
    """
    Individual user signup: Sends OTP to email.
    """
    permission_classes = [permissions.AllowAny]  # Allow anyone to call this endpoint


    @swagger_auto_schema(
        request_body=IndividualSignupSerializer,
        responses={
            200: openapi.Response("OTP sent to email"),
            400: "Email already exists or invalid input"
        }
    )
    def post(self, request):
        serializer = IndividualSignupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]

        # Check if an IndividualUser already exists for this email
        if IndividualUser.objects.filter(user__email=email).exists():
            return Response({"error": "Email already exists"}, status=status.HTTP_400_BAD_REQUEST)

        otp = get_random_string(length=6, allowed_chars="0123456789")
        redis_client.setex(email, 300, otp)  # OTP valid for 5 minutes

        send_mail(
            "Your OTP Code",
            f"Your OTP code is {otp}",
            "noreply@example.com",
            [email],
            fail_silently=False,
        )
        return Response({"message": "OTP sent to email"}, status=status.HTTP_200_OK)


# ---- Verify OTP and Create Individual User ----
class VerifyIndividualOTPView(APIView):
    """
    Verifies OTP and creates an individual user.
    """
    permission_classes = [permissions.AllowAny]  # Allow anyone to call this endpoint

    @swagger_auto_schema(
        request_body=VerifyIndividualOTPSerializer,
        responses={
            201: openapi.Response("Signup successful"),
            400: "Invalid OTP or invalid input"
        }
    )
    def post(self, request):
        serializer = VerifyIndividualOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        stored_otp = redis_client.get(data["email"])
        if not stored_otp or stored_otp != data["otp"]:
            return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)

        # Create CustomUser first
        custom_user = CustomUser.objects.create_user(
            email=data["email"],
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
        return Response({"message": "Signup successful"}, status=status.HTTP_201_CREATED)


# ---- Company Signup ----
class CompanySignupView(APIView):
    """
    Company signup without OTP verification.
    """
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        request_body=CompanySignupSerializer,
        responses={
            201: openapi.Response("Company registered successfully"),
            400: "Company email already exists or invalid input"
        }
    )
    def post(self, request):
        serializer = CompanySignupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        if Company.objects.filter(user__email=data["email"]).exists():
            return Response({"error": "Company email already exists"}, status=status.HTTP_400_BAD_REQUEST)

        # Create CustomUser with is_company=True using the provided password
        custom_user = CustomUser.objects.create_user(
            email=data["email"],
            password=data["password"],
            is_company=True,
        )
        company = Company.objects.create(
            user=custom_user,
            name=data["name"],
            website=data.get("website", ""),
            phone_number=data["phone_number"],
            terms_and_conditions=data["terms_and_conditions"],
        )
        return Response({"message": "Company registered successfully"}, status=status.HTTP_201_CREATED)


# ---- Add Employee (by Company) ----
class AddEmployeeView(APIView):
    """
    Companies can add employees under their account.
    """
    permission_classes = [permissions.AllowAny]  # Allow anyone to call this endpoint

    @swagger_auto_schema(
        request_body=AddEmployeeSerializer,
        responses={
            201: openapi.Response("Employee added successfully"),
            400: "Employee limit reached, email already exists, or invalid input"
        }
    )
    def post(self, request):
        serializer = AddEmployeeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        user = request.user

        company = get_object_or_404(Company, user__email=user)
        if company.employee_count() >= company.employee_limit:
            return Response({"error": f"Employee limit reached ({company.employee_limit})"},
                            status=status.HTTP_400_BAD_REQUEST)

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
            joining_date=data["joining_date"],
            end_of_contract_date=data.get("end_of_contract_date"),
        )

        # Send login credentials to the employee's email
        send_mail(
            "Your Employee Account Details",
            f"Hello {data['first_name']},\n\nYour account has been created.\nEmail: {data['email']}\nPassword: {random_password}\n\nPlease change your password after logging in.",
            "noreply@example.com",
            [data["email"]],
            fail_silently=False,
        )

        return Response({"message": "Employee added successfully"}, status=status.HTTP_201_CREATED)

class CsrfExemptSessionAuthentication(SessionAuthentication):
    def enforce_csrf(self, request):
        return
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
                        "summary": openapi.Schema(type=openapi.TYPE_STRING),
                        "main_sources": openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_OBJECT)),
                        "references": openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_OBJECT)),
                    },
                    required=["summary"]
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
        print(request.user)
        data = request.data
        query_text = data.get("query")
        result = data.get("result", {})
        response_text = result.get("summary", "")
        summary = result.get("summary", "")
        main_sources = result.get("main_sources", [])
        references = result.get("references", [])

        if not query_text or not response_text:
            return Response({"error": "Query and result summary are required."}, status=status.HTTP_400_BAD_REQUEST)

        user_instance = CustomUser.objects.get(pk=request.user.pk)
        query = Query.objects.create(
            user=user_instance,
            query=query_text,
            response_text=response_text,
            summary=summary,
            main_sources=main_sources,
            references=references
        )

        return Response(
            {"message": "Query saved", "query_id": query.query_id},
            status=status.HTTP_201_CREATED
        )

class GetQueriesByUserView(APIView):
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


class GetQueryResponseByIdView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request, query_id):
        try:
            query = Query.objects.get(query_id=query_id)
        except Query.DoesNotExist:
            raise NotFound(f"Query with id {query_id} not found.")
        query_response = {
            "query_id": query.query_id,

            "summary": query.summary,
            "main_sources": query.main_sources,
            "references": query.references
        }
        return Response(query_response, status=status.HTTP_200_OK)
class CreateCheckoutSessionView(APIView):
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


class CheckSubscriptionView(APIView):
    permission_classes = [permissions.AllowAny]
    def get(self, request):
        user = request.user
        try:
            user = CustomUser.objects.get(email=user)
        except CustomUser.DoesNotExist:
            raise NotFound(f"User {user} not found.")
        return Response({"active": user.is_active}, status=status.HTTP_200_OK)

