from rest_framework import serializers
from .models import IndividualUser, Company, Employee, Query, CustomUser


class EmailOnlySerializer(serializers.Serializer):
    """Serializer for collecting just an email address"""
    email = serializers.EmailField()


class VerifyOTPSerializer(serializers.Serializer):
    """Serializer for OTP verification only"""
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)


class IndividualSignupDataSerializer(serializers.Serializer):
    """Serializer for individual user registration data"""
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    phone_number = serializers.CharField()
    date_of_birth = serializers.DateField()
    terms_and_conditions = serializers.BooleanField()


class CompanySignupDataSerializer(serializers.Serializer):
    """Serializer for company registration data"""
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    name = serializers.CharField()
    website = serializers.URLField(required=False, allow_blank=True, allow_null=True)
    phone_number = serializers.CharField()
    terms_and_conditions = serializers.BooleanField()


class AddEmployeeSerializer(serializers.Serializer):
    email = serializers.EmailField()
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    phone_number = serializers.CharField()
    date_of_birth = serializers.DateField()
    joining_date = serializers.DateField()
    end_of_contract_date = serializers.DateField(required=False, allow_null=True)


class QuerySerializer(serializers.ModelSerializer):
    # Expose fields with custom names for the API if needed.
    # Here we're mapping 'query' to the model's 'query_text' field,
    # and 'response' to 'response_text'.
    query = serializers.CharField(source="query_text")
    response = serializers.CharField(source="response_text")

    class Meta:
        model = Query
        fields = ("query", "response")


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

# Response serializers for returning user data
class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('email', 'is_company', 'is_active')

class IndividualUserSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer()
    
    class Meta:
        model = IndividualUser
        fields = ('user', 'first_name', 'last_name', 'phone_number', 'date_of_birth', 'date_joined')

class CompanySerializer(serializers.ModelSerializer):
    user = CustomUserSerializer()
    
    class Meta:
        model = Company
        fields = ('user', 'name', 'website', 'phone_number', 'employee_limit')

class EmployeeSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer()
    company_name = serializers.CharField(source='company.name')
    
    class Meta:
        model = Employee
        fields = ('user', 'company_name', 'first_name', 'last_name', 'phone_number', 'date_of_birth', 'joining_date', 'end_of_contract_date')

class ForgotPasswordSerializer(serializers.Serializer):
    """Serializer for forgot password - collecting email"""
    email = serializers.EmailField()


class ResetPasswordSerializer(serializers.Serializer):
    """Serializer for resetting password with OTP"""
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True)


class ChangePasswordSerializer(serializers.Serializer):
    """Serializer for changing password when logged in"""
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)


class EmployeeInviteSerializer(serializers.Serializer):
    """Serializer for inviting an employee"""
    email = serializers.EmailField()


class CompleteEmployeeRegistrationSerializer(serializers.Serializer):
    """Serializer for employee completing their registration"""
    invite_token = serializers.CharField()
    password = serializers.CharField(write_only=True)
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    phone_number = serializers.CharField()
    date_of_birth = serializers.DateField()
    terms_and_conditions = serializers.BooleanField()


class EmployeeListSerializer(serializers.ModelSerializer):
    """Serializer for listing company employees"""
    user_id = serializers.CharField(source='user.id')
    email = serializers.EmailField(source='user.email')
    is_active = serializers.BooleanField(source='user.is_active')
    
    class Meta:
        model = Employee
        fields = ('user_id', 'email', 'first_name', 'last_name', 'phone_number', 
                  'date_of_birth', 'joining_date', 'end_of_contract_date', 'is_active')
