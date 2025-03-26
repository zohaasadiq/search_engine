from rest_framework import serializers
from .models import IndividualUser, Company, Employee, Query


class IndividualSignupSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    phone_number = serializers.CharField()
    date_of_birth = serializers.DateField()
    terms_and_conditions = serializers.BooleanField()

class VerifyIndividualOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    password = serializers.CharField(write_only=True)
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    phone_number = serializers.CharField()
    date_of_birth = serializers.DateField()
    terms_and_conditions = serializers.BooleanField()


class CompanySignupSerializer(serializers.Serializer):
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

from rest_framework import serializers

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
