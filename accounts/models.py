import os
import uuid

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from dotenv import load_dotenv

load_dotenv()

employee_limit = os.getenv('EMPLOYEE_LIMIT', 10)


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Email is required")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(email, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_company = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email


class IndividualUser(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, primary_key=True)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    phone_number = models.CharField(max_length=15)
    date_of_birth = models.DateField()
    terms_and_conditions = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.email


class Company(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, primary_key=True)
    name = models.CharField(max_length=255)
    website = models.URLField(blank=True, null=True)
    phone_number = models.CharField(max_length=15)
    terms_and_conditions = models.BooleanField(default=False)
    employee_limit = models.PositiveIntegerField(default=employee_limit)

    def employee_count(self):
        return self.employees.count()

    def __str__(self):
        return self.name


class Employee(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, primary_key=True)
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name="employees")
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    phone_number = models.CharField(max_length=15)
    date_of_birth = models.DateField()

    def __str__(self):
        return f"{self.first_name} {self.last_name} - {self.company.name}"


class Query(models.Model):
    query_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    query = models.TextField()
    response_text = models.TextField()
    summary = models.TextField(null=True, blank=True)
    corrected_query = models.TextField(null=True, blank=True)
    references = models.JSONField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return self.query

class SubscriptionPlan(models.Model):
    plan_id = models.CharField(max_length=50, primary_key=True)
    name = models.CharField(max_length=255)
    price = models.PositiveIntegerField()
    validity = models.PositiveIntegerField()
    stripe_price_id = models.CharField(max_length=100, blank=True, null=True)
    is_popular = models.BooleanField(default=False)

    def __str__(self):
        return self.name

class UserSubscriptionManagement(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    subscription_plan = models.ForeignKey(SubscriptionPlan, on_delete=models.CASCADE)
    expires_at = models.DateTimeField()
    subscribed_at = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return self.user.is_active


# Stripe Subscription Models
class Subscription(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='stripe_subscription')
    stripe_customer_id = models.CharField(max_length=100, blank=True, null=True)
    stripe_subscription_id = models.CharField(max_length=100, blank=True, null=True)
    plan_id = models.CharField(max_length=50)  # 'free', 'pro', 'premium' or the actual plan ID
    status = models.CharField(max_length=50, default='inactive')  # 'active', 'canceled', 'past_due'
    current_period_start = models.DateTimeField(null=True, blank=True)
    current_period_end = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.email} - {self.plan_id} - {self.status}"
    
    @property
    def is_active(self):
        return self.status == 'active'


class Transaction(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='transactions')
    stripe_invoice_id = models.CharField(max_length=100)
    stripe_payment_intent_id = models.CharField(max_length=100, blank=True, null=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=50)  # 'succeeded', 'pending', 'failed'
    description = models.CharField(max_length=255)
    receipt_url = models.URLField(blank=True, null=True)
    date = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.email} - ${self.amount} - {self.status}"

