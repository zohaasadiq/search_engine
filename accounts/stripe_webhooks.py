import stripe
import json
from django.conf import settings
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.utils import timezone
from datetime import datetime, timedelta
import os

from .models import CustomUser, Subscription, Transaction

stripe.api_key = settings.STRIPE_SECRET_KEY
TESTING_MODE = os.getenv('TESTING_MODE', 'false').lower() == 'true'

@csrf_exempt
@require_POST
def stripe_webhook(request):
    payload = request.body
    sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')
    
    print(f"Webhook received with signature: {sig_header}")
    print(f"Payload: {payload.decode('utf-8')[:200]}...")
    
    try:
        # In testing mode with no webhook secret, parse the payload directly
        if TESTING_MODE and not settings.STRIPE_WEBHOOK_SECRET:
            try:
                event = json.loads(request.body.decode('utf-8'))
                print("TESTING MODE: Webhook received without signature verification")
            except json.JSONDecodeError:
                print("Failed to parse JSON in testing mode")
                return HttpResponse(status=400)
        else:
            # Normal mode - verify the signature
            try:
                event = stripe.Webhook.construct_event(
                    payload, sig_header, settings.STRIPE_WEBHOOK_SECRET
                )
                print("Signature verification succeeded!")
            except Exception as e:
                print(f"Signature verification error details: {str(e)}")
                raise
    except ValueError as e:
        # Invalid payload
        print(f"Invalid webhook payload: {e}")
        return HttpResponse(status=400)
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        print(f"Invalid webhook signature: {e}")
        return HttpResponse(status=400)
    
    # Handle specific events
    try:
        event_type = event.get('type', '')
        print(f"Webhook received: {event_type}")
        print(f"Event data: {json.dumps(event.get('data', {}), indent=2)}")
        
        if event_type == 'checkout.session.completed':
            print("Processing checkout.session.completed event")
            handle_checkout_session_completed(event)
        elif event_type == 'invoice.payment_succeeded':
            print("Processing invoice.payment_succeeded event")
            handle_invoice_payment_succeeded(event)
        elif event_type == 'customer.subscription.deleted':
            print("Processing customer.subscription.deleted event")
            handle_subscription_deleted(event)
        elif event_type == 'customer.subscription.updated':
            print("Processing customer.subscription.updated event")
            handle_subscription_updated(event)
        else:
            print(f"Event type {event_type} not handled")
    except Exception as e:
        print(f"Error processing webhook: {e}")
        print(f"Error details: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()
    
    return HttpResponse(status=200)

def handle_checkout_session_completed(event):
    """
    Handle the checkout.session.completed event
    This is triggered when a customer completes the Stripe checkout process
    """
    session = event['data']['object']
    
    # Get user_id and plan_id from metadata
    metadata = session.get('metadata', {})
    user_id = metadata.get('user_id') or session.get('client_reference_id')
    plan_id = metadata.get('plan_id')
    
    if not user_id or not plan_id:
        # Missing required information
        return
    
    try:
        # Get user from the database
        user = CustomUser.objects.get(id=user_id)
        
        # Get or create a subscription record for this user
        subscription, created = Subscription.objects.get_or_create(
            user=user,
            defaults={
                'plan_id': plan_id,
                'status': 'inactive'  # Will be set to active when we get more info
            }
        )
        
        # Update the subscription with Stripe customer ID
        subscription.stripe_customer_id = session.get('customer')
        subscription.save()
        
        # If a subscription ID is available in the session, update it
        if 'subscription' in session:
            # Get subscription details from Stripe
            stripe_sub = stripe.Subscription.retrieve(session['subscription'])
            
            # Update our subscription record
            update_subscription_from_stripe(subscription, stripe_sub)
        
    except CustomUser.DoesNotExist:
        # User not found
        return
    except Exception as e:
        # Log the error
        print(f"Error handling checkout session completed: {e}")
        return

def handle_invoice_payment_succeeded(event):
    """
    Handle the invoice.payment_succeeded event
    This is triggered when a payment is successful
    """
    invoice = event['data']['object']
    
    # Get subscription ID from the invoice
    subscription_id = invoice.get('subscription')
    if not subscription_id:
        return
    
    try:
        # Get the customer ID and find our subscription
        customer_id = invoice.get('customer')
        subscription = Subscription.objects.get(stripe_customer_id=customer_id)
        
        # Get subscription details from Stripe
        stripe_sub = stripe.Subscription.retrieve(subscription_id)
        
        # Update our subscription record
        update_subscription_from_stripe(subscription, stripe_sub)
        
        # Record the transaction
        create_transaction_from_invoice(subscription.user, invoice)
        
    except Subscription.DoesNotExist:
        # Subscription not found in our database
        return
    except Exception as e:
        # Log the error
        print(f"Error handling invoice payment succeeded: {e}")
        return

def handle_subscription_deleted(event):
    """
    Handle the customer.subscription.deleted event
    This is triggered when a subscription is cancelled
    """
    stripe_sub = event['data']['object']
    
    try:
        # Find the subscription in our database
        subscription = Subscription.objects.get(stripe_subscription_id=stripe_sub['id'])
        
        # Update the subscription status
        subscription.status = 'canceled'
        subscription.save()
        
    except Subscription.DoesNotExist:
        # Subscription not found in our database
        return
    except Exception as e:
        # Log the error
        print(f"Error handling subscription deleted: {e}")
        return

def handle_subscription_updated(event):
    """
    Handle the customer.subscription.updated event
    This is triggered when a subscription is updated (e.g., plan change, renewal)
    """
    stripe_sub = event['data']['object']
    
    try:
        # Find the subscription in our database
        subscription = Subscription.objects.get(stripe_subscription_id=stripe_sub['id'])
        
        # Update our subscription record
        update_subscription_from_stripe(subscription, stripe_sub)
        
    except Subscription.DoesNotExist:
        # Subscription not found in our database
        return
    except Exception as e:
        # Log the error
        print(f"Error handling subscription updated: {e}")
        return

def update_subscription_from_stripe(subscription, stripe_sub):
    """
    Update our subscription model with data from the Stripe subscription
    """
    # Get the subscription period
    if 'current_period_start' in stripe_sub:
        subscription.current_period_start = datetime.fromtimestamp(stripe_sub['current_period_start'])
    
    if 'current_period_end' in stripe_sub:
        subscription.current_period_end = datetime.fromtimestamp(stripe_sub['current_period_end'])
    
    # Get plan information
    if 'plan' in stripe_sub and 'items' in stripe_sub and 'data' in stripe_sub['items']:
        # In case of Stripe price changes, might need to extract information from items
        if stripe_sub['items']['data']:
            plan = stripe_sub['items']['data'][0].get('plan', {})
            product_id = plan.get('product')
            
            if product_id:
                # Here you might want to map product IDs to your plan IDs
                # For simple implementation, just use product ID for now
                # In a real-world scenario, you'd have a mapping from Stripe Product ID to your plan IDs
                subscription.plan_id = product_id
    
    # Update subscription status
    subscription.status = stripe_sub['status']
    subscription.stripe_subscription_id = stripe_sub['id']
    
    # Save changes
    subscription.save()

def create_transaction_from_invoice(user, invoice):
    """
    Create a transaction record from an invoice
    """
    # Get the payment intent
    payment_intent_id = invoice.get('payment_intent')
    
    # Get the amount
    amount = invoice.get('amount_paid', 0) / 100.0  # Convert from cents to dollars
    
    # Get invoice URL or receipt URL if available
    receipt_url = None
    if payment_intent_id:
        try:
            payment_intent = stripe.PaymentIntent.retrieve(payment_intent_id)
            charges = payment_intent.get('charges', {}).get('data', [])
            if charges:
                receipt_url = charges[0].get('receipt_url')
        except Exception:
            pass
    
    # Create transaction record
    Transaction.objects.create(
        user=user,
        stripe_invoice_id=invoice['id'],
        stripe_payment_intent_id=payment_intent_id,
        amount=amount,
        status='succeeded',
        description=f"Payment for {invoice.get('description') or 'subscription'}",
        receipt_url=receipt_url,
        date=datetime.fromtimestamp(invoice['created'])
    )
