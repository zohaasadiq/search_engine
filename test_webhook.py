import json
import hmac
import hashlib
import time
import requests
import sys

def generate_stripe_signature(payload, secret, timestamp=None):
    """Generate a Stripe webhook signature."""
    if timestamp is None:
        timestamp = int(time.time())
    
    # Convert payload to string if it's a dictionary
    if isinstance(payload, dict):
        payload = json.dumps(payload)
    
    # Create signed payload string
    signed_payload = f"{timestamp}.{payload}"
    
    # Generate HMAC signature
    signature = hmac.new(
        secret.encode('utf-8'),
        signed_payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    # Format as Stripe expects
    return f"t={timestamp},v1={signature}"

def send_test_webhook(webhook_url, payload_file, webhook_secret):
    """Send a test webhook to the specified URL."""
    # Read the payload from file
    with open(payload_file, 'r') as f:
        payload = f.read()
    
    # Parse the payload to validate it's proper JSON
    try:
        json_payload = json.loads(payload)
        print(f"Test event: {json_payload.get('type', 'unknown')} ({json_payload.get('id', 'unknown')})")
    except json.JSONDecodeError:
        print("Error: Invalid JSON payload")
        return False
    
    # Generate signature
    timestamp = int(time.time())
    signature = generate_stripe_signature(payload, webhook_secret, timestamp)
    
    # Set up headers
    headers = {
        'Content-Type': 'application/json',
        'Stripe-Signature': signature
    }
    
    # Send the webhook request
    print(f"Sending test webhook to: {webhook_url}")
    print(f"Timestamp: {timestamp}")
    print(f"Signature: {signature}")
    
    try:
        response = requests.post(webhook_url, data=payload, headers=headers)
        print(f"Response: {response.status_code} {response.reason}")
        if response.content:
            print(f"Response content: {response.content.decode('utf-8')}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error sending webhook: {e}")
        return False

if __name__ == "__main__":
    # Your webhook URL with ngrok
    webhook_url = "https://23ed-2404-3100-1c8d-b871-2831-b68c-8b48-6d41.ngrok-free.app/api/accounts/webhook/stripe/"
    
    # Your webhook secret
    webhook_secret = "whsec_xMUDO69Ei6W0Wdlvlh8u36RkVnjcjbVK"
    
    # Your payload file
    payload_file = "test_event.json"
    
    # Send the test webhook
    success = send_test_webhook(webhook_url, payload_file, webhook_secret)
    
    if success:
        print("Webhook test completed successfully!")
    else:
        print("Webhook test failed!")
        sys.exit(1) 