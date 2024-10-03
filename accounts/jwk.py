from django.http import JsonResponse
from authlib.jose import JsonWebKey
from cryptography.hazmat.primitives import serialization
import os

def public_key_endpoint(request):
    # Load the private key from the PEM file
    try:
        public_key_path = os.getenv("VERIFYING_KEY")
        if not public_key_path:
            raise ValueError("VERIFYING_KEY environment variable is not set or is empty.")

        with open(public_key_path, 'rb') as key_file:
            public_key = key_file.read()

        # Convert public key to PEM format
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Import public key as JWK
        jwk = JsonWebKey.import_key(public_pem, {'kty': 'RSA'})
        public_jwk = jwk.as_dict()

        return JsonResponse({'keys': [public_jwk]})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
