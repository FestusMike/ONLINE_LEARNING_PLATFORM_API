import random
import string
import hashlib
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
from rest_framework import serializers
from django.conf import settings

def profile_image_path(instance, filename):
    return f"profiles/{instance.user.first_name}_{instance.user.last_name}/{filename}"

def certificate_pictures_path(instance, filename):
    return f"certificate_pictures/{filename}"

def calculate_file_hash(file):
    """Calculate the MD5 hash of the file."""
    hasher = hashlib.md5()
    for chunk in file.chunks():
        hasher.update(chunk)
    return hasher.hexdigest()

def GenerateOTP(length: int):
    if length < 1:
        raise ValueError("Length must be at least 1")

    otp_char = string.digits[1:]
    first_char = random.choice(string.digits[1:])
    otp = first_char + "".join(random.choice(otp_char) for _ in range(length - 1))
    return otp[:length]

def send_email(to, reply_to, html_content, sender, subject):
    try:
        configuration = sib_api_v3_sdk.Configuration()
        configuration.api_key["api-key"] = settings.EMAIL_API_KEY

        api_instance = sib_api_v3_sdk.TransactionalEmailsApi(
            sib_api_v3_sdk.ApiClient(configuration)
        )
        send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
            to=to,
            reply_to=reply_to,
            html_content=html_content,
            sender=sender,
            subject=subject,
        )
        api_response = api_instance.send_transac_email(send_smtp_email)

        print("Email sent successfully:", api_response)

        return "Success"

    except ApiException as e:
        print("Exception when calling SMTPApi->send_transac_email:", e)
        return "Fail"

def validate_password(value):
    if not any(c in string.digits for c in value) or not any (c in string.ascii_letters for c in value):
        raise serializers.ValidationError("Password must contain both digits and letters.")
    if len(value) < 8:
        raise serializers.ValidationError("Password must be at least 8 characters long")