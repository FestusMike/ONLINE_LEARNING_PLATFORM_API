from celery import shared_task
from celery.utils.log import get_task_logger
from django.template.loader import render_to_string
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.storage import default_storage
from django.utils import timezone
from .utils import send_email, GenerateOTP
from .models import Certificate
import redis

User = get_user_model()
redis_instance = redis.Redis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, db=settings.REDIS_DB)


logger = get_task_logger(__name__)

@shared_task
def send_welcome_email_task(user_id, otp):
    """Sends the welcome email with OTP using Celery."""
    try:
        user = User.objects.get(id=user_id)
        subject = "Welcome! Verify your email address."
        context = {
            "name": user.get_full_name(),
            "otp": otp,
        }
        message = render_to_string('welcome_email.html', context)

        sender_name = "Longman Academy"
        sender_email = settings.EMAIL_SENDER
        reply_to_email = settings.REPLY_TO_EMAIL
        to = [{"email": user.email, "name": user.get_full_name()}]

        send_email(
            to=to,
            subject=subject,
            sender={"name": sender_name, "email": sender_email},
            reply_to={"email": reply_to_email},
            html_content=message,
        )

    except User.DoesNotExist:
        print(f"User with ID {user_id} not found. Email not sent.") 

@shared_task
def send_otp_resend_email(user_id):
    """Sends the OTP resend email using Celery."""
    try:
        user = User.objects.get(id=user_id)
        otp = GenerateOTP(length=6)
        redis_instance.setex(name=f"user_{user.id}_otp", value=otp, time=300)

        subject = "Verify your email address."
        context = {'name': user.get_full_name(), 'otp': otp}
        message = render_to_string('otp_resend.html', context)

        sender_name = "Longman Academy"
        sender_email = settings.EMAIL_SENDER
        reply_to_email = settings.REPLY_TO_EMAIL
        to = [{"email": user.email, "name": user.get_full_name()}]

        send_email(
            to=to,
            subject=subject,
            sender={"name": sender_name, "email": sender_email},
            reply_to={"email": reply_to_email},
            html_content=message,
        )

    except User.DoesNotExist:
        print(f"User with ID {user_id} not found. Email not sent.")

@shared_task
def send_password_reset_otp_email(user_id):
    """Sends the password reset OTP email using Celery."""
    try:
        user = User.objects.get(id=user_id)
        otp = GenerateOTP(length=6)
        redis_instance.setex(name=f"user_{user.id}_otp", value=otp, time=300)

        subject = "Password Reset OTP."
        context = {'name': user.get_full_name(), 'otp': otp}
        message = render_to_string('password_reset.html', context)

        sender_name = "Longman Academy"
        sender_email = settings.EMAIL_SENDER
        reply_to_email = settings.REPLY_TO_EMAIL
        to = [{"email": user.email, "name": user.get_full_name()}]

        send_email(
            to=to,
            subject=subject,
            sender={"name": sender_name, "email": sender_email},
            reply_to={"email": reply_to_email},
            html_content=message,
        )

    except User.DoesNotExist:
        print(f"User with ID {user_id} not found. Email not sent.")

@shared_task
def delete_unverified_users():
    """
    Deletes users who haven't verified their email within 48 hours of registration.
    """

    time_threshold = timezone.now() - timezone.timedelta(hours=48)
    
    unverified_users = User.objects.filter(
    email_verified=False, 
    created_at__lt=time_threshold,
    is_superuser=False,
    is_staff=False,
    is_active=False
    )

    deleted_count, _ = unverified_users.delete()

    if deleted_count > 0:
        print(f"Deleted {deleted_count} unverified user accounts.")

