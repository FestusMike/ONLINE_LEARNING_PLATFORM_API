from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from .models import User, Profile
from .tasks import send_welcome_email_task
from .utils import GenerateOTP
import redis
from django.conf import settings

User = get_user_model()


redis_instance = redis.Redis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, db=settings.REDIS_DB)

@receiver(post_save, sender=User)
def create_profile_and_send_welcome_email(sender, instance, created, **kwargs):
    """
    Creates a user profile and sends a welcome email with an OTP.
    """
    if created and not (instance.is_staff or instance.is_superuser):
        Profile.objects.create(user=instance)

        otp = GenerateOTP(length=6)
        redis_instance.setex(name=f"user_{instance.id}_otp", value=otp, time=300)

        send_welcome_email_task.delay(instance.id, otp)


