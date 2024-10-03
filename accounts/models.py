from django.db import models
from django.contrib.auth.models import AbstractUser
from .constants import SALARY_PAYMENT_STATUS, NOTIFICATION_TYPE, EDUCATIONAL_QUALIFICATION, AREA_OF_SPECIALIZATION
from utils.models import BaseModel
from .utils import profile_image_path, certificate_pictures_path
from .managers import CustomUserManager


class User(AbstractUser, BaseModel):
    username = None
    email = models.EmailField(unique=True, blank=False)
    is_student = models.BooleanField(default=False)
    is_tutor = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False) 
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def __str__(self):
        return self.email


class Profile(BaseModel):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    date_of_birth = models.DateField(null=True)
    current_age = models.IntegerField(null=True)
    profile_picture = models.ImageField(blank=True, null=True, upload_to=profile_image_path)
    linkedin_url = models.URLField(max_length=255, blank=True, null=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    educational_qualification = models.CharField(max_length=15, null=True, blank=True, choices=EDUCATIONAL_QUALIFICATION)
    discipline = models.CharField(max_length=30, null=True, blank=True) 
    area_of_specialization = models.CharField(max_length=50, null=True, blank=True, choices=AREA_OF_SPECIALIZATION)
    graduation_year = models.IntegerField(null=True)
    certificates = models.ManyToManyField("Certificate", related_name="certificate_pictures")
    years_of_experience = models.IntegerField(null=True)
    date_updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.first_name} {self.user.last_name}'s Profile"


class Certificate(BaseModel):
    image = models.ImageField(null=True, upload_to=certificate_pictures_path)
    image_hash = models.CharField(max_length=64, default="")
    caption = models.CharField(max_length=200, blank=True)
    date_created = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "Tutors_Certificates"
        abstract = False
        ordering = ["-date_created"]

    def __str__(self):
        return f"{self.id}"


class SalaryPayment(BaseModel):
    tutor = models.ForeignKey(User, on_delete=models.CASCADE, related_name='salary_payments')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_date = models.DateTimeField(auto_now_add=True)
    payment_status = models.CharField(max_length=20, choices=SALARY_PAYMENT_STATUS)

    def __str__(self):
        return f"Salary Payment to {self.tutor.username}"


class Notification(BaseModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    notification_text = models.TextField()
    notification_type = models.CharField(max_length=50, choices=NOTIFICATION_TYPE) 
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Notification for {self.user.username}"
