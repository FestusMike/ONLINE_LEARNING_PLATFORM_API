from rest_framework import serializers
import re
from datetime import datetime, date
from .utils import validate_password
from .models import Profile, Certificate
import filetype

class UserRegistrationSerializer(serializers.Serializer):
    first_name = serializers.CharField(max_length=150, required=True)
    last_name = serializers.CharField(max_length=150, required=True)
    email = serializers.EmailField(required=True)

    def validate_first_name(self, value):
        if not re.match("^[a-zA-Z-]+$", value):
            raise serializers.ValidationError("Only alphabetical characters and hyphens are allowed for the first name.")
        return value
    
    def validate_last_name(self, value):
        if not re.match("^[a-zA-Z-]+$", value):
            raise serializers.ValidationError("Only alphabetical characters and hyphens are allowed for the last name.")
        return value


class NewOTPRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()


class OTPVerificationSerializer(serializers.Serializer):
    otp = serializers.CharField()
    email = serializers.EmailField(required=False)

    def validate(self, data):
        """
        Check if either email or request.user is provided.
        """
        if not data.get('email') and not self.context.get('request').user.is_authenticated:
            raise serializers.ValidationError("Email is required for unauthenticated users.")
        return data


class PasswordSerializer(serializers.Serializer):
    email = serializers.CharField(required=True)
    password1 = serializers.CharField(write_only=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True)

    def validate(self, data):
        password1 = data.get("password1")
        password2 = data.get("password2")

        if password1 != password2:
            raise serializers.ValidationError("Passwords don't match")        
        return data

class DeliberatePasswordChangeSerializer(serializers.Serializer):
    current_password = serializers.CharField(write_only=True)
    new_password1 = serializers.CharField(write_only=True, validators=[validate_password])
    new_password2 = serializers.CharField(write_only=True)

    def validate(self, data):
        self.password_equality(data)
        return data

    def password_equality(self, data):
        new_password1 = data.get("new_password1")
        new_password2 = data.get("new_password2")

        if new_password1 != new_password2:
            raise serializers.ValidationError("Passwords don't match")
        return data

    
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class CertificateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Certificate
        fields = ["id", "image"]


class ProfileUpdateSerializer(serializers.ModelSerializer):
    current_age = serializers.IntegerField(read_only=True)
    certificates = CertificateSerializer(many=True, read_only=True)
    certificate_files = serializers.ListField(
        child=serializers.ImageField(), write_only=True, required=False
    ) 

    class Meta:
        model = Profile
        fields = [
            'date_of_birth', 'current_age', 'profile_picture', 'linkedin_url',
            'phone_number', 'educational_qualification', 'discipline',
            'area_of_specialization', 'graduation_year', 'years_of_experience',
            'certificates', "certificate_files"
        ]
        extra_kwargs = {
            'date_of_birth': {'required': True},
            'area_of_specialization' : {"required": True},
            'educational_qualification':{"required" : True}
            }
        
    def validate_date_of_birth(self, value):
        """Ensure date_of_birth is valid and calculate age."""
        if not value:
            raise serializers.ValidationError("Date of birth is required.")

        today = date.today()
        age = today.year - value.year - ((today.month, today.day) < (value.month, value.day))

        if age < 0:
            raise serializers.ValidationError("Date of birth cannot be in the future.")

        max_age = 120 
        if age > max_age:
            raise serializers.ValidationError(f"Invalid date of birth. Age cannot be greater than {max_age} years.")

        return value

    def validate_graduation_year(self, value):
        """Ensure the graduation year is logical."""
        current_year = datetime.now().year
        if value:
            if value < 1900:
                raise serializers.ValidationError("Graduation year cannot be earlier than 1900.")
            if value > current_year:
                raise serializers.ValidationError(f"Graduation year cannot be in the future. It must be before or equal to {current_year}.")
        return value

    def validate_profile_picture(self, value):
        """Validate profile picture format and size."""
        if value:
            kind = filetype.guess(value)
            if kind is None or kind.mime not in ['image/jpeg', 'image/png']:
                raise serializers.ValidationError("Only JPEG and PNG formats are allowed.")
            if value.size > 5 * 1024 * 1024:
                raise serializers.ValidationError("Profile picture size must not exceed 5MB.")
        return value
    
    def validate_phone_number(self, value):
        """Validate phone number format."""
        if value:
            phone_number = re.sub(r"[^\d+]", "", value)
            if not re.match(r"^\+\d{10,15}$", phone_number):
                raise serializers.ValidationError("Invalid phone number format. Please use a format similar to +2348012345678.")
        return value


    def validate_certificate_files(self, value):
        """Validate certificates for file type and size."""
        if value:
            for certificate in value:
                kind = filetype.guess(certificate)
                if kind is None or kind.mime not in ['image/jpeg', 'image/png']:
                    raise serializers.ValidationError(f"{certificate.name} is not a valid image format (JPEG or PNG required).")
                if certificate.size > 5 * 1024 * 1024:
                    raise serializers.ValidationError(f"{certificate.name} exceeds the maximum size of 5MB.")
        return value

    def validate(self, data):
        """Ensure all validations for tutors and optional validation for students."""
        user = self.context['request'].user

        if 'date_of_birth' in data:
            age = datetime.now().year - data['date_of_birth'].year - (
            (datetime.now().month, datetime.now().day) < (data['date_of_birth'].month, data['date_of_birth'].day))
            data['current_age'] = age

        if user.is_tutor:
            required_fields = [
            'date_of_birth', 'profile_picture', 'linkedin_url', 'phone_number',
            'educational_qualification', 'discipline', 'area_of_specialization',
            'graduation_year', 'years_of_experience', 'certificates', 'certificate_files'
        ]
            for field in required_fields:
                if field not in data or not data.get(field):
                    raise serializers.ValidationError({field: f"{field.replace('_', ' ').capitalize()} is required for tutors."})
        return data

    