from django.contrib.auth import get_user_model, authenticate
from django.conf import settings
from django.utils import timezone
from django.db import transaction
from drf_spectacular.utils import extend_schema
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.parsers import MultiPartParser, FormParser
from .serializers import (UserRegistrationSerializer, NewOTPRequestSerializer, OTPVerificationSerializer, 
                          PasswordSerializer, LoginSerializer, DeliberatePasswordChangeSerializer, 
                          ProfileUpdateSerializer)
from .models import Certificate
from .utils import calculate_file_hash
from .tasks import send_otp_resend_email, send_password_reset_otp_email
import redis
from cloudinary.exceptions import Error as CloudinaryError
import logging


logger = logging.getLogger(__name__)

User = get_user_model()
redis_instance = redis.Redis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, db=settings.REDIS_DB)


@extend_schema(
    description= """
    This endpoint registers a new student user based on their full name and email address.
    It then sends an OTP (One-Time Password) to the provided email address for verification purposes.
    """,
    request=UserRegistrationSerializer,
    responses={
        201: {
            "type": "object",
            "properties": {
                "status": {"type": "integer", "description": "HTTP status code"},
                "Success": {"type": "boolean", "description": "Indicates if the request was successful"},
                "message": {"type": "string", "description": "A human-readable message describing the outcome"},
                "data": {
                    "type": "object",
                    "properties" : {
                        "first_name" :{"type" : "string", "description": "The titled first name of the registered user"},
                        "last_name" :{"type" : "string", "description": "The titled last name of the registered user"},
                        "email" :{"type" : "string", "description": "The email address of the registered user"} 
                    }                    
                    },
            },
        },
        400: {
            "type": "object",
            "properties": {
                "status": {"type": "integer", "description": "HTTP status code"},
                "Success": {"type": "boolean", "description": "Indicates if the request was successful"},
                "message": {"type": "string", "description": "A human-readable message describing the outcome"},
            },
        },
        500: {
            "type": "object",
            "properties": {
                "status": {"type": "integer", "description": "HTTP status code"},
                "Success": {"type": "boolean", "description": "Indicates if the request was successful"},
                "message": {"type": "string", "description": "A human-readable message describing the outcome"},
            },
        },
    },
    methods=["POST"],
    tags=['Authentication']
    )
class StudentRegistrationAPIView(generics.GenericAPIView):
    """
    Registers a new student user.

    Sends an OTP to the provided email address for verification.
    """

    serializer_class = UserRegistrationSerializer
          
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        if User.objects.filter(email=email).exists():
            return Response(
                {
                    "status": status.HTTP_400_BAD_REQUEST,
                    "Success": False,
                    "message": "User with this email already exists",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        first_name = serializer.validated_data["first_name"].title()
        last_name = serializer.validated_data["last_name"].title()
        User.objects.create_user(
            email=email,
            first_name=first_name,
            last_name=last_name,
            is_student=True,
            is_active=False
        )
        response_data = {
            "status": status.HTTP_201_CREATED,
            "Success": True,
            "message": "Thank you for registering with us. A 6-digit OTP has been sent to your email address. Please check your inbox or spam folder.",
            "data": {"first_name": first_name, "last_name": last_name, "email": email}
        }
        return Response(response_data, status=status.HTTP_201_CREATED)
    
@extend_schema(
    description= """
    This endpoint registers a new tutor user based on their full name and email address.
    It then sends an OTP (One-Time Password) to the provided email address for verification purposes.
    """,
    request=UserRegistrationSerializer,
    responses={
        201: {
            "type": "object",
            "properties": {
                "status": {"type": "integer", "description": "HTTP status code"},
                "Success": {"type": "boolean", "description": "Indicates if the request was successful"},
                "message": {"type": "string", "description": "A human-readable message describing the outcome"},
                "data": {
                    "type": "object",
                    "properties" : {
                        "first_name" :{"type" : "string", "description": "The titled first name of the registered user"},
                        "last_name" :{"type" : "string", "description": "The titled last name of the registered user"},
                        "email" :{"type" : "string", "description": "The email address of the registered user"} 
                    }                    
                    },
            },
        },
        400: {
            "type": "object",
            "properties": {
                "status": {"type": "integer", "description": "HTTP status code"},
                "Success": {"type": "boolean", "description": "Indicates if the request was successful"},
                "message": {"type": "string", "description": "A human-readable message describing the outcome"},
            },
        },
        500: {
            "type": "object",
            "properties": {
                "status": {"type": "integer", "description": "HTTP status code"},
                "Success": {"type": "boolean", "description": "Indicates if the request was successful"},
                "message": {"type": "string", "description": "A human-readable message describing the outcome"},
            },
        },
    },
    methods=["POST"],
    tags=['Authentication']
    )
class TutorRegistrationAPIView(generics.GenericAPIView):
    """
    Registers a new tutor user.

    Sends an OTP to the provided email address for verification.
    """

    serializer_class = UserRegistrationSerializer
          
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        if User.objects.filter(email=email).exists():
            return Response(
                {
                    "status": status.HTTP_400_BAD_REQUEST,
                    "Success": False,
                    "message": "User with this email already exists",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        first_name = serializer.validated_data["first_name"].title()
        last_name = serializer.validated_data["last_name"].title()
        User.objects.create_user(
            email=email,
            first_name=first_name,
            last_name=last_name,
            is_tutor=True,
            is_active=False
        )
        response_data = {
            "status": status.HTTP_201_CREATED,
            "Success": True,
            "message": "Thank you for registering with us. A 6-digit OTP has been sent to your email address. Please check your inbox or spam folder.",
            "data": {"first_name": first_name, "last_name": last_name, "email": email}
        }
        return Response(response_data, status=status.HTTP_201_CREATED)

@extend_schema(
        description="""
        This endpoint resends a 6-digit OTP for any action if a user's OTP expires.
        The user enters their registered email to receive the new OTP.
        """,
        request=NewOTPRequestSerializer,
        responses={
            200: {
                "type": "object",
                "properties": {
                    "status": {"type": "integer", "description": "HTTP status code"},
                    "Success": {"type": "boolean", "description": "Indicates if the request was successful"},
                    "message": {"type": "string", "description": "A human-readable message describing the outcome"},
                },
            },
            400: {
                "type": "object",
                "properties": {
                    "status": {"type": "integer", "description": "HTTP status code"},
                    "Success": {"type": "boolean", "description": "Indicates if the request was successful"},
                    "message": {"type": "string", "description": "A human-readable message describing the outcome"},
                },
            },
            404: {
                "type": "object",
                "properties": {
                    "status": {"type": "integer", "description": "HTTP status code"},
                    "Success": {"type": "boolean", "description": "Indicates if the request was successful"},
                    "message": {"type": "string", "description": "A human-readable message describing the outcome"},
                },
            },
            500: {
                "type": "object",
                "properties": {
                    "status": {"type": "integer", "description": "HTTP status code"},
                    "Success": {"type": "boolean", "description": "Indicates if the request was successful"},
                    "message": {"type": "string", "description": "A human-readable message describing the outcome"},
                },
            },
        },
        methods=["POST"],
        tags=["Authentication"]
    )
class ResendOTPAPIView(generics.GenericAPIView):
    """
    This view resends a verification OTP for any action if a user's OTP expires.
    The user enters their registered email to receive a new 6-digit OTP.
    """

    serializer_class = NewOTPRequestSerializer
    
    def post(self, request, *args, **kwargs):
        
        if request.user.is_authenticated:
            email = request.user.email
        
        else:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            email = serializer.validated_data["email"]

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {
                    "status": status.HTTP_404_NOT_FOUND,
                    "Success": False,
                    "message": "E-mail doesn't exist",
                },
                status=status.HTTP_404_NOT_FOUND,
            )
        cached_otp = redis_instance.get(f"user_{user.id}_otp")
        if cached_otp:
            return Response(
                {
                    "status": status.HTTP_400_BAD_REQUEST,
                    "Success": False,
                    "message": "You can't request another OTP until your current OTP expires.",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        today = timezone.now().date()
        redis_key = f"user_{user.id}_otp_requests_{today}"
        otp_requests = redis_instance.get(redis_key)

        if otp_requests and int(otp_requests) >= 2:
            return Response(
                {
                    "status": status.HTTP_429_TOO_MANY_REQUESTS,
                    "Success": False,
                    "message": "You have exceeded the maximum number of OTP requests for now. Please try again after 30 minutes.",
                },
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )
        redis_instance.incr(redis_key)
        redis_instance.expire(redis_key, 1800)

        send_otp_resend_email.delay(user.id) 

        return Response(
            {
                "status": status.HTTP_200_OK,
                "Success": True,
                "message": f"We have sent you a 6-digit OTP. Please check your inbox or spam folder.",
            },
            status=status.HTTP_200_OK,
        )
        
@extend_schema(
        description="""
        This endpoint verifies the OTP sent to a user's email address. 
        The user provides their email and OTP, and the system checks its validity against the cached value.
        """,
        request=OTPVerificationSerializer,
        responses={
            200: {
                "type": "object",
                "properties": {
                    "status": {"type": "integer", "description": "HTTP status code"},
                    "Success": {"type": "boolean", "description": "Indicates if the request was successful"},
                    "message": {"type": "string", "description": "A human-readable message describing the outcome"},
                },
            },
            400: {
                "type": "object",
                "properties": {
                    "status": {"type": "integer", "description": "HTTP status code"},
                    "Success": {"type": "boolean", "description": "Indicates if the request was successful"},
                    "message": {"type": "string", "description": "A human-readable message describing the outcome"},
                },
            },
            404: {
                "type": "object",
                "properties": {
                    "status": {"type": "integer", "description": "HTTP status code"},
                    "Success": {"type": "boolean", "description": "Indicates if the request was successful"},
                    "message": {"type": "string", "description": "A human-readable message describing the outcome"},
                },
            },
            500: {
                "type": "object",
                "properties": {
                    "status": {"type": "integer", "description": "HTTP status code"},
                    "Success": {"type": "boolean", "description": "Indicates if the request was successful"},
                    "message": {"type": "string", "description": "A human-readable message describing the outcome"},
                },
            },
        },
        methods=["POST"],
        tags=["Authentication"]
    )
class OTPVerificationAPIView(generics.GenericAPIView):
    """
    This view confirms the OTP sent to the user's email address.
    It checks if the provided OTP is valid and within the expiration time.
    If valid, the user's email is verified.
    """

    serializer_class = OTPVerificationSerializer

    def post(self, request, *args, **kwargs):
        
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        otp = serializer.validated_data["otp"]

        if request.user.is_authenticated:
            user = request.user
        else:
            email = serializer.validated_data["email"]
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response(
                    {
                        "status": status.HTTP_404_NOT_FOUND,
                        "Success": False,
                        "message": "User does not exist.",
                    },
                    status=status.HTTP_404_NOT_FOUND,
                )

        user_id = user.id
        cached_otp = redis_instance.get(f"user_{user_id}_otp")

        if cached_otp and otp == cached_otp.decode():
            user.email_verified = True
            user.save()
            redis_instance.delete(f"user_{user_id}_otp")
            return Response(
                {
                    "status": status.HTTP_200_OK,
                    "Success": True,
                    "message": "OTP verification successful.",
                },
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {
                    "status": status.HTTP_400_BAD_REQUEST,
                    "Success": False,
                    "message": "Invalid or expired OTP.",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
   
@extend_schema(
    description =  """
    This endpoint allows a user whose OTP has been verified to create a password.
    Once the password is created, their account is activated, and they can log in.
    """,
    request=PasswordSerializer,
    responses={
        201: {
            "type": "object",
            "properties": {
                "status": {"type": "integer"},
                "Success": {"type": "boolean"},
                "message": {"type": "string"},
                "access_token": {"type": "string"},
                "refresh_token": {"type": "string"},
            },
        },
        400: {
            "type": "object",
            "properties": {
                "status": {"type": "integer"},
                "Success": {"type": "boolean"},
                "message": {"type": "string"},
            },
        },
        404: {
            "type": "object",
            "properties": {
                "status": {"type": "integer"},
                "Success": {"type": "boolean"},
                "message": {"type": "string"},
            },
        },
    },
    methods=["POST"],
    ) 
class PasswordSetUpAPIView(generics.GenericAPIView):
    """
    This view allows a user whose OTP has been verified to create a password.
    Once the password is created, their account is activated.
    """
    serializer_class = PasswordSerializer
    
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {
                    "status": status.HTTP_404_NOT_FOUND,
                    "Success": False,
                    "message": "User Not Found",
                },
                status=status.HTTP_404_NOT_FOUND,
            )
        if not user.email_verified:
            return Response({
            "status": status.HTTP_400_BAD_REQUEST,
            "Success": False,
            "message": "Your email hasn't been verified yet. Please verify your email before attempting a password setup",
            
        }, status=status.HTTP_400_BAD_REQUEST
        
        )            
        user.set_password(serializer.validated_data["password1"])
        user.is_active = True
        user.last_login = timezone.now()
        user.save()

        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        response_data = {
            "status": status.HTTP_201_CREATED,
            "Success": True,
            "message": "Password set successfully and account creation complete.",
            "access_token": access_token,
            "refresh_token": refresh_token,
        }

        return Response(response_data, status=status.HTTP_201_CREATED)
    
@extend_schema(
    description= """
    This endpoint allows a user to login based on their e-mail and password. If these login params\n
    are valid, they will be provided with an access and a refresh token, which will be included\n
    in the header in every API call that requires authentication.
    """,
    request=LoginSerializer,
    responses={
        200: {
            "type": "object",
            "properties": {
                "status": {"type": "integer"},
                "Success": {"type": "boolean"},
                "message": {"type": "string"},
                "access_token": {"type": "string"},
                "refresh_token": {"type": "string"},
            },
        },
        401: {
            "type": "object",
            "properties": {
                "status": {"type": "integer"},
                "Success": {"type": "boolean"},
                "message": {"type": "string"},
            },
        },
    },
    methods=["POST"],
    )
class UserLoginAPIView(generics.GenericAPIView):
    """
    This view allows a user to login based on their e-mail and password. If these login params\n
    are valid, they will be provided with an access and a refresh token, which will be included\n
    in the header in every API call that requires authentication.
    """

    serializer_class = LoginSerializer

    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]

        user = authenticate(request, email=email, password=password)

        if user and user.is_active:
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)
            user.last_login = timezone.now()
            user.save()
            
            return Response(
                {
                    "status": status.HTTP_200_OK,
                    "Success": True,
                    "message": "Login successful",
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                },
                status=status.HTTP_200_OK,
            )

        elif user and not user.is_active:
            response_data = {
                "status": status.HTTP_401_UNAUTHORIZED,
                "Success": False,
                "message": "Inactive Account",
            }
            return Response(response_data, status=status.HTTP_401_UNAUTHORIZED)

        else:
            response_data = {
                "status": status.HTTP_401_UNAUTHORIZED,
                "Success": False,
                "message": "Invalid Credentials",
            }
            return Response(response_data, status=status.HTTP_401_UNAUTHORIZED)

@extend_schema(
    description=  """
    This endpoint blacklists the refresh token, consequently preventing a user from generating a new\n
    access token until they are re-authenticated.
    """,
    responses={
        200: {"description": "Log out successful"},
        400: {"description": "Log out not successful"}
    },
    request=None,
    methods=["POST"]
    ) 
class UserLogoutAPIView(generics.GenericAPIView):
    """
    This View blacklists the refresh token, consequently preventing a user from generating a new\n
    access token until they are re-authenticated.
    """
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get_serializer_class(self):
        return None
        
    def post(self, request, *args, **kwargs):
        try:
            refresh_token = request.data.get("refresh")
            if not refresh_token:
                raise Exception("Refresh token not provided")
            token = RefreshToken(refresh_token)
            token.blacklist()       

            user = request.user
            user.last_logout = timezone.now()
            user.save()
            response_data = {
                "status": status.HTTP_200_OK,
                "Success": True,
                "message": "Log out successful",
            }
            return Response(response_data, status=status.HTTP_200_OK)
        except Exception as e:
            response_data = {
                "status": status.HTTP_400_BAD_REQUEST,
                "Success": False,
                "message": f"Logout not successful because {e}",
            }
            return Response(response_data, status=status.HTTP_400_BAD_REQUEST)

@extend_schema(
        description="""
        This endpoint initiates a password reset process. It generates a 6-digit OTP (One-Time Password), 
        stores it in a cache, and sends it to the user's registered email address. 
        The OTP is valid for 5 minutes.
        """,
        request=NewOTPRequestSerializer,
        responses={
            200: {
                "type": "object",
                "properties": {
                    "status": {"type": "integer", "description": "HTTP status code"},
                    "Success": {"type": "boolean", "description": "Indicates if the request was successful"},
                    "message": {"type": "string", "description": "A human-readable message describing the outcome"},
                },
            },
            404: {
                "type": "object",
                "properties": {
                    "status": {"type": "integer", "description": "HTTP status code"},
                    "Success": {"type": "boolean", "description": "Indicates if the request was successful"},
                    "message": {"type": "string", "description": "A human-readable message describing the outcome"},
                },
            },
            500: {
                "type": "object",
                "properties": {
                    "status": {"type": "integer", "description": "HTTP status code"},
                    "Success": {"type": "boolean", "description": "Indicates if the request was successful"},
                    "message": {"type": "string", "description": "A human-readable message describing the outcome"},
                },
            },
        },
        methods=["POST"],
        tags=["Authentication"]
    )
class PasswordResetOTPAPIView(generics.GenericAPIView):

    """
    This view allows a user to generate a password reset OTP. If the user is authenticated,
    the OTP is sent directly to the user's registered e-mail. Otherwise, they will be required
    to provide their registered e-mail to receive the OTP.
    """
    permission_classes = [AllowAny]
    serializer_class = NewOTPRequestSerializer
    authentication_classes = [JWTAuthentication]

    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            email = request.user.email

        else:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            email = serializer.validated_data["email"]
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                    {
                        "status": status.HTTP_404_NOT_FOUND,
                        "Success": False,
                        "message": "E-mail doesn't exist",
                    },
                    status=status.HTTP_404_NOT_FOUND,
                )

        today = timezone.now().date()
        redis_key = f"user_{user.id}_otp_requests_{today}"
        otp_requests = redis_instance.get(redis_key)

        if otp_requests and int(otp_requests) >= 1:
            return Response(
                {
                    "status": status.HTTP_429_TOO_MANY_REQUESTS,
                    "Success": False,
                    "message": "You have exceeded the maximum number of OTP requests for now. Please try again after 30 minutes",
                },
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )
        redis_instance.incr(redis_key)
        redis_instance.expire(redis_key, 1800)

        send_password_reset_otp_email.delay(user.id)

        response_data = {
            "status": status.HTTP_200_OK,
            "Success": True,
            "message": "A password reset OTP has been sent to your registered email address. Please note that it expires after 5 minutes.",
        }
        return Response(response_data, status=status.HTTP_200_OK)

@extend_schema(
    description= """
    This endpoint is for users who have forgotten their passwords. They will be prompted to input their\n
    new password, and new password confirmation. Immediately these inputs are verified as valid,\n
    they will be allowed to login with their new password.
    """,
    request=PasswordSerializer,
    responses={
        200: {
            "type": "object",
            "properties": {
                "status": {"type": "integer"},
                "Success": {"type": "boolean"},
                "message": {"type": "string"},
            },
        },
        400: {
            "type": "object",
            "properties": {
                "status": {"type": "integer"},
                "Success": {"type": "boolean"},
                "message": {"type": "string"},
            },
        },
        404: {
            "type": "object",
            "properties": {
                "status": {"type": "integer"},
                "Success": {"type": "boolean"},
                "message": {"type": "string"},
            },
        },
    },
    methods=["POST"],
    )
class ForgottenPasswordResetAPIView(generics.GenericAPIView):
    
    """
    This view is for users who have forgotten their passwords. They will be prompted to input their\n
    new password, and new password confirmation. Immediately these inputs are verified as valid,\n
    they will be allowed to login with their new password.
    """
    serializer_class = PasswordSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {
                    "status": status.HTTP_404_NOT_FOUND,
                    "Success": False,
                    "message": "User Not Found",
                },
                status=status.HTTP_404_NOT_FOUND,
            )
        cached_otp = redis_instance.get(f"user_{user.id}_otp")
        if cached_otp:
            return Response(
                {
                    "status": status.HTTP_400_BAD_REQUEST,
                    "Success": False,
                    "message": "An OTP is currently active for this account. Please verify the OTP before resetting your password.",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        new_password = serializer.validated_data["password1"]
        user.set_password(new_password)
        user.save()

        return Response(
                {
                    "status": status.HTTP_200_OK,
                    "Success": True,
                    "message": "Password changed successfully",
                },
                status=status.HTTP_200_OK,
            )

@extend_schema(
    description =  """
    This endpoint allows only authenticated users to change their password.\n
    A more nuanced explanation is that a user didn't forget their password, but they feel like changing it for reasons\n
    best personal to them. Hence, they will be required to provide their current password before they can proceed.
    """,
    request=DeliberatePasswordChangeSerializer,
    responses={
        200: {
            "type": "object",
            "properties": {
                "status": {"type": "integer"},
                "Success": {"type": "boolean"},
                "message": {"type": "string"},
            },
        },
        400: {
            "type": "object",
            "properties": {
                "status": {"type": "integer"},
                "Success": {"type": "boolean"},
                "message": {"type": "string"},
            },
        },
        404: {
            "type": "object",
            "properties": {
                "status": {"type": "integer"},
                "Success": {"type": "boolean"},
                "message": {"type": "string"},
            },
        },
    },
    methods=["POST"],
    )
class DeliberatePasswordResetAPIView(generics.GenericAPIView):
    """
    Unlike the ForgottenPasswordResetAPIView, this view allows only authenticated users to change their password.\n
    A more nuanced explanation is that a user didn't forget their password, but they feel like changing it for reasons\n
    best personal to them. Hence, they will be required to provide their current password before they can proceed.
    """
    serializer_class = DeliberatePasswordChangeSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user

        if not user.check_password(serializer.validated_data["current_password"]):
            return Response(
                {"status": status.HTTP_400_BAD_REQUEST,
                 "Success": False,
                 "message": "Incorrect password"},
                status=status.HTTP_400_BAD_REQUEST)
        
        new_password = serializer.validated_data["new_password1"]
        user.set_password(new_password)
        user.save()

        return Response(
            {
                "status": status.HTTP_200_OK,
                "Success": True,
                "message": "Password changed successfully",
            },
            status=status.HTTP_200_OK,
        )


class UserProfileUpdateAPIView(generics.UpdateAPIView):
    serializer_class = ProfileUpdateSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    parser_classes = [MultiPartParser, FormParser]

    def get_object(self):
        return self.request.user.profile

    @transaction.atomic
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        try:
        
            self._update_profile_picture(instance, request.FILES.get('profile_picture'))

            self._update_certificates(instance, request.FILES.getlist('certificate_files'))

            self.perform_update(serializer)

            return Response({
                "status": status.HTTP_200_OK,
                "success": True,
                "message": "Profile updated successfully",
                "data": serializer.data,
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error updating profile: {str(e)}")
            return Response({
                "status": status.HTTP_500_INTERNAL_SERVER_ERROR,
                "success": False,
                "message": "An error occurred while updating the profile",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _update_profile_picture(self, instance, new_profile_picture):
        if new_profile_picture:
            if instance.profile_picture:
                instance.profile_picture.delete()
            instance.profile_picture = new_profile_picture
            
    def _update_certificates(self, instance, new_certificates):
        if new_certificates:
            for certificate in new_certificates:
                if certificate.size == 0:
                    logger.warning(f"Skipping empty certificate file: {certificate.name}")
                    continue

                try:
                    certificate_hash = calculate_file_hash(certificate)
                    existing_cert = Certificate.objects.filter(image_hash=certificate_hash).first()

                    if existing_cert:
                        self._update_existing_certificate(existing_cert, certificate)
                    else:
                        self._create_new_certificate(instance, certificate, certificate_hash)

                except CloudinaryError as e:
                    logger.error(f"Cloudinary upload error for {certificate.name}: {str(e)}")
                    raise
                except Exception as e:
                    logger.error(f"Error processing certificate {certificate.name}: {str(e)}")
                    raise

    def _update_existing_certificate(self, existing_cert, new_certificate):
        existing_cert.image.delete()
        existing_cert.image = new_certificate
        existing_cert.save()

    def _create_new_certificate(self, instance, certificate, certificate_hash):
        new_cert = Certificate.objects.create(image=certificate, image_hash=certificate_hash)
        instance.certificates.add(new_cert)