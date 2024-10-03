from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, Profile, Certificate, SalaryPayment, Notification

class ProfileInline(admin.StackedInline):
    model = Profile
    can_delete = False
    verbose_name_plural = 'Profile'

class CertificateInline(admin.TabularInline):
    model = Certificate.certificate_pictures.through
    extra = 1

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    inlines = (ProfileInline,)
    list_display = ('email', 'first_name', 'last_name', 'is_student', 'is_tutor', 'email_verified', 'is_staff')
    list_filter = ('is_student', 'is_tutor', 'is_staff', 'is_superuser', 'is_active', 'groups')
    search_fields = ('email', 'first_name', 'last_name')
    readonly_fields = ('created_at', 'updated_at', 'last_login', 'date_joined')
    ordering = ('email',)
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined', 'created_at', 'updated_at')}),
        ('User Roles', {'fields': ('is_student', 'is_tutor')}),
        ('Verification Status', {'fields': ('email_verified',)}),
    )
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("email", "password1", "password2", "is_active", "is_staff", 
                           "is_superuser", "is_student", "is_tutor", "email_verified"),
            },
        ),
    )

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'date_of_birth', 'current_age', 'phone_number', 'educational_qualification', 
                    'discipline', 'area_of_specialization', 'graduation_year', 'years_of_experience')
    list_filter = ('educational_qualification', 'discipline', 'area_of_specialization')
    search_fields = ('user__email', 'user__first_name', 'user__last_name', 'phone_number')
    inlines = [CertificateInline]

@admin.register(Certificate)
class CertificateAdmin(admin.ModelAdmin):
    list_display = ('id', 'caption', 'date_created')
    search_fields = ('caption',)

@admin.register(SalaryPayment)
class SalaryPaymentAdmin(admin.ModelAdmin):
    list_display = ('tutor', 'amount', 'payment_date', 'payment_status')
    list_filter = ('payment_status', 'payment_date')
    search_fields = ('tutor__email', 'tutor__first_name', 'tutor__last_name')

@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('user', 'notification_text', 'notification_type', 'is_read', 'created_at')
    list_filter = ('notification_type', 'is_read', 'created_at')
    search_fields = ('user__email', 'user__first_name', 'user__last_name', 'notification_text')
