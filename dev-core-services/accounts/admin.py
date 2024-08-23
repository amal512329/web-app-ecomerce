from django.contrib import admin
from .models import CustomUser
from django.contrib.auth.admin import UserAdmin
from import_export.admin import ImportExportModelAdmin
from .resources import UserProfileResource
# Register your models here.


class CustomUserAdmin(UserAdmin):
    list_display = ('firstname', 'lastname', 'username', 'email', 'role', 'is_active', 'date_joined','is_active_2fa','id')
    search_fields = ('username', 'email', 'phone', 'first_name', 'last_name')
    list_filter = ('role', 'is_active', 'is_staff', 'is_superuser')
    ordering = ('-date_joined',)

    fieldsets = (
        (None, {'fields': ('username', 'email', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name', 'phone')}),
        ('Roles and Permissions', {'fields': ('role', 'is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
       
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2', 'is_active_2fa', 'role', 'is_active', 'is_staff', 'is_superuser', 'first_name', 'last_name','id'),
        }),
    )

    filter_horizontal = ('groups', 'user_permissions')

    # Add any other customizations you need


from django.contrib import admin
from .models import UserProfile

# class UserProfileAdmin(admin.ModelAdmin):
#     list_display = ('user', 'address1', 'dist', 'state', 'country', 'zip_code','created_at','updated_at','is_active','is_deleted')
#     search_fields = ('user__username', 'user__email', 'dist', 'state', 'country', 'zip_code')
#     list_filter = ('dist', 'state', 'country')

#     fieldsets = (
#         ('User Information', {
#             'fields': ('user','created_at',  'is_active', 'is_deleted')
#         }),
#         ('Address', {
#             'fields': ('address1', 'address2', 'address3', 'dist', 'state', 'country', 'zip_code')
#         }),
#         ('Profile Pictures', {
#             'fields': ('profile', 'cover')
#         }),
#     )

    
class UserProfileAdmin(ImportExportModelAdmin):
    
    resource_class = UserProfileResource 
   
    list_display = ('auto_id','user','created_at','is_deleted')
    fieldsets = (
        ('User Information', {
            'fields': ('user','created_by' , 'is_deleted')
        }),
        ('Address', {
            'fields': ('address1', 'address2', 'address3', 'dist', 'state', 'country', 'zip_code')
        }),
        ('Profile Pictures', {
            'fields': ('profile', 'cover')
        }),
    )



admin.site.register(UserProfile, UserProfileAdmin)

admin.site.register(CustomUser, CustomUserAdmin)