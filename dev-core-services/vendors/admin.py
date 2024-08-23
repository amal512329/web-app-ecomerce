from django.contrib import admin
from .models import Vendor
from .resources import VendorResource
from import_export.admin import ImportExportModelAdmin


# Register your models here.


# class VendorAdmin(admin.ModelAdmin):

#     prepopulated_fields = {'slug': ('name',)}
#     list_display = ('name', 'email', 'website', 'country','slug', 'tax')
#     search_fields = ('name', 'email', 'country', 'tax')
#     list_filter = ('country',)

    # Add any other customizations you need

class VendorAdmin(ImportExportModelAdmin):
    
    resource_class = VendorResource 
    list_display = ('auto_id','created_by','user', 'is_deleted')
    fieldsets = (
        ('User Information', {
            'fields': ('user',  'is_deleted')
        }),
        ('Address', {
            'fields': ('name', 'email', 'website', 'country', 'slug', 'tax')
        }),

    )
        

admin.site.register(Vendor,VendorAdmin)