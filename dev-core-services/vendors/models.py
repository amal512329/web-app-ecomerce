from django.db import models
from accounts.models import CustomUser
from base.models import BaseModel

# Create your models here.

class Vendor(BaseModel):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='vendor_profile')
    name = models.CharField(max_length=255, verbose_name='Name')
    slug = models.SlugField(verbose_name='Slug',null=False)
    email = models.EmailField(verbose_name='Email')
    website = models.URLField(blank=True, verbose_name='Website')
    country = models.CharField(max_length=100, verbose_name='Country')
    tax = models.CharField(max_length=50, verbose_name='Tax')

   
    class Meta:
        verbose_name = 'Vendor'
        verbose_name_plural = 'Vendors'
        ordering = ('name',)

    def __str__(self):
        return self.name