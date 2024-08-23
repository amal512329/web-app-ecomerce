from base.resources import BaseResource
from .models import Vendor


class VendorResource(BaseResource):
    class Meta:
        model = Vendor
        fields = BaseResource.COMMON_FIELDS + (
            'user', 'name', 'slug', 'email', 'website', 'country', 'tax'
        )
