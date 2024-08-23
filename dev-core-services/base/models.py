from django.db import models
import uuid


# BASE USER MODEL This model not created tables in database, This model class can extends for another classes.
class BaseModel(models.Model):
    
    
    
    
    auto_id = models.PositiveIntegerField(db_index=True, unique=True)
    created_by = models.ForeignKey(
        "accounts.CustomUser", blank=True, related_name="created_by_%(class)s_objects", on_delete=models.CASCADE,
        null=True
    )
    updated_by = models.ForeignKey(
        "accounts.CustomUser", blank=True, related_name="updated_by_%(class)s_objects", on_delete=models.CASCADE,
        null=True
    )
    deleted_by = models.ForeignKey(
        "accounts.CustomUser", blank=True, null=True, related_name="deleted_by_%(class)s_objects", on_delete=models.CASCADE
    )
    created_at = models.DateTimeField(db_index=True, auto_now_add=True)
    updated_at = models.DateTimeField(db_index=True, auto_now=True)
    deleted_at = models.DateTimeField(db_index=True, null=True, blank=True)
    is_deleted = models.BooleanField(default=False)

    class Meta:
        abstract = True
