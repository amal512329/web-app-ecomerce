import uuid
from import_export import resources
from base.functions import get_auto_id


class BaseResource(resources.ModelResource):
   
    COMMON_FIELDS = (
        'id', 'auto_id', 'created_by', 'updated_by', 'deleted_by', 'created_at', 'updated_at', 'deleted_at',
        'is_deleted',
    )

    def before_import_row(self, row, **kwargs):
        request = kwargs.get('user')
        print("test case 1",request)
        print('the rows are',row)
        if request and request.is_authenticated:
            print('request is authenticated',request)
            if 'id' not in row:
                row['id'] = str(uuid.uuid4())

            if 'created_by' in row:
                print("created by: ", row['created_by'])
                print('The user is ,',request)
                row['created_by'] = request

            if 'updated_by'  in row:
                row['updated_by'] = request

            if 'is_deleted' in row and row['is_deleted'] == '0':
                row['deleted_by'] = None
                row['deleted_at'] = None

            if 'auto_id' not in row:
                row['auto_id'] = get_auto_id(self._meta.model)
                print('In resource the auto id is',row['auto_id'])



"""
class BaseResource(resources.ModelResource):
    COMMON_FIELDS = (
        'id', 'auto_id', 'created_by', 'updated_by', 'deleted_by', 'created_at', 'updated_at', 'deleted_at',
        'is_deleted',
    )

    def before_import_row(self, row, **kwargs):
        if kwargs.get('user') and kwargs.get('user').is_authenticated and kwargs.get('user').is_superuser:
            if 'id' not in row:
                row['id'] = str(uuid.uuid4())

            if 'created_by' not in row:
                row['created_by'] = settings.CORE_USER_ID

            if 'updated_by' not in row:
                row['updated_by'] = settings.CORE_USER_ID

            if 'is_deleted' in row and row['is_deleted'] == '0':
                row['deleted_by'] = None
                row['deleted_at'] = None

            if 'auto_id' not in row:
                row['auto_id'] = get_auto_id(self._meta.model)
"""
