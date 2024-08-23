from django.db.models import Max


def get_auto_id(model, field_name='auto_id'):
	# Get the maximum value of the specified field
	latest_auto = model.objects.aggregate(Max(field_name))
	max_value = latest_auto.get(field_name + '__max')
	# Calculate the next auto_id
	if max_value is not None:
		auto_id = max_value + 1
	else:
		auto_id = 1
	return auto_id
