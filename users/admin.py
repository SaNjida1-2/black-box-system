from django.contrib import admin
from .models import Profile

# We manually register it to ensure the Role field is visible
@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    # This column will now appear in the main list
    list_display = ('user', 'role')
    # This forces the Role field to appear when you click on a profile
    fields = ('user', 'role', 'name', 'description', 'image', 'wing')

# If there is another "admin.site.register(Profile)" line anywhere else, delete it!
