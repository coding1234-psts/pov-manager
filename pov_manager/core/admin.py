from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from .models import User


class UserAdmin(DjangoUserAdmin):
    list_display = ('email', 'first_name', 'last_name')
    ordering = ('email', )


admin.site.unregister(User)
admin.site.register(User, UserAdmin)
