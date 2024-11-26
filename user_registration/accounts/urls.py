from django.urls import path
from .views import register_user, login_user, authorize_user, modify_user, delete_user, get_full_name

urlpatterns = [
    path('register/', register_user, name='register_user'),
    path('login/', login_user, name='login_user'),
    path('authorize_user/', authorize_user, name='authorize_user'),
    path('modify_user/', modify_user, name='modify_user'),
    path('delete_user/', delete_user, name='delete_user'),
    path('get_full_name/', get_full_name, name='get_full_name'),
]
