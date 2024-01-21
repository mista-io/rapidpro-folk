"""
Written by Keeya Emmanuel Lubowa
On 24th Aug, 2022
Email ekeeya@oddjobs.tech
"""

from .views import *
from . import views
from django.urls import path
from .views import HandlerCRUDL, hello




# urlpatterns = HandlerCRUDL().as_urlpatterns(),

# # urlpatterns = [ path('ussd/', views.hello) ,

# #                path('ussd1/', views.HandlerCRUDL.List.as_view(), name='ussd.handler_list')]
urlpatterns = [
    path('ussd/handlers/', HandlerCRUDL.List.as_view(), name='ussd.handler_list'),
    path('ussd/handlers/create/', HandlerCRUDL.Create.as_view(), name='ussd.handler_create'),
    # path('ussd/handlers/delete/<int:pk>/', HandlerCRUDL.Delete.as_view(), name='ussd.handler_delete'),
    path('ussd/handlers/read/<int:pk>/', HandlerCRUDL.Read.as_view(), name='ussd.handler_read'),
    path('ussd/handlers/update/<int:pk>/', HandlerCRUDL.Update.as_view(), name='ussd.handler_update'),
    path('hello/', hello, name='hello'),  # Example path for the hello view
]            
