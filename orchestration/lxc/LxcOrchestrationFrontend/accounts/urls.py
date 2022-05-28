# accounts/urls.py
#from django.conf.urls import url
from django.urls import path
from . import views
from .views import SignUpView
from .views import Gateway_create_view
from django.views.generic import TemplateView


urlpatterns = [
    path('signup/', views.SignUpView, name='signup'),
    path('dashboard/', views.Dashboard_view, name='dashboard'),
    path('gatewayconfig/', views.Gateway_create_view, name='gatewayconfig'),
    path('hostconfig/', views.Host_create_view, name='hostconfig'),
    path('proxyconfig/', views.Proxy_create_view, name='proxyconfig'),
    path('routerconfig/', views.Router_create_view, name='routerconfig'),
    path('publicconfig/', views.Public_create_view, name='publicconfig'),
    path(r'^startContainer/(?P<ct_name>)/$', views.Start_container, name='startContainer'),
    path(r'^stopContainer/(?P<ct_name>)/$', views.Stop_container, name='stopContainer'),
    path(r'^containerInfo/(?P<ct_name>)/$', views.Get_Container_Info, name='containerInfo'),
    path('networkSetupExample/', views.Example_Network_view, name='networkSetupExample')
]
