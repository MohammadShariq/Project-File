from django.conf.urls import url
from tutorial import views

app_name = 'tutorial'
urlpatterns = [
    url(r'^$', views.home, name='home'),
    url(r'^home/$', views.home, name='home'),
    url(r'^gettoken/$', views.gettoken, name='gettoken'),
    url(r'^mail/$', views.mail, name='mail'),
    url(r'^events/$', views.events, name='events'),
    url(r'^contacts/$', views.contacts, name='contacts'),
]