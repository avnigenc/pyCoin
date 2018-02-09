#-*- coding: utf-8 -*-
from django.conf import settings
from django.conf.urls import url
from django.conf.urls.static import static
from django.contrib import admin
import pycoin.views

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^$', pycoin.views.landing),
    url(r'^login', pycoin.views.login),
    url(r'^logout', pycoin.views.logout),
    url(r'^createnewwallet/', pycoin.views.createnewwallet),
    url(r'^transactions', pycoin.views.ws),
    url(r'^checkwallet/', pycoin.views.checkwallet),
    url(r'^sendpycoin', pycoin.views.sendpycoin),



] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
