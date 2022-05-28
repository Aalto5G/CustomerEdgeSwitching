from django.contrib import admin
from .models import Gateway, Host, Router

# Register your models here.
class ContactAdmin(admin.ModelAdmin):
    pass
    #list_display = ('Host_name', 'Mgt0_IP_Address', 'Lan_Network_Link', 'Lan_IP_Address','Wan_Network_link','Wan_IP_Address','Wan_Gateway_Address')
    #list_display = ('Host_name', 'Gateway_name', 'Mgt0_IP_Address', 'Private_interface_name', 'Private_IP_Address', 'Public_iface_name', 'Public_iface_IP_Address',
    #                'Public_default_gateway_address', 'Container_Memory', 'CPU_Cores', 'Lan_Network_Link', 'Lan_IP_Address','Wan_Network_link','Wan_IP_Address','Wan_Gateway_Address')

admin.site.register(Gateway, ContactAdmin)
