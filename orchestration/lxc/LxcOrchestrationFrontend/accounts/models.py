from django.db import models
# Create your models here.

class Gateway(models.Model):
    id = models.AutoField(primary_key=True)
    Gateway_name = models.CharField(max_length=100)
    Domain_name = models.CharField(max_length=256)
    Mgt0_IP_Address = models.CharField(max_length=50)
    Private_interface_name = models.CharField(max_length=4, default="lan0")
    Private_IP_Address = models.CharField(max_length=50, blank=True, null=True)
    Public_interface_name = models.CharField(max_length=4, default="wan0")
    Public_iface_IP_Address = models.CharField(max_length=50, default=None)
    Public_default_gateway_address = models.CharField(max_length=50, default=None)
    Container_Memory = models.CharField(max_length=500, default=1024)
    CPU_Cores = models.CharField(max_length=500, default=2)


class Host(models.Model):
    id = models.AutoField(primary_key=True)
    Host_name = models.CharField(max_length=100)
    Domain_name = models.CharField(max_length=256)
    Mgt0_IP_Address = models.CharField(max_length=50)
    Lan0_IP_Address = models.CharField(max_length=50)
    Lan0_iface_direction = models.CharField(max_length=50)
    Lan0_gateway_address = models.CharField(max_length=50)
    Lan0_gateway_name = models.CharField(max_length=50)
    container_Memory = models.CharField(max_length=500)
    CPU_Cores = models.CharField(max_length=500)


class Proxy(models.Model):
    id = models.AutoField(primary_key=True)
    Proxy_name = models.CharField(max_length=100)
    Domain_name = models.CharField(max_length=256)
    Mgt0_IP_Address = models.CharField(max_length=50)
    Lan0_IP_Address = models.CharField(max_length=50)
    Lan0_iface_direction = models.CharField(max_length=50)
    Lan0_gateway_address = models.CharField(max_length=50)
    Lan0_gateway_name = models.CharField(max_length=50)
    container_Memory = models.CharField(max_length=500)
    CPU_Cores = models.CharField(max_length=500)


class Router(models.Model):
    id = models.AutoField(primary_key=True)
    Router_name = models.CharField(max_length=100)
    Domain_name = models.CharField(max_length=256)
    Mgt0_IP_Address = models.CharField(max_length=50)
    Mgt0_iface_direction = models.CharField(max_length=50)
    Lan0_IP_Address = models.CharField(max_length=50)
    Lan0_iface_direction = models.CharField(max_length=50)
    Lan0_gateway_address = models.CharField(max_length=50)
    Lan0_gateway_name = models.CharField(max_length=50)
    container_Memory = models.CharField(max_length=500)
    CPU_Cores = models.CharField(max_length=500)


class Public(models.Model):
    id = models.AutoField(primary_key=True)
    Host_name = models.CharField(max_length=100)
    Domain_name = models.CharField(max_length=256)
    Mgt0_IP_Address = models.CharField(max_length=50)
    Mgt0_iface_direction = models.CharField(max_length=50)
    Lan0_IP_Address = models.CharField(max_length=50)
    Lan0_iface_direction = models.CharField(max_length=50)
    Lan0_gateway_address = models.CharField(max_length=50)
    Lan0_gateway_name = models.CharField(max_length=50)
    container_Memory = models.CharField(max_length=500)
    CPU_Cores = models.CharField(max_length=500)


