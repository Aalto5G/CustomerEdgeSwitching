from django.contrib.auth.forms import UserCreationForm
from django.urls import reverse_lazy
from django.views import generic
from django.shortcuts import render
from django.http import HttpResponse
from .forms import GatewayForm, HostForm, RouterForm, ProxyForm, PublicForm
from django.views.generic import TemplateView
from django.views.generic.edit import FormView
import json
import requests

BASE_URL = "http://127.0.0.1:8080/"
CREATE_PRIVATE_HOST_URL_TEMPLATE    = BASE_URL + "create_container/private_host/{}"
CREATE_GATEWAY_URL_TEMPLATE         = BASE_URL + "create_container/gateway/{}"
GET_CONTAINER_LIST_URL              = BASE_URL + "get_container_list"
GET_CONTAINER_STATUS_URL            = BASE_URL + "get_container_status"
START_CONTAINER_URL                 = BASE_URL + "start_container/{}"
STOP_CONTAINER_URL                  = BASE_URL + "stop_container/{}"
GET_CONTAINER_INFO_URL_TEMPLATE     = BASE_URL + "get_container_info/{}"

class SignUpView(generic.CreateView):
    form_class = UserCreationForm
    success_url = reverse_lazy('login')
    template_name = 'registration/signup.html'


def Dashboard_view(request):
    context = {}
    resp = requests.get(GET_CONTAINER_STATUS_URL)         # Excludes base container from the list
    print("resp.status_code: ", resp.status_code)
    if resp.status_code == 200:
        ct_dict = resp.json()
        context['container_count'] = len(ct_dict)
        context['ct_dict'] = ct_dict                      # One can pre-process content, instead of implementing container (type & status) as tuple members in HTML template.

    return render(request, "dashboard.html", context)


def Get_Container_Info(request, ct_name):
    """ Get container detail from backend and """
    context = {}
    get_container_info_url = GET_CONTAINER_INFO_URL_TEMPLATE.format(ct_name)
    resp = requests.get(get_container_info_url)
    if resp.status_code != 200:
        return render(request, "containerInfo.html", context)

    ct_info = resp.json()
    #context['ct_info'] = ct_info
    context["name"] = ct_info["name"]
    context["type"] = ct_info["type"]
    context["bridges_list"] = []
    context["interface_list"] = []
    context["interfaces"] = {}
    context["interfaces_bridges"] = {}
    context["interfaces_ipaddr"] = {}

    for iface, br in ct_info["iface_br_info"].items():
        context["interface_list"].append(iface)
        context["bridges_list"].append(br)
        context["interfaces_bridges"][iface] = br
        ip_addrs = ct_info["iface_ip_info"][iface]
        context["interfaces_ipaddr"][iface] = ip_addrs

    #print("context: ", context)
    return render(request, "containerInfo.html", context)


def Example_Network_view(request):
    context = {}
    return render(request, "networkSetupExample.html", context)


def getContainerList():
    """ Get container list from LXC orchestration backend """
    ct_list = []
    try:
        resp = requests.get(GET_CONTAINER_LIST_URL)
        if resp.status_code == 200:
            ct_list = resp.json()
    except Exception as ex:
        print("Failure to get container list from backend")
    finally:
        return ct_list

def createGatewayContainerRequest(formContent):
    """
    curl -X POST -H "Content-Type: application/json" -d
    '{"interfaces": {"mgt0":{"ip_addr":["172.31.255.11"], "iface_direction":"mgmt"},
                    "lan0":{"ip_addr":["192.168.0.1"], "iface_direction":"private"},
                    "wan0":{"ip_addr":["100.64.1.130", "100.64.1.131", "100.64.1.132"], "iface_direction":"public", "gateway":"100.64.1.1"} }}'
                http://127.0.0.1:8080/create_container/gateway/gwa
    """

    gwRequest = {"interfaces":None}

    if "Mgt0_IP_Address" in formContent:
        mgmtIfaceName = "mgt0"
        gwRequest["interfaces"] = { mgmtIfaceName: None }                                   # first sub-level must be initiated this way.
        gwRequest["interfaces"][mgmtIfaceName] = {"iface_direction": "mgmt"}
        gwRequest["interfaces"][mgmtIfaceName]["ip_addr"] = []
        gwRequest["interfaces"][mgmtIfaceName]["ip_addr"].append( formContent["Mgt0_IP_Address"] )

    if "Public_interface_name" in formContent:
        publicIfaceName = formContent["Public_interface_name"]
        gwRequest["interfaces"][publicIfaceName] = {"iface_direction": "public"}
        gwRequest["interfaces"][publicIfaceName]["gateway"] = formContent["Public_default_gateway_address"]
        gwRequest["interfaces"][publicIfaceName]["ip_addr"] = []
        gwRequest["interfaces"][publicIfaceName]["ip_addr"].append( formContent["Public_iface_IP_Address"] )

    if "Private_interface_name" in formContent:
        privateIfaceName = formContent["Private_interface_name"]
        gwRequest["interfaces"][privateIfaceName] = {"iface_direction": "private"}
        gwRequest["interfaces"][privateIfaceName]["ip_addr"] = []
        gwRequest["interfaces"][privateIfaceName]["ip_addr"].append( formContent["Private_IP_Address"] )

    #print("formContent:", formContent)
    #print("gwRequest:", gwRequest)
    return gwRequest


def createHostContainerRequest(hostData):
    """
    curl -X POST -H "Content-Type: application/json" -d '{"interfaces": {"mgt0":{"ip_addr":["172.31.255.31"], "iface_direction":"mgmt"}, "lan0":{"ip_addr":["192.168.0.101"], "gateway":"192.168.0.1", "gateway_name":"gwa", "iface_direction":"public"}} }' http://127.0.0.1:8080/create_container/private_host/hosta1
    '{"interfaces": {"mgt0":{"ip_addr":["172.31.255.31"], "iface_direction":"mgmt"}, "lan0":{"ip_addr":["192.168.0.101"], "gateway":"192.168.0.1", "gateway_name":"gwa", "iface_direction":"public"}} }'
    http://127.0.0.1:8080/create_container/private_host/hosta1
    """
    print(hostData)
    print("hostData['Host_name']")
    print(hostData["Host_name"])
    #return hostData
    hostRequest = {}
    hostRequest["interfaces"] = {}
    hostRequest["interfaces"]["mgt0"] = {}
    hostRequest["interfaces"]["lan0"] = {}

    hostRequest["interfaces"]["mgt0"]["ip_addr"] = []
    hostRequest["interfaces"]["mgt0"]["ip_addr"].append(hostData["Mgt0_IP_Address"])
    hostRequest["interfaces"]["mgt0"]["iface_direction"] = "mgmt"

    hostRequest["interfaces"]["lan0"]["ip_addr"] = [hostData["Lan0_IP_Address"]]
    hostRequest["interfaces"]["lan0"]["gateway"] = hostData["Lan0_gateway_address"]
    hostRequest["interfaces"]["lan0"]["gateway_name"] = hostData["Lan0_gateway_name"]
    hostRequest["interfaces"]["lan0"]["iface_direction"] = hostData["Lan0_iface_direction"]
    print("hostRequest:", hostRequest)
    return hostRequest

def Gateway_create_view(request):
    """ Create gateway container based from UI """
    if request.method == 'POST':
        form = GatewayForm(request.POST)
        if form.is_valid():
            cleanedData = form.cleaned_data
            gw_name = cleanedData["Gateway_name"]
            gateway_data = createGatewayContainerRequest(cleanedData)
            gateway_url = CREATE_GATEWAY_URL_TEMPLATE.format(gw_name)
            resp = requests.post(gateway_url, data=json.dumps(gateway_data))
            #form.save()

            if resp.status_code == 200:
                return HttpResponse("Request to create '{}' container is successful".format(gw_name))
            else:
                return HttpResponse("Didn't get a valid response for Request to create '{}'".format(gw_name))
        else:
            print("Errors:", form.errors)
            return HttpResponse("Form failed the verification")

    else:
        form = GatewayForm()
        context = {'form': form}
        return render(request, 'gateway.html', context)


def Host_create_view(request):
    """ Create host container based from UI """
    if request.method == 'POST':
        form = HostForm(request.POST)
        if form.is_valid():
            cleanedData = form.cleaned_data
            host_name = cleanedData["Host_name"]
            hostData = createHostContainerRequest(cleanedData)
            host_url = CREATE_PRIVATE_HOST_URL_TEMPLATE.format(host_name)
            #data = requests.post(host_url, data=json.dumps(hostData))
            #data = requests.post("http://127.0.0.1:8080/test_post", data=json.dumps(hostData))
            data = requests.post(host_url, data=json.dumps(hostData))
            if data.status_code == 200:
                #form.save()
                return HttpResponse("Request to create '{}' container is successful".format(host_name))
        else:
            return HttpResponse('Form content is invalid')
    else:
        form = HostForm()
        context = {'form': form}
        return render(request, 'host.html', context)


def Proxy_create_view(request):
    """ Create host container based from UI """
    if request.method == 'POST':
        form = ProxyForm(request.POST)
        if form.is_valid():
            cleanedData = form.cleaned_data
            host_name = cleanedData["Host_name"]
            host_url = "http://127.0.0.1:8080/create_container/private_host/{}".format(host_name)
            #data = requests.post(host_url, data=json.dumps(hostData))

            hostData = createHostContainerRequest(cleanedData)
            #data = requests.post("http://127.0.0.1:8080/test_post", data=json.dumps(hostData))
            data = requests.post(host_url, data=json.dumps(hostData))
            if data.status_code == 200:
                form.save()
                return HttpResponse("Request to create '{}' container is successful".format(host_name))
        else:
            return HttpResponse('Form content is invalid')
    else:
        form = ProxyForm()
        context = {'form': form}
        return render(request, 'proxy.html', context)


def Router_create_view(request):
    if request.method == 'POST':
        form = RouterForm(request.POST)
        if form.is_valid():
            cleanedData = form.cleaned_data
            host_name = cleanedData["Host_name"]
            host_url = "http://127.0.0.1:8080/create_container/private_host/{}".format(host_name)
            #data = requests.post(host_url, data=json.dumps(hostData))

            hostData = createHostContainerRequest(cleanedData)
            data = requests.post("http://127.0.0.1:8080/test_post", data=json.dumps(hostData))
            if data.status_code == 200:
                return HttpResponse('Test message has been successfully posted')

            form.save()
        return HttpResponse('Your review has been taken')

    else:
        form = RouterForm()
        context = { 'form': form}
        return render(request, 'router.html', context)


def Public_create_view(request):
    if request.method == 'POST':
        form = PublicForm(request.POST)
        if form.is_valid():
            cleanedData = form.cleaned_data
            host_name = cleanedData["Host_name"]
            host_url = "http://127.0.0.1:8080/create_container/private_host/{}".format(host_name)
            #data = requests.post(host_url, data=json.dumps(hostData))

            hostData = createHostContainerRequest(cleanedData)
            data = requests.post("http://127.0.0.1:8080/test_post", data=json.dumps(hostData))
            if data.status_code == 200:
                return HttpResponse('Test message has been successfully posted')

            form.save()
        return HttpResponse('Your review has been taken')

    else:
        form = PublicForm()
        context = { 'form': form}
        return render(request, 'publicHost.html', context)


def Start_container(request, ct_name):
    """ Container control from dashboard, e.g. start/stop container  """
    resp_text = ""

    if request.method == "GET":
        ct_start_url = START_CONTAINER_URL.format(ct_name)
        http_resp = requests.get(ct_start_url)

        if http_resp.status_code == 200:
            resp_text = http_resp.text                  # Returns backend's response for action done on container
        else:
            resp_text = "Failed to process request"     # Message notifying failure of request handling in backend

        context = { 'resp': resp_text}
        return render(request, 'containerStatusReport.html', context)


def Stop_container(request, ct_name):
    """ Container control from dashboard, e.g. start/stop container  """
    resp_text = ""
    if request.method == "GET":
        ct_start_url = STOP_CONTAINER_URL.format(ct_name)
        http_resp = requests.get(ct_start_url)

        if http_resp.status_code == 200:
            resp_text = http_resp.text                  # Returns backend's response for action done on container
        else:
            resp_text = "Failed to process request"     # Message notifying failure of request handling in backend

        #print("Response:", resp_text)
        context = { 'resp': resp_text}
        return render(request, 'containerStatusReport.html', context)
