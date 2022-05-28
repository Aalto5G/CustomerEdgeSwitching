from django import forms
from .models import Gateway, Host, Router, Proxy, Public


class GatewayForm(forms.ModelForm):
    extra_field_count = '5'

    class Meta:
        model = Gateway
        fields = '__all__'

    def clean(self):
        cleaned_data = super(GatewayForm, self).clean()
        # additional cleaning here
        return cleaned_data


class HostForm(forms.ModelForm):
    class Meta:
        model = Host
        fields = '__all__'

    def clean(self):
        cleaned_data = super(HostForm, self).clean()
        # additional cleaning here
        return cleaned_data


class ProxyForm(forms.ModelForm):
    class Meta:
        model = Proxy
        fields = '__all__'

    def clean(self):
        cleaned_data = super(ProxyForm, self).clean()
        # additional cleaning here
        return cleaned_data


class RouterForm(forms.ModelForm):
    class Meta:
        model = Router
        fields = ['Router_name','container_Memory','CPU_Cores']

    def clean(self):
        cleaned_data = super(RouterForm, self).clean()
        # additional cleaning here
        return cleaned_data


class PublicForm(forms.ModelForm):
    class Meta:
        model = Public
        fields = '__all__'

    def clean(self):
        cleaned_data = super(PublicForm, self).clean()
        # additional cleaning here
        return cleaned_data

